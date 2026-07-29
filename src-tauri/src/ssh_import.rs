//! Trusted SSH onboarding helpers.
//!
//! Resolution happens outside the webview and never invokes a shell. Import
//! previews are cached behind one-time opaque ids so a later save can only
//! read identity files that this resolver actually discovered.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Stdio;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serde::Serialize;
use ssh_key::known_hosts::{KnownHosts, Marker};
use ssh_key::HashAlg;
use uuid::Uuid;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_CONFIG_FILES: usize = 64;
const MAX_SSH_G_OUTPUT: usize = 1024 * 1024;
const MAX_IDENTITY_BYTES: u64 = 1024 * 1024;
const IMPORT_TTL: Duration = Duration::from_secs(10 * 60);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct ResolvedSshImport {
    pub destination: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
    pub proxy_jump: Option<String>,
    pub host_key_alias: Option<String>,
    pub known_hosts_files: Vec<PathBuf>,
    pub host_key_candidates: Vec<HostKeyCandidate>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyCandidate {
    pub fingerprint: String,
    pub algorithm: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshImportPreview {
    pub import_id: String,
    pub destination: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<String>,
    pub proxy_jump: Option<String>,
    pub host_key_candidates: Vec<HostKeyCandidate>,
    pub warnings: Vec<String>,
}

#[derive(Default)]
pub struct ImportCache {
    entries: HashMap<String, CachedImport>,
}

struct CachedImport {
    created_at: Instant,
    resolved: ResolvedSshImport,
}

impl ImportCache {
    pub fn insert(&mut self, resolved: ResolvedSshImport) -> SshImportPreview {
        self.entries
            .retain(|_, entry| entry.created_at.elapsed() < IMPORT_TTL);
        let import_id = Uuid::new_v4().to_string();
        let preview = SshImportPreview {
            import_id: import_id.clone(),
            destination: resolved.destination.clone(),
            host: resolved.host.clone(),
            port: resolved.port,
            user: resolved.user.clone(),
            identity_files: resolved
                .identity_files
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            proxy_jump: resolved.proxy_jump.clone(),
            host_key_candidates: resolved.host_key_candidates.clone(),
            warnings: resolved.warnings.clone(),
        };
        self.entries.insert(
            import_id,
            CachedImport {
                created_at: Instant::now(),
                resolved,
            },
        );
        preview
    }

    pub fn get(&mut self, import_id: &str) -> Result<ResolvedSshImport, String> {
        self.entries
            .retain(|_, entry| entry.created_at.elapsed() < IMPORT_TTL);
        let entry = self
            .entries
            .get(import_id)
            .ok_or_else(|| "SSH import preview expired; resolve it again".to_string())?;
        Ok(entry.resolved.clone())
    }

    pub fn remove(&mut self, import_id: &str) {
        self.entries.remove(import_id);
    }
}

pub fn load_identity(
    resolved: &ResolvedSshImport,
    selected_path: &str,
    passphrase: Option<&str>,
) -> Result<zeroize::Zeroizing<String>, aka_core::capability::ssh::KeyImportError> {
    use aka_core::capability::ssh::KeyImportError::Unusable;
    let selected = Path::new(selected_path)
        .canonicalize()
        .map_err(|error| Unusable(format!("could not open selected identity file: {error}")))?;
    if !resolved.identity_files.iter().any(|path| path == &selected) {
        return Err(Unusable(
            "selected identity file was not part of this SSH import preview".into(),
        ));
    }
    let metadata = fs::metadata(&selected)
        .map_err(|error| Unusable(format!("could not inspect selected identity file: {error}")))?;
    if !metadata.is_file() || metadata.len() > MAX_IDENTITY_BYTES {
        return Err(Unusable(
            "selected identity must be a regular file smaller than 1 MiB".into(),
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Unusable(
            "selected identity file must not be accessible by group or other users".into(),
        ));
    }
    let value =
        zeroize::Zeroizing::new(fs::read_to_string(&selected).map_err(|error| {
            Unusable(format!("could not read selected identity file: {error}"))
        })?);
    // A passphrase-protected `~/.ssh/id_*` is the ordinary case, not an error:
    // decrypt it here, in the trusted onboarding surface, and hand the vault the
    // cleartext OpenSSH form it seals.
    aka_core::capability::ssh::private_key_for_vault(value.as_bytes(), passphrase)
}

pub fn resolve(source: &str) -> Result<ResolvedSshImport, String> {
    let parsed = parse_command(source)?;
    scan_configs_for_exec(&parsed.config_file)?;

    let mut command = Command::new("/usr/bin/ssh");
    command
        .arg("-G")
        .args(&parsed.arguments)
        .arg(&parsed.destination)
        .env("LC_ALL", "C");
    let output = bounded_output(&mut command, "OpenSSH configuration resolution")?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            "OpenSSH could not resolve that destination".into()
        } else {
            format!("OpenSSH could not resolve that destination: {detail}")
        });
    }
    if output.stdout.len() > MAX_SSH_G_OUTPUT {
        return Err("OpenSSH produced an unexpectedly large configuration".into());
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "OpenSSH returned non-UTF-8 configuration".to_string())?;
    let mut resolved = resolved_from_output(parsed.destination, &stdout)?;
    resolve_known_hosts(&mut resolved)?;
    Ok(resolved)
}

struct ParsedCommand {
    destination: String,
    arguments: Vec<OsString>,
    config_file: ConfigSelection,
}

enum ConfigSelection {
    Default,
    None,
    File(PathBuf),
}

fn parse_command(source: &str) -> Result<ParsedCommand, String> {
    let mut words = shell_words::split(source.trim())
        .map_err(|error| format!("could not parse SSH command: {error}"))?;
    if words.first().is_some_and(|word| word == "ssh") {
        words.remove(0);
    }
    if words.is_empty() {
        return Err("SSH command is missing a destination".into());
    }

    let mut arguments = Vec::new();
    let mut destination = None;
    let mut config_file = ConfigSelection::Default;
    let mut index = 0;
    while index < words.len() {
        let word = &words[index];
        if !word.starts_with('-') || word == "-" {
            if destination.is_some() {
                return Err("SSH import accepts a destination but not a remote command".into());
            }
            validate_destination(word)?;
            destination = Some(word.clone());
            index += 1;
            continue;
        }
        if destination.is_some() {
            return Err("SSH options must appear before the destination".into());
        }

        let (flag, attached) = split_short_option(word)?;
        match flag {
            'p' | 'l' | 'i' | 'J' => {
                let value = option_value(&words, &mut index, attached, flag)?;
                arguments.push(format!("-{flag}").into());
                arguments.push(value.into());
            }
            'F' => {
                let value = option_value(&words, &mut index, attached, flag)?;
                config_file = if value == "none" {
                    ConfigSelection::None
                } else {
                    ConfigSelection::File(expand_home(&value)?)
                };
                arguments.push("-F".into());
                arguments.push(value.into());
            }
            'o' => {
                let value = option_value(&words, &mut index, attached, flag)?;
                validate_o_option(&value)?;
                arguments.push("-o".into());
                arguments.push(value.into());
            }
            _ => return Err(format!("SSH option -{flag} is not supported by import")),
        }
        index += 1;
    }

    Ok(ParsedCommand {
        destination: destination
            .ok_or_else(|| "SSH command is missing a destination".to_string())?,
        arguments,
        config_file,
    })
}

fn split_short_option(word: &str) -> Result<(char, Option<&str>), String> {
    let mut chars = word.chars();
    if chars.next() != Some('-') {
        return Err("invalid SSH option".into());
    }
    let flag = chars
        .next()
        .ok_or_else(|| "invalid SSH option".to_string())?;
    let consumed = 1 + flag.len_utf8();
    let attached = (word.len() > consumed).then_some(&word[consumed..]);
    Ok((flag, attached))
}

fn option_value(
    words: &[String],
    index: &mut usize,
    attached: Option<&str>,
    flag: char,
) -> Result<String, String> {
    if let Some(value) = attached {
        if !value.is_empty() {
            return Ok(value.to_string());
        }
    }
    *index += 1;
    words
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("SSH -{flag} requires a value"))
}

fn validate_destination(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('-')
        || value.contains('/')
        || value.chars().any(char::is_whitespace)
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "._-+%@".contains(ch))
    {
        return Err("SSH destination must be a hostname, alias, or user@hostname".into());
    }
    Ok(())
}

fn validate_o_option(value: &str) -> Result<(), String> {
    let key = value
        .split_once('=')
        .map(|(key, _)| key)
        .or_else(|| value.split_whitespace().next())
        .unwrap_or("")
        .to_ascii_lowercase();
    const ALLOWED: &[&str] = &[
        "hostname",
        "port",
        "user",
        "identityfile",
        "proxyjump",
        "hostkeyalias",
        "userknownhostsfile",
        "globalknownhostsfile",
    ];
    if !ALLOWED.contains(&key.as_str()) {
        return Err(format!("SSH -o {key} is not supported by import"));
    }
    Ok(())
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is unavailable; cannot resolve SSH configuration".to_string())
}

fn expand_home(value: &str) -> Result<PathBuf, String> {
    if value == "~" {
        return home_dir();
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return Ok(home_dir()?.join(rest));
    }
    Ok(PathBuf::from(value))
}

fn scan_configs_for_exec(selection: &ConfigSelection) -> Result<(), String> {
    let mut roots = Vec::new();
    match selection {
        ConfigSelection::Default => {
            roots.push(home_dir()?.join(".ssh/config"));
            roots.push(PathBuf::from("/etc/ssh/ssh_config"));
        }
        ConfigSelection::None => return Ok(()),
        ConfigSelection::File(path) => roots.push(path.clone()),
    }
    let mut seen = HashSet::new();
    for root in roots {
        scan_config(&root, &mut seen)?;
    }
    Ok(())
}

fn scan_config(path: &Path, seen: &mut HashSet<PathBuf>) -> Result<(), String> {
    if seen.len() >= MAX_CONFIG_FILES {
        return Err("SSH configuration includes too many files".into());
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("could not inspect {}: {error}", path.display())),
    };
    if !seen.insert(canonical.clone()) {
        return Ok(());
    }
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("could not inspect {}: {error}", canonical.display()))?;
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "SSH config {} is unexpectedly large",
            canonical.display()
        ));
    }
    let text = fs::read_to_string(&canonical)
        .map_err(|error| format!("could not inspect {}: {error}", canonical.display()))?;
    let base = canonical.parent().unwrap_or(Path::new("/"));
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let words = shell_words::split(line)
            .map_err(|error| format!("could not parse {}: {error}", canonical.display()))?;
        let Some(keyword) = words.first().map(|word| word.to_ascii_lowercase()) else {
            continue;
        };
        if keyword == "match"
            && words.iter().skip(1).any(|word| {
                let criterion = word.trim_start_matches('!').to_ascii_lowercase();
                criterion == "exec" || criterion.starts_with("exec=")
            })
        {
            return Err(format!(
                "automatic import is disabled because {} contains Match exec",
                canonical.display()
            ));
        }
        if keyword == "include" {
            for pattern in words.iter().skip(1) {
                let expanded = expand_include(pattern, base)?;
                let pattern = expanded.to_string_lossy();
                let matches = glob::glob(&pattern)
                    .map_err(|error| format!("invalid Include pattern {pattern:?}: {error}"))?;
                for included in matches.flatten() {
                    scan_config(&included, seen)?;
                }
            }
        }
    }
    Ok(())
}

fn expand_include(value: &str, base: &Path) -> Result<PathBuf, String> {
    if value.contains('%')
        || value.contains("${")
        || (value.starts_with('~') && value != "~" && !value.starts_with("~/"))
    {
        return Err(format!(
            "automatic import cannot safely inspect Include path {value:?}"
        ));
    }
    let path = expand_home(value)?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(base.join(path))
    }
}

fn bounded_output(command: &mut Command, operation: &str) -> Result<Output, String> {
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start {operation}: {error}"))?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|error| format!("could not finish {operation}: {error}"));
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{operation} timed out"));
            }
            Err(error) => return Err(format!("could not monitor {operation}: {error}")),
        }
    }
}

fn resolved_from_output(destination: String, output: &str) -> Result<ResolvedSshImport, String> {
    let mut values: HashMap<&str, Vec<&str>> = HashMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once(char::is_whitespace) {
            values.entry(key).or_default().push(value.trim());
        }
    }
    let one = |key: &str| {
        values
            .get(key)
            .and_then(|values| values.first())
            .copied()
            .filter(|value| !value.is_empty())
    };
    let host = one("hostname")
        .ok_or_else(|| "OpenSSH did not resolve a hostname".to_string())?
        .to_string();
    let port = one("port")
        .ok_or_else(|| "OpenSSH did not resolve a port".to_string())?
        .parse::<u16>()
        .map_err(|_| "OpenSSH resolved an invalid port".to_string())?;
    let user = one("user")
        .ok_or_else(|| "OpenSSH did not resolve a user".to_string())?
        .to_string();
    let identity_files = expanded_existing_paths(values.get("identityfile"));
    let mut known_hosts_files = expanded_existing_paths(values.get("userknownhostsfile"));
    known_hosts_files.extend(expanded_existing_paths(values.get("globalknownhostsfile")));
    dedupe_paths(&mut known_hosts_files);
    let proxy_jump = one("proxyjump")
        .filter(|value| *value != "none")
        .map(str::to_string);
    let host_key_alias = one("hostkeyalias")
        .filter(|value| *value != "none")
        .map(str::to_string);
    let mut warnings = Vec::new();
    match identity_files.len() {
        0 => warnings.push("OpenSSH did not resolve an existing identity file.".into()),
        1 => {}
        _ => warnings
            .push("OpenSSH resolved multiple identity files; choose the one to import.".into()),
    }
    if let Some(jump) = &proxy_jump {
        warnings.push(format!(
            "This destination connects through ProxyJump {jump}."
        ));
    }
    Ok(ResolvedSshImport {
        destination,
        host,
        port,
        user,
        identity_files,
        proxy_jump,
        host_key_alias,
        known_hosts_files,
        host_key_candidates: vec![],
        warnings,
    })
}

struct KnownHostsScan {
    candidates: Vec<HostKeyCandidate>,
    saw_revoked: bool,
    saw_authority: bool,
}

/// Search the given known_hosts files for `host` (`[host]:port` when
/// non-default) with `ssh-keygen -F`, which also resolves hashed entries.
fn scan_known_hosts(host: &str, port: u16, files: &[PathBuf]) -> Result<KnownHostsScan, String> {
    let lookup = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    let mut candidates = Vec::new();
    let mut saw_revoked = false;
    let mut saw_authority = false;
    for path in files {
        let mut command = Command::new("/usr/bin/ssh-keygen");
        command
            .arg("-F")
            .arg(&lookup)
            .arg("-f")
            .arg(path)
            .env("LC_ALL", "C");
        let output = bounded_output(&mut command, "known_hosts lookup")?;
        if output.stdout.len() > MAX_SSH_G_OUTPUT {
            return Err("known_hosts lookup produced unexpectedly large output".into());
        }
        if !output.status.success() && output.status.code() != Some(1) {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(format!(
                "could not search {}{}",
                path.display(),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        for entry in KnownHosts::new(&text).flatten() {
            match entry.marker() {
                Some(Marker::Revoked) => {
                    saw_revoked = true;
                    continue;
                }
                Some(Marker::CertAuthority) => {
                    saw_authority = true;
                    continue;
                }
                None => {}
            }
            let public = entry.public_key();
            candidates.push(HostKeyCandidate {
                fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
                algorithm: public.algorithm().as_str().to_string(),
                source: path.to_string_lossy().into_owned(),
            });
        }
    }
    let mut seen = HashSet::new();
    candidates.retain(|candidate| seen.insert(candidate.fingerprint.clone()));
    Ok(KnownHostsScan {
        candidates,
        saw_revoked,
        saw_authority,
    })
}

/// known_hosts candidates for a saved connection's `host:port`, from the
/// OpenSSH default files. Used at approval time so the first-connection
/// trust prompt can say whether the observed key matches, conflicts with,
/// or is absent from the user's known_hosts.
pub fn known_hosts_candidates(host: &str, port: u16) -> Result<Vec<HostKeyCandidate>, String> {
    let home = home_dir()?;
    let files: Vec<PathBuf> = [
        home.join(".ssh/known_hosts"),
        home.join(".ssh/known_hosts2"),
        PathBuf::from("/etc/ssh/ssh_known_hosts"),
        PathBuf::from("/etc/ssh/ssh_known_hosts2"),
    ]
    .into_iter()
    .filter(|path| path.is_file())
    .collect();
    Ok(scan_known_hosts(host, port, &files)?.candidates)
}

fn resolve_known_hosts(resolved: &mut ResolvedSshImport) -> Result<(), String> {
    let lookup_host = resolved.host_key_alias.as_deref().unwrap_or(&resolved.host);
    let scan = scan_known_hosts(lookup_host, resolved.port, &resolved.known_hosts_files)?;
    if scan.saw_revoked {
        resolved
            .warnings
            .push("known_hosts contains a revoked key for this destination.".into());
    }
    if scan.saw_authority {
        resolved.warnings.push(
            "known_hosts trusts this destination through a certificate authority; the concrete host key is confirmed at the first connection."
                .into(),
        );
    }
    resolved.host_key_candidates = scan.candidates;
    Ok(())
}

fn expanded_existing_paths(values: Option<&Vec<&str>>) -> Vec<PathBuf> {
    let mut paths = values
        .into_iter()
        .flatten()
        .flat_map(|value| value.split_whitespace())
        .filter(|value| *value != "none")
        .filter_map(|value| expand_home(value).ok())
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    dedupe_paths(&mut paths);
    paths
}

fn dedupe_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use ssh_key::{Algorithm, LineEnding, PrivateKey};

    #[test]
    fn parses_supported_command_options_without_a_shell() {
        let parsed =
            parse_command("ssh -p 2222 -i '~/.ssh/deploy key' -J jump deploy@prod").unwrap();
        assert_eq!(parsed.destination, "deploy@prod");
        assert_eq!(
            parsed.arguments,
            ["-p", "2222", "-i", "~/.ssh/deploy key", "-J", "jump"].map(OsString::from)
        );
    }

    #[test]
    fn rejects_remote_commands_and_executable_options() {
        assert!(parse_command("ssh prod uptime").is_err());
        assert!(parse_command("ssh -o ProxyCommand=evil prod").is_err());
        assert!(parse_command("ssh prod; touch /tmp/nope").is_err());
    }

    #[test]
    fn parses_effective_configuration() {
        let output = "host prod\nuser deploy\nhostname prod.example.com\nport 2222\nidentityfile ~/.ssh/missing\nproxyjump jump\nhostkeyalias prod-key\nuserknownhostsfile ~/.ssh/known_hosts\n";
        let resolved = resolved_from_output("prod".into(), output).unwrap();
        assert_eq!(resolved.destination, "prod");
        assert_eq!(resolved.host, "prod.example.com");
        assert_eq!(resolved.port, 2222);
        assert_eq!(resolved.user, "deploy");
        assert_eq!(resolved.proxy_jump.as_deref(), Some("jump"));
        assert_eq!(resolved.host_key_alias.as_deref(), Some("prod-key"));
    }

    #[test]
    fn detects_match_exec_before_running_openssh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        fs::write(
            &path,
            "Host prod\n  HostName prod.example.com\nMatch exec \\\"touch /tmp/nope\\\"\n",
        )
        .unwrap();
        let error = scan_configs_for_exec(&ConfigSelection::File(path)).unwrap_err();
        assert!(error.contains("Match exec"));
    }

    #[test]
    fn rejects_include_tokens_the_preflight_cannot_expand() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        fs::write(&path, "Include %h/config\n").unwrap();
        let error = scan_configs_for_exec(&ConfigSelection::File(path)).unwrap_err();
        assert!(error.contains("cannot safely inspect Include path"));
    }

    #[cfg(unix)]
    #[test]
    fn loads_only_a_previewed_private_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deploy");
        let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        fs::write(&path, key.to_openssh(LineEnding::LF).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let canonical = path.canonicalize().unwrap();
        let resolved = ResolvedSshImport {
            destination: "prod".into(),
            host: "prod.example.com".into(),
            port: 22,
            user: "deploy".into(),
            identity_files: vec![canonical.clone()],
            proxy_jump: None,
            host_key_alias: None,
            known_hosts_files: vec![],
            host_key_candidates: vec![],
            warnings: vec![],
        };
        assert!(load_identity(&resolved, canonical.to_str().unwrap(), None).is_ok());
        assert!(load_identity(&resolved, "/etc/hosts", None)
            .unwrap_err()
            .message()
            .contains("not part of this SSH import preview"));
    }

    /// SSH-23. A passphrase-protected `~/.ssh/id_*` is the ordinary case. It was
    /// refused with advice to strip the passphrase first — leaving the stripped
    /// key on disk unprotected — so it is decrypted here instead, and the vault
    /// (Keychain / XChaCha20) is the protection boundary for what is stored.
    #[cfg(unix)]
    #[test]
    fn loads_a_passphrase_protected_identity_and_stores_it_decrypted() {
        use aka_core::capability::ssh::KeyImportError;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deploy");
        let mut rng = ssh_key::rand_core::OsRng;
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let expected = key.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        fs::write(
            &path,
            key.encrypt(&mut rng, b"correct horse")
                .unwrap()
                .to_openssh(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let canonical = path.canonicalize().unwrap();
        let resolved = ResolvedSshImport {
            destination: "prod".into(),
            host: "prod.example.com".into(),
            port: 22,
            user: "deploy".into(),
            identity_files: vec![canonical.clone()],
            proxy_jump: None,
            host_key_alias: None,
            known_hosts_files: vec![],
            host_key_candidates: vec![],
            warnings: vec![],
        };
        let selected = canonical.to_str().unwrap();
        assert_eq!(
            load_identity(&resolved, selected, None).unwrap_err(),
            KeyImportError::NeedsPassphrase
        );
        assert_eq!(
            load_identity(&resolved, selected, Some("battery")).unwrap_err(),
            KeyImportError::WrongPassphrase
        );
        let stored = load_identity(&resolved, selected, Some("correct horse")).unwrap();
        let reloaded = PrivateKey::from_openssh(stored.as_bytes()).unwrap();
        assert!(
            !reloaded.is_encrypted(),
            "the vault stores cleartext OpenSSH"
        );
        assert_eq!(
            reloaded.public_key().fingerprint(ssh_key::HashAlg::Sha256),
            expected
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolves_hashed_known_hosts_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        fs::write(
            &path,
            format!(
                "prod.example.com {}\n",
                key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let status = Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-H", "-f"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let mut resolved = ResolvedSshImport {
            destination: "prod".into(),
            host: "prod.example.com".into(),
            port: 22,
            user: "deploy".into(),
            identity_files: vec![],
            proxy_jump: None,
            host_key_alias: None,
            known_hosts_files: vec![path],
            host_key_candidates: vec![],
            warnings: vec![],
        };
        resolve_known_hosts(&mut resolved).unwrap();
        assert_eq!(resolved.host_key_candidates.len(), 1);
        assert_eq!(
            resolved.host_key_candidates[0].fingerprint,
            key.public_key().fingerprint(HashAlg::Sha256).to_string()
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolves_alias_include_identity_jump_and_known_host_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let includes = dir.path().join("conf.d");
        fs::create_dir(&includes).unwrap();
        let identity_path = dir.path().join("deploy");
        let identity =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        fs::write(&identity_path, identity.to_openssh(LineEnding::LF).unwrap()).unwrap();
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600)).unwrap();
        let host_key =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        let known_hosts = dir.path().join("known_hosts");
        fs::write(
            &known_hosts,
            format!(
                "[prod.example.com]:2222 {}\n",
                host_key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        fs::write(
            includes.join("prod.conf"),
            format!(
                "Host prod\n  HostName prod.example.com\n  Port 2222\n  User deploy\n  IdentityFile {}\n  UserKnownHostsFile {}\n  ProxyJump bastion\n",
                identity_path.display(),
                known_hosts.display()
            ),
        )
        .unwrap();
        let config = dir.path().join("config");
        fs::write(&config, format!("Include {}/*\n", includes.display())).unwrap();

        let resolved = resolve(&format!("ssh -F {} prod", config.display())).unwrap();
        assert_eq!(resolved.destination, "prod");
        assert_eq!(resolved.host, "prod.example.com");
        assert_eq!(resolved.port, 2222);
        assert_eq!(resolved.user, "deploy");
        assert_eq!(resolved.proxy_jump.as_deref(), Some("bastion"));
        assert_eq!(resolved.identity_files.len(), 1);
        assert_eq!(resolved.host_key_candidates.len(), 1);
        assert_eq!(
            resolved.host_key_candidates[0].fingerprint,
            host_key
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string()
        );
    }
}
