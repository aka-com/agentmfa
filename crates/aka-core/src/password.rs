//! Password-credential helpers: site canonicalization and derived names.

use crate::error::CoreError;
use crate::template::is_valid_secret_name;
use crate::Result;

/// Canonicalize the site a password signs in to. The stored form is the
/// future match key for origin-scoped dispensing, so it is normalized once
/// on write and compared exactly afterwards: lowercase host (plus `:port`
/// when one was given), no scheme, no path, no credentials. The result is a
/// fixpoint: normalizing a stored site returns it unchanged.
pub fn normalize_site(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidSite("enter the website".into()));
    }
    // Accept what people paste: a bare domain, an origin, or a full URL.
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = url::Url::parse(&with_scheme)
        .map_err(|_| CoreError::InvalidSite(format!("{trimmed:?} is not a website address")))?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(CoreError::InvalidSite(format!(
                "{other}:// addresses are not websites"
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CoreError::InvalidSite(
            "leave credentials out of the website address".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| CoreError::InvalidSite(format!("{trimmed:?} has no host")))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(CoreError::InvalidSite(format!("{trimmed:?} has no host")));
    }
    // "www." is presentation, not identity — but only when a dotted domain
    // remains ("www.com" is itself a registrable name, not a prefix).
    let host = match host.strip_prefix("www.") {
        Some(rest) if rest.contains('.') => rest,
        _ => &host,
    };
    Ok(match url.port() {
        // The stored form deliberately drops the scheme. Fold both HTTP
        // defaults regardless of the input scheme so a stored `host:443`
        // cannot reparse as HTTPS and silently become `host` on the next
        // edit. Non-default development ports survive.
        Some(port) if port != 80 && port != 443 => format!("{host}:{port}"),
        _ => host.to_string(),
    })
}

/// Derive the internal name for a password. Connection wiring references
/// credentials by name, so passwords get stable env-style names without
/// asking the user for one: `PASSWORD_<SITE>[_<USER>]`, deduplicated with a
/// numeric suffix against the names already taken.
pub fn derive_password_name(
    site: &str,
    username: Option<&str>,
    taken: impl Fn(&str) -> bool,
) -> String {
    let mut stem = String::from("PASSWORD_");
    stem.push_str(&name_part(site));
    // An email username keeps only its local part: the domain is already in
    // the site, and RAYKYRI reads better than RAYKYRI_GMAIL_COM.
    if let Some(user) = username {
        let user = user.split('@').next().unwrap_or(user);
        let part = name_part(user);
        if !part.is_empty() {
            stem.push('_');
            stem.push_str(&part);
        }
    }
    let stem = trimmed_name(&stem, 64);
    if is_valid_secret_name(&stem) && !taken(&stem) {
        return stem;
    }
    for suffix in 2..10_000u32 {
        let suffix = format!("_{suffix}");
        let candidate = format!("{}{suffix}", trimmed_name(&stem, 64 - suffix.len()));
        if is_valid_secret_name(&candidate) && !taken(&candidate) {
            return candidate;
        }
    }
    // Unreachable in practice; the store's name validation still backstops.
    stem
}

fn name_part(value: &str) -> String {
    let mut out = String::new();
    let mut gap = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            if gap && !out.is_empty() {
                out.push('_');
            }
            out.push(ch.to_ascii_uppercase());
            gap = false;
        } else {
            gap = true;
        }
    }
    out
}

fn trimmed_name(name: &str, max: usize) -> String {
    let cut: String = name.chars().take(max).collect();
    cut.trim_end_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sites_normalize_to_bare_lowercase_hosts() {
        assert_eq!(normalize_site("x.com").unwrap(), "x.com");
        assert_eq!(normalize_site("  X.Com  ").unwrap(), "x.com");
        assert_eq!(
            normalize_site("https://www.google.com/login?x=1").unwrap(),
            "google.com"
        );
        assert_eq!(
            normalize_site("http://localhost:8080/admin").unwrap(),
            "localhost:8080"
        );
        assert_eq!(normalize_site("https://fly.io:443").unwrap(), "fly.io");
        assert_eq!(
            normalize_site("http://example.com:443").unwrap(),
            "example.com"
        );
        assert_eq!(normalize_site("example.com:80").unwrap(), "example.com");
        assert_eq!(normalize_site("example.com.").unwrap(), "example.com");
        assert_eq!(
            normalize_site("app.example.co.uk").unwrap(),
            "app.example.co.uk"
        );
    }

    #[test]
    fn normalized_sites_are_fixpoints() {
        for input in [
            "http://example.com:443",
            "https://www.x.com/login",
            "x.com:8443",
            "example.com.",
        ] {
            let stored = normalize_site(input).unwrap();
            assert_eq!(normalize_site(&stored).unwrap(), stored, "{input}");
        }
    }

    #[test]
    fn www_strips_only_as_a_prefix_of_a_dotted_domain() {
        assert_eq!(normalize_site("www.example.com").unwrap(), "example.com");
        assert_eq!(normalize_site("www.com").unwrap(), "www.com");
        assert_eq!(
            normalize_site("wwww.example.com").unwrap(),
            "wwww.example.com"
        );
    }

    #[test]
    fn junk_sites_are_refused() {
        assert!(normalize_site("").is_err());
        assert!(normalize_site("   ").is_err());
        assert!(normalize_site("ftp://example.com").is_err());
        assert!(normalize_site("https://user:pw@example.com").is_err());
        assert!(normalize_site("not a website").is_err());
    }

    #[test]
    fn names_derive_from_site_and_username() {
        let none_taken = |_: &str| false;
        assert_eq!(
            derive_password_name("x.com", Some("raykyri@gmail.com"), none_taken),
            "PASSWORD_X_COM_RAYKYRI"
        );
        assert_eq!(
            derive_password_name("google.com", Some("social@aka.com"), none_taken),
            "PASSWORD_GOOGLE_COM_SOCIAL"
        );
        assert_eq!(
            derive_password_name("fly.io", None, none_taken),
            "PASSWORD_FLY_IO"
        );
        assert_eq!(
            derive_password_name("localhost:8080", Some("---"), none_taken),
            "PASSWORD_LOCALHOST_8080"
        );
    }

    #[test]
    fn taken_names_gain_a_numeric_suffix() {
        let taken = |name: &str| name == "PASSWORD_X_COM" || name == "PASSWORD_X_COM_2";
        assert_eq!(
            derive_password_name("x.com", None, taken),
            "PASSWORD_X_COM_3"
        );
    }

    #[test]
    fn long_parts_stay_within_the_name_limit() {
        let site = format!("{}.com", "a".repeat(80));
        let name = derive_password_name(&site, Some("user"), |_| false);
        assert!(name.len() <= 64, "{name}");
        assert!(name.starts_with("PASSWORD_A"));
        let suffixed = derive_password_name(&site, Some("user"), |n| n.len() == 64);
        assert!(suffixed.len() <= 64, "{suffixed}");
    }
}
