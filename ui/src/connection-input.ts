// Pure connection-form helpers. Kept separate from app.tsx so the security-
// relevant normalization rules can be exercised without a browser/Tauri.

export type ConnectionType = 'api' | 'pg' | 'ssh';
export type SecretSource = 'existing' | 'new' | 'none';

/** Initial credential selection for a connection form. MCP OAuth mints its
 * own credential, while branded REST and manual-token MCP flows exist to
 * collect one. Infrastructure remains intentionally credential-optional. */
export function initialSecretSource(input: {
  type: ConnectionType;
  explicit?: SecretSource;
  imported: boolean;
  mcp: boolean;
  authMode?: string;
  brandedApi: boolean;
}): SecretSource {
  if (input.explicit) return input.explicit;
  if (input.imported) return 'new';
  if (input.type === 'api' && input.mcp) {
    return input.authMode === 'oauth' ? 'none' : 'new';
  }
  if (input.type === 'api' && input.brandedApi) return 'new';
  return 'none';
}

const QUICK_SETUP_PLACEHOLDERS: Record<ConnectionType, string> = {
  pg: 'postgresql://app@db.example.com/production',
  ssh: 'ssh deploy@prod.example.com',
  api: 'https://api.github.com',
};

export function quickSetupPlaceholder(type: ConnectionType): string {
  return QUICK_SETUP_PLACEHOLDERS[type];
}

/** Whether a host names this machine's loopback interface. */
export function isLoopbackHost(host: string | null | undefined): boolean {
  let normalized = (host || '').trim().toLowerCase();
  if (normalized.endsWith('.')) normalized = normalized.slice(0, -1);
  if (normalized.startsWith('[') && normalized.endsWith(']')) {
    normalized = normalized.slice(1, -1);
  }
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return true;
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;

  const octets = normalized.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

/** Warn when a complete broker/browser URL would expose credentials on the
 * network. Incomplete input is left to normal form validation. */
export function insecureNonLoopbackHttp(value: unknown): boolean {
  try {
    const parsed = new URL(String(value).trim());
    return parsed.protocol === 'http:' && !isLoopbackHost(parsed.hostname);
  } catch {
    return false;
  }
}

/** The default name for a new connection: the tool's label, numbered when
 * the label is already taken — "Postgres", then "Postgres 2". The endpoint
 * never rides in the name; the row's subline carries the live target. */
export function defaultConnectionName(
  type: ConnectionType,
  label: string,
  existingNames: string[] = [],
): string {
  const base = label.trim() || (type === 'pg' ? 'Postgres' : type === 'ssh' ? 'SSH' : 'Connection');
  const taken = new Set(existingNames.map((name) => name.trim().toLowerCase()));
  if (!taken.has(base.toLowerCase())) return base;
  for (let n = 2; ; n++) {
    const candidate = `${base} ${n}`;
    if (!taken.has(candidate.toLowerCase())) return candidate;
  }
}

export interface HostKeyCandidate {
  fingerprint: string;
  algorithm: string;
  source: string;
}

export interface SshImportPreview {
  importId: string;
  destination: string;
  host: string;
  port: number;
  user: string;
  proxyJump?: string | null;
  identityFiles?: string[];
  hostKeyCandidates?: HostKeyCandidate[];
  warnings?: string[];
}

interface ImportBase<T extends ConnectionType, F> {
  type: T;
  name: string;
  credential: string | null;
  warnings: string[];
  fields: F;
}

export type ConnectionImport =
  | ImportBase<'api', { origin: string }>
  | ImportBase<'pg', {
      host: string;
      port: number;
      user: string;
      dbname: string;
      sslmode: string;
      pgCaBundlePath: string | null;
    }>
  | ImportBase<'ssh', {
      destination?: string;
      host: string;
      port: number;
      user: string;
      // Always empty on import: the host key is confirmed with the user and
      // pinned at the first agent connection (trust on first use).
      hostKeyFingerprint: string;
      identityFiles?: string[];
      identityFile?: string;
      sshImportId?: string;
      proxyJump?: string | null;
    }>;

export function apiOriginFromParts(
  scheme = 'https',
  host = '',
  port: number | string | null = null,
): string {
  if (!host) return '';
  return `${scheme || 'https'}://${host}${port ? `:${port}` : ''}`;
}

export function parseApiOrigin(value: unknown): {
  scheme: string;
  host: string;
  port: number | null;
} {
  let parsed: URL;
  try {
    parsed = new URL(String(value).trim());
  } catch {
    throw new Error('Enter a complete API root such as https://api.example.com');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('API root must start with https:// or http://');
  }
  if (parsed.username || parsed.password) {
    throw new Error('API root must not contain credentials');
  }
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('API root cannot contain a path, query, or fragment');
  }
  const port = parsed.port ? Number(parsed.port) : null;
  return {
    scheme: parsed.protocol.slice(0, -1),
    host: parsed.hostname,
    port,
  };
}

/**
 * Split an MCP server URL into the parts a connection stores.
 *
 * An MCP server is an API connection whose path matters, so unlike
 * `parseApiOrigin` this keeps the path — that is the `mcp_path` the MCP host
 * posts JSON-RPC to. A bare origin means `/mcp`, the conventional default.
 */
export function parseMcpServerUrl(value: unknown): {
  scheme: string;
  host: string;
  port: number | null;
  mcpPath: string;
} {
  let parsed: URL;
  try {
    parsed = new URL(String(value).trim());
  } catch {
    throw new Error('Enter a complete server URL such as https://mcp.example.com/mcp');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Server URL must start with https:// or http://');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Server URL must not contain credentials');
  }
  if (parsed.hash) {
    throw new Error('Server URL cannot contain a fragment');
  }
  const path = parsed.pathname === '/' ? '/mcp' : parsed.pathname.replace(/\/$/, '');
  return {
    scheme: parsed.protocol.slice(0, -1),
    host: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : null,
    mcpPath: `${path}${parsed.search}`,
  };
}

function decoded(value: string, label: string): string {
  try { return decodeURIComponent(value); }
  catch { throw new Error(`${label} contains invalid percent encoding`); }
}

function isIpAddress(host: string): boolean {
  const value = host.replace(/^\[|\]$/g, '');
  if (value.includes(':')) return /^[0-9a-f:.]+$/i.test(value);
  const octets = value.split('.');
  return octets.length === 4 && octets.every((octet) =>
    /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function suggestedName(host: string | undefined, fallback: string): string {
  if (host && isIpAddress(host)) return '';
  const first = String(host || fallback || 'connection').split('.')[0];
  const clean = first.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  return clean || fallback || 'connection';
}

function unwrapInput(value: unknown): string {
  let text = String(value || '').trim();
  text = text.replace(/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*/, '').trim();
  if ((text.startsWith('"') && text.endsWith('"')) ||
      (text.startsWith("'") && text.endsWith("'"))) text = text.slice(1, -1);
  return text.trim();
}

function parseSshCommand(text: string): ConnectionImport {
  if (/[;&|`$<>\n\r]/.test(text)) {
    throw new Error('SSH import accepts one ssh command without shell operators');
  }
  const parts = text.split(/\s+/).filter(Boolean);
  if (parts.shift() !== 'ssh') throw new Error('SSH command must start with ssh');
  let port = 22;
  let identityFile = null;
  let destination = null;
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i];
    if (part === '-p') {
      const raw = parts[++i];
      if (!/^\d+$/.test(raw || '') || Number(raw) < 1 || Number(raw) > 65535) {
        throw new Error('SSH port must be between 1 and 65535');
      }
      port = Number(raw);
    } else if (part === '-i') {
      identityFile = parts[++i] || null;
      if (!identityFile) throw new Error('SSH -i requires an identity file');
    } else if (part.startsWith('-')) {
      throw new Error(`SSH option ${part} is not supported by quick import`);
    } else if (!destination) destination = part;
    else throw new Error('SSH import accepts a destination but not a remote command');
  }
  if (!destination) throw new Error('SSH command is missing user@host');
  const at = destination.lastIndexOf('@');
  const user = at >= 0 ? destination.slice(0, at) : '';
  const host = at >= 0 ? destination.slice(at + 1) : destination;
  if (!host || host.includes(':') || host.includes('/')) {
    throw new Error('SSH destination must be a hostname or user@hostname');
  }
  const warnings = [];
  if (!user) warnings.push('SSH user was not present; enter it below.');
  if (identityFile) warnings.push(`Identity file ${identityFile} is not read automatically; choose or save its private key below.`);
  return {
    type: 'ssh', name: suggestedName(host, 'ssh'), credential: null, warnings,
    fields: { host, port, user, hostKeyFingerprint: '' },
  };
}

export function shouldResolveSshImport(value: unknown): boolean {
  const text = unwrapInput(value);
  if (/^ssh\s+/i.test(text)) return true;
  return /^[A-Za-z0-9._+%-]+(?:@[A-Za-z0-9._+%-]+)?$/.test(text);
}

/**
 * The fingerprint to pre-fill, and what to say about it.
 *
 * Leaving this blank meant trust-on-first-use: the first key the broker sees
 * becomes the permanent anchor, silently. The user's own `known_hosts` is a
 * better anchor — it was established by their own earlier connections rather
 * than by whatever answers next — and the resolver already collected it. So a
 * single candidate is pre-filled, with the file it came from named, and it sits
 * in an editable field the user can clear.
 *
 * Several candidates are *not* guessed between. The pin is one fingerprint and
 * the client presents whichever host key algorithm it negotiates, so picking
 * the wrong one of two turns every login into a host-key refusal. They are
 * listed instead, for the user to paste one.
 */
function hostKeyPrefill(
  candidates: HostKeyCandidate[],
): { fingerprint: string; warnings: string[] } {
  if (candidates.length === 1) {
    const [only] = candidates;
    return {
      fingerprint: only.fingerprint,
      warnings: [`Host key pinned from ${only.source} (${only.algorithm}). Clear it to trust the first key seen instead.`],
    };
  }
  if (candidates.length > 1) {
    const listed = candidates.map((c) => `${c.algorithm} ${c.fingerprint}`).join(', ');
    return {
      fingerprint: '',
      warnings: [`known_hosts holds more than one key for this destination (${listed}); paste the one to pin, or leave it blank to trust the first key seen.`],
    };
  }
  return { fingerprint: '', warnings: [] };
}

export function sshImportFromPreview(preview: SshImportPreview): ConnectionImport {
  const identityFiles = preview.identityFiles || [];
  const destinationHost = String(preview.destination || preview.host || '').split('@').pop();
  const hostKey = hostKeyPrefill(preview.hostKeyCandidates || []);
  return {
    type: 'ssh',
    name: suggestedName(destinationHost, 'ssh'),
    credential: null,
    warnings: [...(preview.warnings || []), ...hostKey.warnings],
    fields: {
      destination: preview.destination,
      host: preview.host,
      port: preview.port,
      user: preview.user,
      hostKeyFingerprint: hostKey.fingerprint,
      identityFiles,
      identityFile: identityFiles.length === 1 ? identityFiles[0] : '',
      sshImportId: preview.importId,
      proxyJump: preview.proxyJump || null,
    },
  };
}

export function parseConnectionImport(value: unknown): ConnectionImport {
  const text = unwrapInput(value);
  if (!text) throw new Error('Paste a URL, Postgres DSN, or ssh command');
  if (/^ssh\s+/i.test(text)) return parseSshCommand(text);

  let parsed: URL;
  try { parsed = new URL(text); }
  catch { throw new Error('Could not recognize that tool. Use a complete URL, Postgres DSN, or ssh command.'); }
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  if (scheme === 'http' || scheme === 'https') {
    if (parsed.username || parsed.password) throw new Error('API URLs with embedded credentials are not supported');
    const warnings = [];
    if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
      warnings.push('Only the API root is saved; the path, query, and fragment are supplied per request.');
    }
    return {
      type: 'api', name: suggestedName(parsed.hostname, 'api'), credential: null, warnings,
      fields: { origin: parsed.origin },
    };
  }
  if (scheme === 'postgres' || scheme === 'postgresql') {
    if (!parsed.hostname) throw new Error('Postgres DSN is missing a host');
    const user = decoded(parsed.username, 'Postgres user');
    const credential = parsed.password ? decoded(parsed.password, 'Postgres password') : null;
    const dbname = decoded(parsed.pathname.replace(/^\//, ''), 'Postgres database');
    const rawSslmode = parsed.searchParams.get('sslmode') || 'verify-full';
    const allowed = new Set(['disable', 'prefer', 'require', 'verify-ca', 'verify-full']);
    const sslmode = allowed.has(rawSslmode) ? rawSslmode : 'verify-full';
    const trustedCaBundlePath = parsed.searchParams.get('sslrootcert') || null;
    const warnings = [];
    if (!user) warnings.push('Postgres user was not present; enter it below.');
    if (!dbname) warnings.push('Database name was not present; enter it below.');
    if (rawSslmode !== sslmode) warnings.push(`Unsupported sslmode ${rawSslmode}; using verify-full.`);
    const unsupported = [...parsed.searchParams.keys()].filter((key) => !['sslmode', 'sslrootcert'].includes(key));
    if (unsupported.length) warnings.push(`Review unsupported DSN options: ${[...new Set(unsupported)].join(', ')}.`);
    if (credential) warnings.push('A password was filled in below. It will be saved if you add this tool with “New secret…” selected.');
    return {
      type: 'pg', name: suggestedName(parsed.hostname, 'postgres'), credential, warnings,
      fields: {
        host: parsed.hostname,
        port: parsed.port ? Number(parsed.port) : 5432,
        user,
        dbname,
        sslmode,
        pgCaBundlePath: trustedCaBundlePath,
      },
    };
  }
  if (scheme === 'ssh') {
    if (parsed.password) throw new Error('SSH URLs with embedded passwords are not supported');
    const host = parsed.hostname;
    const user = decoded(parsed.username, 'SSH user');
    if (!host) throw new Error('SSH URL is missing a host');
    return {
      type: 'ssh', name: suggestedName(host, 'ssh'), credential: null,
      warnings: user ? [] : ['SSH user was not present; enter it below.'],
      fields: { host, port: parsed.port ? Number(parsed.port) : 22, user, hostKeyFingerprint: '' },
    };
  }
  throw new Error(`Tool scheme ${scheme || '(missing)'} is not supported`);
}

export function suggestedSecretName(connectionName: string, type: ConnectionType): string {
  // Postgres and SSH connection names already embed the tool ("SSH
  // (localhost)"), so deriving the credential name from them doubles it up
  // (SSH_LOCALHOST_SSH_KEY). The tool's base name alone is the suggestion.
  if (type === 'pg') return 'POSTGRES_PASSWORD';
  if (type === 'ssh') return 'SSH_KEY';
  const base = String(connectionName || 'CONNECTION')
    .toUpperCase().replace(/[^A-Z0-9_]+/g, '_').replace(/^_+|_+$/g, '') || 'CONNECTION';
  return `${base}_TOKEN`.slice(0, 64);
}

export function authTemplate(
  type: ConnectionType,
  mode: string,
  secretName: string,
  detail = '',
): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(secretName)) {
    throw new Error('Credential name must be a valid template reference');
  }
  if (mode === 'bearer') return `Authorization: Bearer {{${secretName}}}`;
  if (mode === 'header') {
    if (!/^[A-Za-z0-9-]+$/.test(detail)) throw new Error('Enter a valid HTTP header name');
    return `${detail}: {{${secretName}}}`;
  }
  if (type === 'api' && mode === 'query') {
    if (!/^[A-Za-z0-9._~-]+$/.test(detail)) throw new Error('Enter a valid query parameter name');
    return `?${detail}={{url(${secretName})}}`;
  }
  throw new Error('Unsupported authentication recipe');
}

/**
 * Point an existing one-credential API template at another saved credential.
 *
 * Stored templates are already parse-validated by the broker. Rewriting only
 * reference tokens inside placeholders preserves the chosen header/query
 * shape and deliberately leaves literal text (including quoted transform
 * arguments) untouched. A credential-less template has no shape to preserve,
 * so it adopts the ordinary Bearer form.
 */
export function rebindApiCredentialTemplate(
  template: string,
  oldName: string | null | undefined,
  newName: string,
): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(newName)) {
    throw new Error('Credential name must be a valid template reference');
  }
  if (!template.trim() || !oldName) return authTemplate('api', 'bearer', newName);

  let rewritten = false;
  const next = template.replace(/\{\{([\s\S]*?)\}\}/g, (placeholder, expression: string) => {
    const open = expression.indexOf('(');
    if (open < 0) {
      if (expression.trim() !== oldName) return placeholder;
      rewritten = true;
      return `{{${expression.replace(oldName, newName)}}}`;
    }

    // Function names are not credential references. Only scan the argument
    // list, and skip double-quoted literals such as base64(USER ":" PASS).
    const close = expression.lastIndexOf(')');
    if (close < open) return placeholder;
    const args = expression.slice(open + 1, close);
    let out = '';
    let index = 0;
    let quoted = false;
    while (index < args.length) {
      const char = args[index];
      if (quoted && char === '\\' && index + 1 < args.length) {
        out += char + args[index + 1];
        index += 2;
        continue;
      }
      if (char === '"') {
        quoted = !quoted;
        out += char;
        index += 1;
        continue;
      }
      if (!quoted && /[A-Za-z_]/.test(char)) {
        let end = index + 1;
        while (end < args.length && /[A-Za-z0-9_]/.test(args[end])) end += 1;
        const token = args.slice(index, end);
        if (token === oldName) {
          out += newName;
          rewritten = true;
        } else {
          out += token;
        }
        index = end;
        continue;
      }
      out += char;
      index += 1;
    }
    return `{{${expression.slice(0, open + 1)}${out}${expression.slice(close)}}}`;
  });

  // This can only happen after the user manually changed the advanced
  // template after opening the sheet. Avoid presenting a chooser selection
  // that does not match the saved template.
  return rewritten ? next : authTemplate('api', 'bearer', newName);
}
