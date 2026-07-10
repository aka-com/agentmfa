// Pure connection-form helpers. Kept separate from app.js so the security-
// relevant normalization rules can be exercised without a browser/Tauri.

export function apiOriginFromParts(scheme = 'https', host = '', port = null) {
  if (!host) return '';
  return `${scheme || 'https'}://${host}${port ? `:${port}` : ''}`;
}

export function parseApiOrigin(value) {
  let parsed;
  try {
    parsed = new URL(String(value).trim());
  } catch {
    throw new Error('Enter a complete origin such as https://api.example.com');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('API origin must start with https:// or http://');
  }
  if (parsed.username || parsed.password) {
    throw new Error('API origin must not contain credentials');
  }
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('API origin cannot contain a path, query, or fragment');
  }
  const port = parsed.port ? Number(parsed.port) : null;
  return {
    scheme: parsed.protocol.slice(0, -1),
    host: parsed.hostname,
    port,
  };
}

export function portForTypeSwitch(currentType, nextType, currentPort) {
  const defaults = { pg: '5432', ssh: '22' };
  const value = currentPort == null ? '' : String(currentPort);
  if (value === (defaults[currentType] || '')) return defaults[nextType] || '';
  return value || defaults[nextType] || '';
}

function decoded(value, label) {
  try { return decodeURIComponent(value); }
  catch { throw new Error(`${label} contains invalid percent encoding`); }
}

function suggestedName(host, fallback) {
  const first = String(host || fallback || 'connection').split('.')[0];
  const clean = first.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  return clean || fallback || 'connection';
}

function unwrapInput(value) {
  let text = String(value || '').trim();
  text = text.replace(/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*/, '').trim();
  if ((text.startsWith('"') && text.endsWith('"')) ||
      (text.startsWith("'") && text.endsWith("'"))) text = text.slice(1, -1);
  return text.trim();
}

function parseSshCommand(text) {
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
  const warnings = ['Confirm the server host-key fingerprint before saving.'];
  if (!user) warnings.unshift('SSH user was not present; enter it below.');
  if (identityFile) warnings.push(`Identity file ${identityFile} is not read automatically; choose or save its private key below.`);
  return {
    type: 'ssh', name: suggestedName(host, 'ssh'), credential: null, warnings,
    fields: { host, port, user, hostKeyFingerprint: '' },
  };
}

export function parseConnectionImport(value) {
  const text = unwrapInput(value);
  if (!text) throw new Error('Paste a URL, Postgres DSN, or ssh command');
  if (/^ssh\s+/i.test(text)) return parseSshCommand(text);

  let parsed;
  try { parsed = new URL(text); }
  catch { throw new Error('Could not recognize that connection. Use a complete URL, Postgres DSN, or ssh command.'); }
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  if (scheme === 'http' || scheme === 'https') {
    if (parsed.username || parsed.password) throw new Error('API URLs with embedded credentials are not supported');
    const warnings = [];
    if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
      warnings.push('Only the API origin is saved; the path, query, and fragment are supplied per request.');
    }
    return {
      type: 'api', name: suggestedName(parsed.hostname, 'api'), credential: null, warnings,
      fields: { origin: parsed.origin },
    };
  }
  if (scheme === 'ws' || scheme === 'wss') {
    if (parsed.username || parsed.password) throw new Error('WebSocket URLs with embedded credentials are not supported');
    return {
      type: 'ws', name: suggestedName(parsed.hostname, 'stream'), credential: null, warnings: [],
      fields: { url: parsed.href },
    };
  }
  if (scheme === 'postgres' || scheme === 'postgresql') {
    if (!parsed.hostname) throw new Error('Postgres DSN is missing a host');
    const user = decoded(parsed.username, 'Postgres user');
    const credential = parsed.password ? decoded(parsed.password, 'Postgres password') : null;
    const dbname = decoded(parsed.pathname.replace(/^\//, ''), 'Postgres database');
    const rawSslmode = parsed.searchParams.get('sslmode') || 'require';
    const allowed = new Set(['disable', 'prefer', 'require', 'verify-ca', 'verify-full']);
    const sslmode = allowed.has(rawSslmode) ? rawSslmode : 'require';
    const warnings = [];
    if (!user) warnings.push('Postgres user was not present; enter it below.');
    if (!dbname) warnings.push('Database name was not present; enter it below.');
    if (rawSslmode !== sslmode) warnings.push(`Unsupported sslmode ${rawSslmode}; using require.`);
    const unsupported = [...parsed.searchParams.keys()].filter((key) => key !== 'sslmode');
    if (unsupported.length) warnings.push(`Review unsupported DSN options: ${[...new Set(unsupported)].join(', ')}.`);
    if (credential) warnings.push('A password was detected. It will only be saved if you choose “Save a new credential” below.');
    return {
      type: 'pg', name: suggestedName(parsed.hostname, 'postgres'), credential, warnings,
      fields: {
        host: parsed.hostname,
        port: parsed.port ? Number(parsed.port) : 5432,
        user,
        dbname,
        sslmode,
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
      warnings: [
        ...(user ? [] : ['SSH user was not present; enter it below.']),
        'Confirm the server host-key fingerprint before saving.',
      ],
      fields: { host, port: parsed.port ? Number(parsed.port) : 22, user, hostKeyFingerprint: '' },
    };
  }
  throw new Error(`Connection scheme ${scheme || '(missing)'} is not supported`);
}

export function suggestedSecretName(connectionName, type) {
  const base = String(connectionName || 'CONNECTION')
    .toUpperCase().replace(/[^A-Z0-9_]+/g, '_').replace(/^_+|_+$/g, '') || 'CONNECTION';
  const suffix = type === 'pg' ? 'PASSWORD' : type === 'ssh' ? 'SSH_KEY' : 'TOKEN';
  return `${base}_${suffix}`.slice(0, 64);
}

export function authTemplate(type, mode, secretName, detail = '') {
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
