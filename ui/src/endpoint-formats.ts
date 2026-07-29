// Copy-ready renderings of an issued direct endpoint for common client
// applications — the button row under the detail pane's connect field.
// Pure string factories over the connection summary and the resolved
// endpoint address, in the vein of getting-started's SNIPPETS table.

import { sshDirectCommand } from './getting-started';
import type { ConnectionSummary, ConnectionType } from './types';

export interface EndpointFormat {
  key: string;
  /** Button text — the client application or format name. */
  label: string;
  /** Tooltip naming what the copied string is for. */
  title: string;
  /**
   * True when the copied text embeds the endpoint's retained secret, which
   * connection summaries never carry — the click handler reads it back from
   * the broker before building.
   */
  needsSecret?: boolean;
  /**
   * True when this format copies the endpoint's *second* address rather than
   * the one the field shows — the Postgres TCP DSN, which only the broker
   * knows (it carries the pinned port). The handler reads it back and passes
   * it as `address`; the button is skipped when the endpoint has no second
   * address.
   */
  needsAltAddress?: boolean;
  /** The copyable string, or null when the summary lacks the parts. */
  build: (c: ConnectionSummary, address: string, secret?: string | null) => string | null;
}

/** The value as one double-quoted shell argument. */
function shellQuoted(value: string): string {
  return `"${value.replace(/[\\"`$]/g, '\\$&')}"`;
}

function dec(part: string | undefined): string {
  if (!part) return '';
  try {
    return decodeURIComponent(part);
  } catch {
    return part;
  }
}

// postgresql://user:password@host:port/dbname?params — every slot optional.
// The broker's own endpoint DSN uses an empty authority host with the Unix
// socket directory riding in ?host=, so query params override the authority.
const PG_DSN = /^postgres(?:ql)?:\/\/(?:([^:@/?#]*)(?::([^@/?#]*))?@)?([^/?#:]*)(?::(\d+))?(?:\/([^?#]*))?(?:\?([^#]*))?$/;

/** libpq quoting: single-quote values with spaces, quotes, or backslashes. */
function libpqValue(value: string): string {
  return /[\s'\\]/.test(value) ? `'${value.replace(/[\\']/g, '\\$&')}'` : value;
}

/**
 * The DSN re-expressed as libpq keyword/value pairs — the form GUI clients
 * with separate fields (pgAdmin, DBeaver, DataGrip) and libpq itself accept.
 */
export function libpqKeywords(dsn: string): string | null {
  const match = dsn.match(PG_DSN);
  if (!match) return null;
  const [, user, password, host, port, dbname, rawQuery] = match;
  const query = new URLSearchParams(rawQuery ?? '');
  const pairs: Array<[string, string]> = [];
  const put = (key: string, value: string): void => {
    if (value) pairs.push([key, value]);
  };
  put('host', query.get('host') ?? dec(host));
  put('port', query.get('port') ?? (port ?? ''));
  put('dbname', dec(dbname));
  put('user', dec(user));
  put('password', dec(password));
  for (const [key, value] of query) {
    if (key !== 'host' && key !== 'port') put(key, value);
  }
  if (!pairs.length) return null;
  return pairs.map(([key, value]) => `${key}=${libpqValue(value)}`).join(' ');
}

/**
 * The SSH target's explicit parts. Summary fields win; an imported
 * destination contributes what it spells out (`user@host`), and a bare
 * alias stands in as the host — the best available name for it.
 */
function sshParts(
  c: ConnectionSummary,
): { user: string | null; host: string; port: number | null } | null {
  if (c.host) return { user: c.user ?? null, host: c.host, port: c.port ?? null };
  const destination = c.destination?.trim();
  if (!destination) return null;
  const at = destination.lastIndexOf('@');
  return at > 0
    ? { user: destination.slice(0, at), host: destination.slice(at + 1), port: c.port ?? null }
    : { user: null, host: destination, port: c.port ?? null };
}

/**
 * An scp command over the issued signing socket, mirroring
 * sshInvocationCommand's destination logic (imported alias wins, the
 * import-time non-default port is pinned over whatever the alias resolves to
 * today) — scp spells the port flag -P.
 */
export function scpCommand(socket: string, c: ConnectionSummary): string {
  const importedDestination = c.destination?.trim();
  const destination = importedDestination
    || (c.user && c.host ? `${c.user}@${c.host}` : c.target);
  const port = c.port && c.port !== 22 ? ` -P ${c.port}` : '';
  return `SSH_AUTH_SOCK=${shellQuoted(socket)} scp${port} <file> ${destination}:`;
}

/** An sftp:// URL for GUI file-transfer clients (Cyberduck, FileZilla). */
export function sftpUrl(c: ConnectionSummary): string | null {
  const parts = sshParts(c);
  if (!parts) return null;
  const user = parts.user ? `${parts.user}@` : '';
  const port = parts.port && parts.port !== 22 ? `:${parts.port}` : '';
  return `sftp://${user}${parts.host}${port}`;
}

/**
 * A ~/.ssh/config block pointing IdentityAgent at the issued socket — makes
 * plain `ssh <alias>`, VS Code Remote-SSH, and anything ssh-config-aware
 * reach the server by name.
 */
export function sshConfigBlock(socket: string, c: ConnectionSummary): string | null {
  const parts = sshParts(c);
  if (!parts) return null;
  const alias = c.name.trim().replace(/\s+/g, '-');
  const lines = [`Host ${alias}`, `  HostName ${parts.host}`];
  if (parts.port && parts.port !== 22) lines.push(`  Port ${parts.port}`);
  if (parts.user) lines.push(`  User ${parts.user}`);
  lines.push(`  IdentityAgent ${shellQuoted(socket)}`);
  return lines.join('\n');
}

const SECRET_PLACEHOLDER = '<endpoint-secret>';

export const ENDPOINT_FORMATS: Record<ConnectionType, EndpointFormat[]> = {
  pg: [
    {
      key: 'psql',
      label: 'psql',
      title: 'Copy a runnable psql command',
      build: (_c, dsn) => `psql ${shellQuoted(dsn)}`,
    },
    {
      key: 'libpq',
      label: 'libpq',
      title: 'Copy libpq key/value parameters — pgAdmin, DBeaver, drivers with separate fields',
      build: (_c, dsn) => libpqKeywords(dsn),
    },
    {
      key: 'env',
      label: '.env snippet',
      title: 'Copy a DATABASE_URL line for a .env file',
      build: (_c, dsn) => `DATABASE_URL="${dsn}"`,
    },
    {
      // The Unix-socket DSN above is libpq-only and same-machine-only. JDBC,
      // Node `pg`, Npgsql and several ORMs need this form, and so does any
      // client reaching a hosted broker.
      key: 'tcp',
      label: 'TCP URL',
      title: 'Copy the TCP connection URL — JDBC, Node pg, Npgsql, and remote clients',
      needsAltAddress: true,
      build: (_c, tcpDsn) => tcpDsn,
    },
  ],
  ssh: [
    {
      key: 'ssh',
      label: 'ssh',
      title: 'Copy the ssh command over the issued signing socket',
      build: (c, socket) => sshDirectCommand(socket, c),
    },
    {
      key: 'scp',
      label: 'scp',
      title: 'Copy an scp file-copy command over the issued signing socket',
      build: (c, socket) => scpCommand(socket, c),
    },
    {
      key: 'sftp',
      label: 'sftp',
      title: 'Copy an sftp:// URL — Cyberduck, FileZilla, Transmit',
      build: (c) => sftpUrl(c),
    },
    {
      key: 'ssh-config',
      label: 'SSH config',
      title: 'Copy a ~/.ssh/config block — plain ssh by name, VS Code Remote-SSH',
      build: (c, socket) => sshConfigBlock(socket, c),
    },
  ],
  api: [
    {
      key: 'curl',
      label: 'curl',
      // Runnable as-is, and the trailing slash is the only thing marking
      // where an upstream route goes — the proxy forwards the path through,
      // so the bare root is a 404 against most APIs.
      title: 'Copy a curl command presenting the endpoint secret to the API root',
      needsSecret: true,
      build: (_c, base, secret) =>
        `curl -H "Authorization: Bearer ${secret || SECRET_PLACEHOLDER}" ${base}/`,
    },
    {
      key: 'env',
      label: '.env snippet',
      title: 'Copy API_BASE_URL and API_TOKEN lines for a .env file',
      needsSecret: true,
      build: (_c, base, secret) =>
        `API_BASE_URL=${base}\nAPI_TOKEN=${secret || SECRET_PLACEHOLDER}`,
    },
  ],
};

export function endpointFormatByKey(type: ConnectionType, key: string): EndpointFormat | null {
  return ENDPOINT_FORMATS[type].find((format) => format.key === key) ?? null;
}
