// Just enough of the Postgres frontend/backend protocol to be a client.
//
// The broker's PG data plane is a wire proxy: the agent gets a
// password-less DSN plus a short-lived ticket, and a stock client presents
// the ticket where a password would go. Testing that needs a client, and
// pulling `pg` into the repo for four test files would be a dependency the
// product does not have — so this speaks the handshake and simple query
// protocol directly (protocol 3.0, cleartext password, simple `Q` queries),
// which is all the proxy's own legs exercise.

import { connect, type Socket } from 'node:net';

export interface PgError {
  severity: string;
  code: string;
  message: string;
}

export class PostgresError extends Error {
  constructor(readonly fields: PgError) {
    super(`${fields.severity} ${fields.code}: ${fields.message}`);
    this.name = 'PostgresError';
  }
}

export interface ConnectOptions {
  host?: string;
  /** Unix socket to dial instead of host/port (a direct pg endpoint). */
  socketPath?: string;
  port?: number;
  user: string;
  database: string;
  /** The ticket, endpoint secret, or real password — whatever fills the slot. */
  password: string;
  /** Reported to the server, and shown to the user in the approval prompt. */
  applicationName?: string;
  timeoutMs?: number;
}

export interface QueryResult {
  columns: string[];
  rows: Array<Array<string | null>>;
  /** e.g. `SELECT 1` */
  tag: string;
}

/**
 * Parse a DSN into connect options. Handles both forms the broker mints:
 * the ticket DSN (`postgres://ticket@127.0.0.1:<proxy>/db`) and a direct
 * endpoint's Unix-socket DSN
 * (`postgresql://user:end_…@/db?host=<dir>&port=5432`), where libpq derives
 * the socket path as `<host>/.s.PGSQL.<port>`.
 */
export function parseDsn(dsn: string, password = ''): ConnectOptions {
  // Not `new URL`: a Unix-socket DSN has credentials and an empty host
  // (`postgresql://user:secret@/db?host=/dir`), which the WHATWG parser
  // rejects. The grammar here is exactly the two shapes the broker mints.
  const match =
    /^[a-z]+:\/\/(?:([^:@/]*)(?::([^@/]*))?@)?([^/?]*)\/([^?]*)(?:\?(.*))?$/.exec(dsn);
  if (!match) throw new Error(`not a DSN this client understands: ${dsn}`);
  const [, user, embedded, authority, database, query] = match;
  const parameters = new URLSearchParams(query ?? '');
  const directory = parameters.get('host');
  const port = Number(parameters.get('port') ?? authority.split(':')[1] ?? 5432);
  return {
    ...(directory
      ? { socketPath: `${directory}/.s.PGSQL.${port}` }
      : { host: authority.split(':')[0] || '127.0.0.1', port }),
    user: decodeURIComponent(user ?? ''),
    database: decodeURIComponent(database),
    password: embedded ? decodeURIComponent(embedded) : password,
  };
}

function int32(value: number): Buffer {
  const buffer = Buffer.alloc(4);
  buffer.writeInt32BE(value);
  return buffer;
}

function cstring(value: string): Buffer {
  return Buffer.concat([Buffer.from(value, 'utf8'), Buffer.from([0])]);
}

function message(tag: string | null, payload: Buffer): Buffer {
  const header = int32(payload.byteLength + 4);
  return tag === null
    ? Buffer.concat([header, payload])
    : Buffer.concat([Buffer.from(tag, 'ascii'), header, payload]);
}

interface Frame {
  tag: string;
  payload: Buffer;
}

/** A live connection through the broker's proxy (or straight to a server). */
export class PgConnection {
  private buffer = Buffer.alloc(0);
  private readonly frames: Frame[] = [];
  private waiter: (() => void) | undefined;
  private closed = false;
  private failure: Error | undefined;

  private constructor(private readonly socket: Socket) {
    socket.on('data', (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.drain();
    });
    socket.on('error', (error) => {
      this.failure = error;
      this.closed = true;
      this.waiter?.();
    });
    socket.on('close', () => {
      this.closed = true;
      this.waiter?.();
    });
  }

  private drain(): void {
    for (;;) {
      if (this.buffer.byteLength < 5) break;
      const length = this.buffer.readInt32BE(1);
      if (this.buffer.byteLength < length + 1) break;
      this.frames.push({
        tag: String.fromCharCode(this.buffer[0]),
        payload: this.buffer.subarray(5, length + 1),
      });
      this.buffer = this.buffer.subarray(length + 1);
    }
    this.waiter?.();
  }

  private async next(timeoutMs: number): Promise<Frame> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const frame = this.frames.shift();
      if (frame) return frame;
      if (this.failure) throw this.failure;
      if (this.closed) throw new Error('the server closed the connection');
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('timed out waiting for a Postgres message');
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, Math.min(remaining, 100));
        this.waiter = () => {
          clearTimeout(timer);
          this.waiter = undefined;
          resolve();
        };
      });
    }
  }

  static async open(options: ConnectOptions): Promise<PgConnection> {
    const timeoutMs = options.timeoutMs ?? 30_000;
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s = options.socketPath
        ? connect({ path: options.socketPath })
        : connect({ host: options.host ?? '127.0.0.1', port: options.port ?? 5432 });
      s.setTimeout(timeoutMs);
      s.once('connect', () => {
        s.setTimeout(0);
        resolve(s);
      });
      s.once('timeout', () => {
        s.destroy();
        reject(new Error(`timed out connecting to ${options.socketPath ?? options.port}`));
      });
      s.once('error', reject);
    });

    const connection = new PgConnection(socket);
    const parameters = [
      cstring('user'),
      cstring(options.user),
      cstring('database'),
      cstring(options.database),
      ...(options.applicationName
        ? [cstring('application_name'), cstring(options.applicationName)]
        : []),
      Buffer.from([0]),
    ];
    socket.write(message(null, Buffer.concat([int32(196_608), ...parameters])));

    // Handshake: an authentication request we answer with the ticket, then
    // status frames until ReadyForQuery.
    for (;;) {
      const frame = await connection.next(timeoutMs);
      if (frame.tag === 'E') {
        connection.close();
        throw new PostgresError(errorFields(frame.payload));
      }
      if (frame.tag === 'R') {
        const code = frame.payload.readInt32BE(0);
        if (code === 0) continue; // AuthenticationOk
        if (code === 3) {
          socket.write(message('p', cstring(options.password)));
          continue;
        }
        connection.close();
        throw new Error(`unsupported Postgres authentication request ${code}`);
      }
      if (frame.tag === 'Z') return connection; // ReadyForQuery
      // 'S' ParameterStatus, 'K' BackendKeyData, 'N' NoticeResponse: ignore.
    }
  }

  async query(sql: string, timeoutMs = 30_000): Promise<QueryResult> {
    this.socket.write(message('Q', cstring(sql)));
    const result: QueryResult = { columns: [], rows: [], tag: '' };
    let failure: PostgresError | undefined;
    for (;;) {
      const frame = await this.next(timeoutMs);
      switch (frame.tag) {
        case 'T': {
          const count = frame.payload.readInt16BE(0);
          let offset = 2;
          for (let i = 0; i < count; i += 1) {
            const end = frame.payload.indexOf(0, offset);
            result.columns.push(frame.payload.subarray(offset, end).toString('utf8'));
            offset = end + 1 + 18; // the fixed per-column metadata that follows
          }
          break;
        }
        case 'D': {
          const count = frame.payload.readInt16BE(0);
          let offset = 2;
          const row: Array<string | null> = [];
          for (let i = 0; i < count; i += 1) {
            const length = frame.payload.readInt32BE(offset);
            offset += 4;
            if (length === -1) {
              row.push(null);
            } else {
              row.push(frame.payload.subarray(offset, offset + length).toString('utf8'));
              offset += length;
            }
          }
          result.rows.push(row);
          break;
        }
        case 'C':
          result.tag = frame.payload.subarray(0, frame.payload.indexOf(0)).toString('utf8');
          break;
        case 'E':
          failure = new PostgresError(errorFields(frame.payload));
          break;
        case 'Z':
          if (failure) throw failure;
          return result;
        default:
          break;
      }
    }
  }

  /** Wait for the server to hang up (used when the app closes a session). */
  async waitForClose(timeoutMs = 15_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!this.closed) {
      if (Date.now() > deadline) throw new Error('the session was still open');
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  get isClosed(): boolean {
    return this.closed;
  }

  close(): void {
    if (!this.socket.destroyed) {
      try {
        this.socket.write(message('X', Buffer.alloc(0)));
      } catch {
        // Already gone; nothing to terminate politely.
      }
      this.socket.destroy();
    }
    this.closed = true;
  }
}

function errorFields(payload: Buffer): PgError {
  const fields: Record<string, string> = {};
  let offset = 0;
  while (offset < payload.byteLength && payload[offset] !== 0) {
    const type = String.fromCharCode(payload[offset]);
    const end = payload.indexOf(0, offset + 1);
    fields[type] = payload.subarray(offset + 1, end).toString('utf8');
    offset = end + 1;
  }
  return {
    severity: fields.S ?? fields.V ?? 'ERROR',
    code: fields.C ?? '',
    message: fields.M ?? '',
  };
}

/** Open, run one query, close. */
export async function queryOnce(
  options: ConnectOptions,
  sql: string,
): Promise<QueryResult> {
  const connection = await PgConnection.open(options);
  try {
    return await connection.query(sql);
  } finally {
    connection.close();
  }
}
