// A minimal ssh-agent client, for talking to the socket `/v1/ssh/open` mints.
//
// `multitool ssh <connection>` hands an agent socket to a stock OpenSSH client;
// the broker signs with a key that never leaves it. These helpers let a test
// inspect that socket directly — list the identity, and attempt a signature
// — without needing a full SSH client, which matters for the refusal cases:
// a signature request that skipped `session-bind@openssh.com` is exactly
// what a stock client never sends.

import { connect, type Socket } from 'node:net';

export const SSH_AGENT_FAILURE = 5;
export const SSH_AGENT_SUCCESS = 6;
export const SSH_AGENTC_REQUEST_IDENTITIES = 11;
export const SSH_AGENT_IDENTITIES_ANSWER = 12;
export const SSH_AGENTC_SIGN_REQUEST = 13;
export const SSH_AGENT_SIGN_RESPONSE = 14;
export const SSH_AGENTC_EXTENSION = 27;

export interface AgentIdentity {
  /** The public key blob, as the agent returned it. */
  blob: Buffer;
  comment: string;
  /** The key type read out of the blob, e.g. `ssh-ed25519`. */
  type: string;
}

export interface AgentReply {
  type: number;
  payload: Buffer;
}

function sshString(value: Buffer | string): Buffer {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([header, bytes]);
}

class Reader {
  private offset = 0;
  constructor(private readonly buffer: Buffer) {}

  u32(): number {
    const value = this.buffer.readUInt32BE(this.offset);
    this.offset += 4;
    return value;
  }

  string(): Buffer {
    const length = this.u32();
    const value = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  get done(): boolean {
    return this.offset >= this.buffer.byteLength;
  }
}

/** One request/response round trip against an agent socket. */
export async function agentRequest(
  socketPath: string,
  type: number,
  payload: Buffer = Buffer.alloc(0),
  timeoutMs = 10_000,
): Promise<AgentReply> {
  const socket: Socket = await new Promise((resolve, reject) => {
    const s = connect({ path: socketPath });
    s.once('connect', () => resolve(s));
    s.once('error', reject);
  });
  try {
    const body = Buffer.concat([Buffer.from([type]), payload]);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(body.byteLength);
    socket.write(Buffer.concat([length, body]));

    return await new Promise<AgentReply>((resolve, reject) => {
      let buffer = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error('the agent did not answer')), timeoutMs);
      socket.on('data', (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.byteLength < 4) return;
        const size = buffer.readUInt32BE(0);
        if (buffer.byteLength < size + 4) return;
        clearTimeout(timer);
        resolve({ type: buffer[4], payload: buffer.subarray(5, size + 4) });
      });
      socket.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      socket.on('close', () => {
        clearTimeout(timer);
        reject(new Error('the agent closed the connection without answering'));
      });
    });
  } finally {
    socket.destroy();
  }
}

/** `SSH_AGENTC_REQUEST_IDENTITIES`: what this socket will sign with. */
export async function listIdentities(socketPath: string): Promise<AgentIdentity[]> {
  const reply = await agentRequest(socketPath, SSH_AGENTC_REQUEST_IDENTITIES);
  if (reply.type !== SSH_AGENT_IDENTITIES_ANSWER) {
    throw new Error(`the agent refused the identity listing (type ${reply.type})`);
  }
  const reader = new Reader(reply.payload);
  const count = reader.u32();
  const identities: AgentIdentity[] = [];
  for (let i = 0; i < count; i += 1) {
    const blob = reader.string();
    const comment = reader.string().toString('utf8');
    identities.push({ blob, comment, type: new Reader(blob).string().toString('utf8') });
  }
  return identities;
}

/**
 * `SSH_AGENTC_SIGN_REQUEST` with an arbitrary blob. The broker only signs a
 * userauth request for the pinned user on a session it has bound, so this is
 * the refusal path unless a real client did the handshake first.
 */
export async function signRequest(
  socketPath: string,
  keyBlob: Buffer,
  data: Buffer,
  flags = 0,
): Promise<AgentReply> {
  const flagBytes = Buffer.alloc(4);
  flagBytes.writeUInt32BE(flags);
  return agentRequest(
    socketPath,
    SSH_AGENTC_SIGN_REQUEST,
    Buffer.concat([sshString(keyBlob), sshString(data), flagBytes]),
  );
}

/** An agent extension request (the broker implements session-bind only). */
export async function extension(
  socketPath: string,
  name: string,
  payload: Buffer = Buffer.alloc(0),
): Promise<AgentReply> {
  return agentRequest(
    socketPath,
    SSH_AGENTC_EXTENSION,
    Buffer.concat([sshString(name), payload]),
  );
}
