// Where the Docker sandbox lives and what it expects.
//
// Every value here mirrors dev/sandbox/compose.yaml and
// scripts/sandbox-status.sh — the same SANDBOX_*_PORT overrides, the same
// fake fixture credentials. Keep the three in sync; the fixed credentials
// are test values that must never be reused outside the sandbox.

import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { request } from './http';
import { run } from './proc';

export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');

function port(variable: string, fallback: number): number {
  const raw = process.env[variable];
  const parsed = raw === undefined ? Number.NaN : Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export const sandbox = {
  /** The HTTP API fixture, which also serves MCP at /mcp. */
  httpPort: port('SANDBOX_HTTP_PORT', 18080),
  /** The fixture's second published port; the cross-origin redirect target. */
  altPort: port('SANDBOX_ALT_PORT', 18081),
  pgPort: port('SANDBOX_PG_PORT', 15432),
  sshPort: port('SANDBOX_SSH_PORT', 12222),

  host: '127.0.0.1',
  httpToken: 'aka-test-token',
  mcpToken: 'aka-mcp-test-token',
  mcpPath: '/mcp',

  pgUser: 'aka',
  pgPassword: 'aka-test-password',
  pgDatabase: 'aka_sandbox',

  sshUser: 'sandbox',
  sshKeyPath: join(repoRoot, 'dev/sandbox/state/ssh/client_key'),
} as const;

/** A dead loopback port, for the "upstream is not listening" cases. */
export const closedPort = 9;

/** Is the sandbox's HTTP/MCP fixture answering? */
export async function fixtureUp(): Promise<boolean> {
  try {
    const response = await request({
      host: sandbox.host,
      port: sandbox.httpPort,
      path: '/health',
      timeoutMs: 2_000,
    });
    return response.status === 200;
  } catch {
    return false;
  }
}

/** The sandbox SSH key Multitool is given as the connection's credential. */
export async function sshPrivateKey(): Promise<string> {
  return readFile(sandbox.sshKeyPath, 'utf8');
}

export function sshKeyExists(): boolean {
  return existsSync(sandbox.sshKeyPath);
}

/**
 * The sandbox server's current host-key fingerprint, as `sandbox:status`
 * prints it. Uses the same ssh-keyscan/ssh-keygen pair the script does;
 * `undefined` when either is missing or the server did not answer, so a
 * test can fall back to trust-on-first-use instead of failing on tooling.
 */
export async function sshHostFingerprint(): Promise<string | undefined> {
  try {
    const scan = await run(
      'ssh-keyscan',
      ['-T', '2', '-t', 'ed25519', '-p', String(sandbox.sshPort), sandbox.host],
      { timeoutMs: 10_000 },
    );
    if (!scan.stdout.trim()) return undefined;
    const listed = await run('ssh-keygen', ['-lf', '-'], {
      input: scan.stdout,
      timeoutMs: 10_000,
    });
    const fingerprint = listed.stdout.trim().split(/\s+/)[1];
    return fingerprint?.startsWith('SHA256:') ? fingerprint : undefined;
  } catch {
    return undefined;
  }
}

/** Whether a stock OpenSSH client is on PATH (the login tests need one). */
export async function hasSshClient(): Promise<boolean> {
  try {
    // `ssh -V` prints to stderr and exits 0; any exit code proves the binary.
    await run('ssh', ['-V'], { timeoutMs: 5_000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * The suite refuses to run against a sandbox that is not up rather than
 * reporting a wall of upstream failures. `scripts/sandbox-test.sh` checks
 * the same services before spawning the runner; this is the in-process
 * backstop for `tsx --test` run by hand.
 */
export async function requireFixture(): Promise<void> {
  if (await fixtureUp()) return;
  throw new Error(
    `the sandbox HTTP fixture is not answering on 127.0.0.1:${sandbox.httpPort} — ` +
      'run `pnpm run sandbox:up` first (see dev/sandbox/README.md)',
  );
}
