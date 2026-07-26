// Running child processes: the `mfa` CLI, `ssh`, `ssh-keyscan`.

import { spawn, type SpawnOptions } from 'node:child_process';

export interface RunResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

export interface RunOptions {
  input?: string;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  timeoutMs?: number;
}

/** Run a command to completion. Never throws on a nonzero exit — the exit
 * code is part of what the tests assert. */
export async function run(
  command: string,
  args: string[],
  options: RunOptions = {},
): Promise<RunResult> {
  const spawnOptions: SpawnOptions = {
    env: options.env ?? process.env,
    cwd: options.cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
  };
  return new Promise<RunResult>((resolve, reject) => {
    const child = spawn(command, args, spawnOptions);
    let stdout = '';
    let stderr = '';
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr?.on('data', (chunk: string) => {
      stderr += chunk;
    });
    const timer =
      options.timeoutMs === undefined
        ? undefined
        : setTimeout(() => child.kill('SIGKILL'), options.timeoutMs);
    child.on('error', (error) => {
      if (timer) clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      resolve({ code, signal, stdout, stderr });
    });
    if (options.input !== undefined) child.stdin?.write(options.input);
    child.stdin?.end();
  });
}

/** Whether a command exists and answers a trivial invocation. */
export async function available(command: string, args: string[] = ['--version']): Promise<boolean> {
  try {
    await run(command, args, { timeoutMs: 5_000 });
    return true;
  } catch {
    return false;
  }
}
