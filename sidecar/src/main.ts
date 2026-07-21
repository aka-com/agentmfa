// The Multitool sidecar entry point.
//
// A supervised Node process that will host the executor engine (MCP serving
// plus the Multitool tool plugin). Phase 1 establishes only the lifecycle
// the Rust supervisor in `aka-core::sidecar` expects:
//
//   * bind loopback on an ephemeral port, announced on stdout as a single
//     `{"event":"ready","port":N}` line — no fixed port to collide on;
//   * JSON log lines on stderr, forwarded into the broker's tracing output;
//   * SIGTERM closes the listener and exits 0.

import { log } from './log';
import { createSidecarServer, type SidecarEnv } from './server';

function readEnv(): SidecarEnv {
  const token = process.env.AKA_SIDECAR_TOKEN;
  const brokerSocket = process.env.AKA_BROKER_SOCKET;
  if (!token) throw new Error('AKA_SIDECAR_TOKEN is required');
  if (!brokerSocket) throw new Error('AKA_BROKER_SOCKET is required');
  return { token, brokerSocket };
}

function main(): void {
  const env = readEnv();
  const server = createSidecarServer(env);

  server.on('error', (error) => {
    log('error', 'listener failed', { error: String(error) });
    process.exit(1);
  });

  server.listen(0, '127.0.0.1', () => {
    const address = server.address();
    if (address === null || typeof address === 'string') {
      log('error', 'listener bound to an unexpected address');
      process.exit(1);
      return;
    }
    process.stdout.write(`${JSON.stringify({ event: 'ready', port: address.port })}\n`);
    log('info', 'sidecar ready', { port: address.port, broker: env.brokerSocket });
  });

  const shutdown = (signal: string): void => {
    log('info', 'shutting down', { signal });
    server.close(() => process.exit(0));
    // An idle keep-alive connection would otherwise hold the process open.
    server.closeAllConnections();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

try {
  main();
} catch (error) {
  log('error', 'failed to start', { error: String(error) });
  process.exit(1);
}
