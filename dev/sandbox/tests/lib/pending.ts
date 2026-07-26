// Placeholders for behaviour AKA does not implement yet.
//
// The matrix in this suite is written from the outside in: it names the
// things an operator would expect a broker sitting between an agent and a
// database, a shell, or an API to be able to do. Some of those AKA does not
// do today — per-statement Postgres approval, per-command SSH approval,
// approval levels that differ for reads and writes.
//
// Those cases are kept in the matrix as passing stubs rather than being
// left out, so the gap is visible in the test output and so implementing
// the feature means filling in a test that already exists (and already sits
// next to the cases that do pass). A stub prints a `NOT IMPLEMENTED` note
// through the runner's diagnostic channel, and passes: it asserts nothing,
// because there is nothing yet to assert.

import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';

/**
 * Record an unimplemented behaviour and pass.
 *
 * @param t the test context, for the diagnostic line
 * @param behaviour what a user would expect to be able to do
 * @param today what the broker does instead, and where that is decided
 */
export function pending(t: TestContext, behaviour: string, today: string): void {
  t.diagnostic(`NOT IMPLEMENTED — ${behaviour}`);
  t.diagnostic(`  today: ${today}`);
  assert.ok(true, behaviour);
}
