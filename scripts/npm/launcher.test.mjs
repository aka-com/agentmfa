import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  ".."
);
const launcher = path.join(
  repoRoot,
  "npm",
  "agentmfa",
  "bin",
  "agentmfa.js"
);
function runLauncher() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "agentmfa-launcher-"));
  const stub = path.join(dir, "mfa-stub");
  const capture = path.join(dir, "capture.json");
  writeFileSync(
    stub,
    `#!/bin/sh
printf '{"args":"%s"}' "$*" > "$AGENTMFA_CAPTURE"
`,
  );
  chmodSync(stub, 0o755);

  const env = {
    ...process.env,
    AGENTMFA_BIN: stub,
    AGENTMFA_CAPTURE: capture,
  };

  const result = spawnSync(
    process.execPath,
    [launcher, "serve", "--root", "/tmp/aka-test"],
    { env, encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(readFileSync(capture, "utf8"));
}

test("launcher hands arguments to the platform binary", () => {
  const captured = runLauncher();
  assert.equal(captured.args, "serve --root /tmp/aka-test");
});
