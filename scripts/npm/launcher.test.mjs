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
  "multitool",
  "bin",
  "multitool.js"
);
function runLauncher(useLegacyOverride = false) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "multitool-launcher-"));
  const stub = path.join(dir, "multitool-stub");
  const capture = path.join(dir, "capture.json");
  writeFileSync(
    stub,
    `#!/bin/sh
printf '{"args":"%s"}' "$*" > "$MULTITOOL_CAPTURE"
`,
  );
  chmodSync(stub, 0o755);

  const env = {
    ...process.env,
    MULTITOOL_CAPTURE: capture,
  };
  env[useLegacyOverride ? "AGENTMFA_BIN" : "MULTITOOL_BIN"] = stub;

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

test("launcher keeps the legacy AGENTMFA_BIN override working", () => {
  const captured = runLauncher(true);
  assert.equal(captured.args, "serve --root /tmp/aka-test");
});
