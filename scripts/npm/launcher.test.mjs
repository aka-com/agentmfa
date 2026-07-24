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
const packagedSidecar = path.join(
  repoRoot,
  "npm",
  "agentmfa",
  "sidecar",
  "main.mjs"
);

function runLauncher(overrides = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "agentmfa-launcher-"));
  const stub = path.join(dir, "mfa-stub");
  const capture = path.join(dir, "capture.json");
  writeFileSync(
    stub,
    `#!/bin/sh
printf '{"node":"%s","script":"%s","args":"%s"}' \
  "$AKA_SIDECAR_NODE" "$AKA_SIDECAR_SCRIPT" "$*" > "$AGENTMFA_CAPTURE"
`
  );
  chmodSync(stub, 0o755);

  const env = {
    ...process.env,
    AGENTMFA_BIN: stub,
    AGENTMFA_CAPTURE: capture,
    ...overrides,
  };
  if (!Object.hasOwn(overrides, "AKA_SIDECAR_NODE")) {
    delete env.AKA_SIDECAR_NODE;
  }
  if (!Object.hasOwn(overrides, "AKA_SIDECAR_SCRIPT")) {
    delete env.AKA_SIDECAR_SCRIPT;
  }

  const result = spawnSync(
    process.execPath,
    [launcher, "serve", "--root", "/tmp/aka-test"],
    { env, encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(readFileSync(capture, "utf8"));
}

test("launcher gives the broker its Node runtime and packaged MCP host", () => {
  const captured = runLauncher();
  assert.equal(captured.node, process.execPath);
  assert.equal(captured.script, packagedSidecar);
  assert.equal(captured.args, "serve --root /tmp/aka-test");
});

test("launcher preserves explicit sidecar overrides", () => {
  const captured = runLauncher({
    AKA_SIDECAR_NODE: "/custom/node",
    AKA_SIDECAR_SCRIPT: "/custom/main.mjs",
  });
  assert.equal(captured.node, "/custom/node");
  assert.equal(captured.script, "/custom/main.mjs");
});
