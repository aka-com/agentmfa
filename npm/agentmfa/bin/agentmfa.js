#!/usr/bin/env node
"use strict";

// Launcher for the `agentmfa` npm package. The real CLI is the prebuilt Rust
// `mfa` binary shipped in the platform-specific package that npm selected via
// optionalDependencies (agentmfa-<os>-<arch>); this script only resolves it
// and hands over argv. There is deliberately no postinstall step and no
// network access here: a credential broker's install should be inert.

const { spawnSync } = require("child_process");
const path = require("path");

const PLATFORM_PACKAGES = {
  "darwin arm64": "agentmfa-darwin-arm64",
  "darwin x64": "agentmfa-darwin-x64",
  "linux arm64": "agentmfa-linux-arm64",
  "linux x64": "agentmfa-linux-x64",
};

function fail(message) {
  console.error(`agentmfa: ${message}`);
  process.exit(1);
}

function resolveBinary() {
  // Escape hatch for development and unusual layouts: point AGENTMFA_BIN at
  // any `mfa` binary (e.g. target/release/mfa) and the launcher uses it.
  if (process.env.AGENTMFA_BIN) return process.env.AGENTMFA_BIN;

  const key = `${process.platform} ${process.arch}`;
  const pkg = PLATFORM_PACKAGES[key];
  if (!pkg) {
    fail(
      `unsupported platform ${key}; prebuilt binaries exist for ` +
        `${Object.keys(PLATFORM_PACKAGES).join(", ")}. The broker is ` +
        "Unix-only (Unix domain sockets), so Windows is not supported."
    );
  }

  let binPath;
  try {
    binPath = require.resolve(`${pkg}/bin/mfa`);
  } catch {
    fail(
      `the ${pkg} package holding the binary for ${key} is not installed.\n` +
        "It is an optionalDependency of agentmfa: reinstall without " +
        "--no-optional/--omit=optional, and make sure your package manager " +
        "installs platform-specific optional dependencies."
    );
  }

  // npm can leave a stale platform package behind across updates (hoisting,
  // lockfile edits); running a binary from another release would be
  // confusing at best for a security tool, so refuse the mismatch.
  const want = require("../package.json").version;
  const got = require(`${pkg}/package.json`).version;
  if (want !== got) {
    fail(
      `version mismatch: agentmfa@${want} resolved ${pkg}@${got}; ` +
        "reinstall agentmfa to repair the pairing."
    );
  }
  return binPath;
}

// The npm package carries the self-contained JavaScript MCP host, while the
// Node process already running this launcher supplies its runtime. Point the
// Rust supervisor at both exact paths so `mfa serve` works from any cwd and
// does not accidentally select a different `node` from PATH. Explicit
// overrides remain useful for development and diagnostics.
const childEnv = { ...process.env };
if (!childEnv.AKA_SIDECAR_NODE) {
  childEnv.AKA_SIDECAR_NODE = process.execPath;
}
if (!childEnv.AKA_SIDECAR_SCRIPT) {
  childEnv.AKA_SIDECAR_SCRIPT = path.join(
    __dirname,
    "..",
    "sidecar",
    "main.mjs"
  );
}

const result = spawnSync(resolveBinary(), process.argv.slice(2), {
  stdio: "inherit",
  env: childEnv,
});
if (result.error) {
  fail(result.error.message);
}
if (result.signal) {
  // Re-raise so callers observe the same signal-death the CLI had.
  process.kill(process.pid, result.signal);
}
process.exit(result.status === null ? 1 : result.status);
