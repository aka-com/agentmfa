#!/usr/bin/env node
"use strict";

// Launcher for the `multitool` npm package. The real CLI is the prebuilt Rust
// `multitool` binary shipped in the platform-specific package that npm selected via
// optionalDependencies (multitool-<os>-<arch>); this script only resolves it
// and hands over argv. There is deliberately no postinstall step and no
// network access here: a credential broker's install should be inert.

const { spawnSync } = require("child_process");

const PLATFORM_PACKAGES = {
  "darwin arm64": "@aka-com/multitool-darwin-arm64",
  "darwin x64": "@aka-com/multitool-darwin-x64",
  "linux arm64": "@aka-com/multitool-linux-arm64",
  "linux x64": "@aka-com/multitool-linux-x64",
};

function fail(message) {
  console.error(`multitool: ${message}`);
  process.exit(1);
}

function resolveBinary() {
  // Escape hatch for development and unusual layouts: point MULTITOOL_BIN at
  // any `multitool` binary (e.g. target/release/multitool) and the launcher uses it.
  if (process.env.MULTITOOL_BIN) return process.env.MULTITOOL_BIN;
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
    binPath = require.resolve(`${pkg}/bin/multitool`);
  } catch {
    fail(
      `the ${pkg} package holding the binary for ${key} is not installed.\n` +
        "It is an optionalDependency of @aka-com/multitool: reinstall without " +
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
      `version mismatch: @aka-com/multitool@${want} resolved ${pkg}@${got}; ` +
        "reinstall @aka-com/multitool to repair the pairing."
    );
  }
  return binPath;
}

const result = spawnSync(resolveBinary(), process.argv.slice(2), {
  stdio: "inherit",
});
if (result.error) {
  fail(result.error.message);
}
if (result.signal) {
  // Re-raise so callers observe the same signal-death the CLI had.
  process.kill(process.pid, result.signal);
}
process.exit(result.status === null ? 1 : result.status);
