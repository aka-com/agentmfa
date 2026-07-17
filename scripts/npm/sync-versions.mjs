#!/usr/bin/env node
// Keep the npm distribution's package versions in lock-step with the Cargo
// workspace version — the single source of truth the `aka` binary reports
// via `--version`. Covers the five package.json files under npm/ and the
// main package's exact-pinned optionalDependencies on the platform packages.
//
//   node scripts/npm/sync-versions.mjs          rewrite any file that drifted
//   node scripts/npm/sync-versions.mjs --check  exit 1 on drift, change nothing

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  ".."
);

const MAIN_PACKAGE = "agentmfa";
const PLATFORM_PACKAGES = [
  "agentmfa-darwin-arm64",
  "agentmfa-darwin-x64",
  "agentmfa-linux-arm64",
  "agentmfa-linux-x64",
];

function workspaceVersion() {
  const cargo = readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
  const section = cargo.match(/\[workspace\.package\]([^[]*)/);
  const version = section?.[1].match(/^version\s*=\s*"([^"]+)"/m);
  if (!version) {
    throw new Error("no [workspace.package] version found in Cargo.toml");
  }
  return version[1];
}

const checkOnly = process.argv.includes("--check");
const version = workspaceVersion();
const drifted = [];

for (const name of [MAIN_PACKAGE, ...PLATFORM_PACKAGES]) {
  const file = path.join(repoRoot, "npm", name, "package.json");
  const pkg = JSON.parse(readFileSync(file, "utf8"));
  const before = JSON.stringify(pkg);

  pkg.version = version;
  if (name === MAIN_PACKAGE) {
    for (const platform of PLATFORM_PACKAGES) {
      pkg.optionalDependencies[platform] = version;
    }
  }

  if (JSON.stringify(pkg) !== before) {
    drifted.push(path.relative(repoRoot, file));
    if (!checkOnly) {
      writeFileSync(file, `${JSON.stringify(pkg, null, 2)}\n`);
    }
  }
}

if (drifted.length === 0) {
  console.log(`npm packages in sync with Cargo workspace version ${version}`);
} else if (checkOnly) {
  console.error(
    `npm packages out of sync with Cargo workspace version ${version}:\n` +
      drifted.map((file) => `  ${file}`).join("\n") +
      "\nrun `node scripts/npm/sync-versions.mjs` to fix."
  );
  process.exit(1);
} else {
  console.log(
    `stamped version ${version} into:\n` +
      drifted.map((file) => `  ${file}`).join("\n")
  );
}
