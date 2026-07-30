#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  accessSync,
  constants,
  readFileSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  ".."
);
const npmRoot = path.join(repoRoot, "npm");

const PLATFORM_PACKAGES = {
  "agentmfa-darwin-arm64": { os: "darwin", cpu: "arm64", format: "macho" },
  "agentmfa-darwin-x64": { os: "darwin", cpu: "x64", format: "macho" },
  "agentmfa-linux-arm64": { os: "linux", cpu: "arm64", format: "elf" },
  "agentmfa-linux-x64": { os: "linux", cpu: "x64", format: "elf" },
};
const MAIN_PACKAGE = "agentmfa";
const ALL_PACKAGES = [...Object.keys(PLATFORM_PACKAGES), MAIN_PACKAGE];
const REQUIRED_NODE_ENGINE = ">=22";
const publishedName = (directory) => directory;

function fail(message) {
  throw new Error(`npm package verification failed: ${message}`);
}

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

function workspaceVersion() {
  const cargo = readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
  const section = cargo.match(/\[workspace\.package\]([^[]*)/);
  const version = section?.[1].match(/^version\s*=\s*"([^"]+)"/m);
  if (!version) fail("no [workspace.package] version found in Cargo.toml");
  return version[1];
}

function verifyManifest(directory, expectedVersion) {
  const packageDir = path.join(npmRoot, directory);
  const manifest = readJson(path.join(packageDir, "package.json"));
  const expectedName = publishedName(directory);
  if (manifest.name !== expectedName) {
    fail(`${directory} manifest declares name ${JSON.stringify(manifest.name)}`);
  }
  if (manifest.version !== expectedVersion) {
    fail(
      `${expectedName}@${manifest.version} does not match Cargo workspace version ${expectedVersion}`
    );
  }
  if (manifest.engines?.node !== REQUIRED_NODE_ENGINE) {
    fail(`${expectedName} must require Node ${REQUIRED_NODE_ENGINE}`);
  }
  if (manifest.publishConfig?.access !== "public") {
    fail(`${expectedName} must publish with public access`);
  }
  return { packageDir, manifest };
}

function binaryIdentity(binary) {
  const bytes = readFileSync(binary);
  if (bytes.length < 20) fail(`${binary} is too short to be an executable`);

  if (
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46
  ) {
    if (bytes[4] !== 2) fail(`${binary} is not a 64-bit ELF executable`);
    const littleEndian = bytes[5] === 1;
    if (!littleEndian && bytes[5] !== 2) {
      fail(`${binary} has an unknown ELF byte order`);
    }
    const machine = littleEndian
      ? bytes.readUInt16LE(18)
      : bytes.readUInt16BE(18);
    const cpu = machine === 62 ? "x64" : machine === 183 ? "arm64" : null;
    if (!cpu) fail(`${binary} has unsupported ELF machine type ${machine}`);
    return { format: "elf", cpu };
  }

  const magic = bytes.readUInt32LE(0);
  if (magic === 0xfeedfacf || magic === 0xcffaedfe) {
    const littleEndian = magic === 0xfeedfacf;
    const cpuType = littleEndian
      ? bytes.readUInt32LE(4)
      : bytes.readUInt32BE(4);
    const cpu =
      cpuType === 0x01000007
        ? "x64"
        : cpuType === 0x0100000c
          ? "arm64"
          : null;
    if (!cpu) fail(`${binary} has unsupported Mach-O CPU type ${cpuType}`);
    return { format: "macho", cpu };
  }

  fail(`${binary} is neither a supported ELF nor Mach-O executable`);
}

function verifyPlatformPackage(directory, expectedVersion) {
  const expected = PLATFORM_PACKAGES[directory];
  const { packageDir, manifest } = verifyManifest(directory, expectedVersion);
  const name = manifest.name;
  if (manifest.os?.length !== 1 || manifest.os[0] !== expected.os) {
    fail(`${name} must declare os ${expected.os}`);
  }
  if (manifest.cpu?.length !== 1 || manifest.cpu[0] !== expected.cpu) {
    fail(`${name} must declare cpu ${expected.cpu}`);
  }

  const binary = path.join(packageDir, "bin", "mfa");
  try {
    accessSync(binary, constants.R_OK | constants.X_OK);
  } catch {
    fail(`${name} is missing an executable bin/mfa; build and stage it first`);
  }
  if (!statSync(binary).isFile()) fail(`${name}/bin/mfa is not a regular file`);

  const identity = binaryIdentity(binary);
  if (identity.format !== expected.format || identity.cpu !== expected.cpu) {
    fail(
      `${name}/bin/mfa is ${identity.format}-${identity.cpu}, expected ` +
        `${expected.format}-${expected.cpu}`
    );
  }

  if (process.platform === expected.os && process.arch === expected.cpu) {
    const result = spawnSync(binary, ["--version"], { encoding: "utf8" });
    if (result.error) fail(`${name}/bin/mfa --version: ${result.error.message}`);
    if (result.status !== 0) {
      fail(`${name}/bin/mfa --version exited with status ${result.status}`);
    }
    const actual = result.stdout.trim();
    if (actual !== `mfa ${expectedVersion}`) {
      fail(
        `${name}/bin/mfa reports ${JSON.stringify(actual)}, expected ` +
          `${JSON.stringify(`mfa ${expectedVersion}`)}`
      );
    }
  }

  console.log(
    `verified ${name}@${expectedVersion} (${identity.format}-${identity.cpu})`
  );
}

function verifyMainPackage(expectedVersion) {
  const { packageDir, manifest } = verifyManifest(MAIN_PACKAGE, expectedVersion);
  const launcher = path.join(packageDir, "bin", "agentmfa.js");
  try {
    accessSync(launcher, constants.R_OK);
  } catch {
    fail("agentmfa is missing bin/agentmfa.js");
  }
  for (const directory of Object.keys(PLATFORM_PACKAGES)) {
    const name = publishedName(directory);
    if (manifest.optionalDependencies?.[name] !== expectedVersion) {
      fail(
        `agentmfa optionalDependency ${name} must be pinned to ${expectedVersion}`
      );
    }
  }
  console.log(`verified agentmfa@${expectedVersion} launcher`);
}

function packageNameFromEnvironment() {
  const manifest = process.env.npm_package_json;
  const packageDir = manifest ? path.dirname(manifest) : process.cwd();
  if (path.dirname(packageDir) !== npmRoot) {
    fail("run from an npm package directory, pass a package path, or use --all");
  }
  return path.basename(packageDir);
}

const expectedVersion = workspaceVersion();
let packageNames;
if (process.argv.includes("--all")) {
  packageNames = ALL_PACKAGES;
} else if (process.argv.length > 2) {
  packageNames = process.argv
    .slice(2)
    .map((value) => path.basename(path.resolve(value)));
} else {
  packageNames = [packageNameFromEnvironment()];
}

for (const name of packageNames) {
  if (name === MAIN_PACKAGE) {
    verifyMainPackage(expectedVersion);
  } else if (PLATFORM_PACKAGES[name]) {
    verifyPlatformPackage(name, expectedVersion);
  } else {
    fail(`unknown npm package ${name}`);
  }
}
