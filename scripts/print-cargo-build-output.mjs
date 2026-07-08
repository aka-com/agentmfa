#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

const buildArgs = process.argv.slice(2);
const cargoArgs = buildArgs.includes("--")
  ? buildArgs.slice(0, buildArgs.indexOf("--"))
  : buildArgs;

function flagValue(names) {
  for (let index = 0; index < cargoArgs.length; index += 1) {
    const arg = cargoArgs[index];
    for (const name of names) {
      if (arg === name) {
        return cargoArgs[index + 1];
      }
      if (arg.startsWith(`${name}=`)) {
        return arg.slice(name.length + 1);
      }
    }
  }
  return undefined;
}

function flagValues(names) {
  const values = [];
  for (let index = 0; index < cargoArgs.length; index += 1) {
    const arg = cargoArgs[index];
    for (const name of names) {
      if (arg === name && cargoArgs[index + 1]) {
        values.push(cargoArgs[index + 1]);
      } else if (arg.startsWith(`${name}=`)) {
        values.push(arg.slice(name.length + 1));
      }
    }
  }
  return values;
}

function hasFlag(names) {
  return cargoArgs.some((arg) => names.includes(arg));
}

function matchesPackage(pkg, spec) {
  return pkg.name === spec || pkg.id === spec || pkg.id.includes(`#${spec}`);
}

function executableSuffix(targetTriple) {
  const buildsWindowsTarget = targetTriple?.includes("windows");
  return buildsWindowsTarget || (!targetTriple && process.platform === "win32")
    ? ".exe"
    : "";
}

const manifestPath = flagValue(["--manifest-path"]);
const metadataArgs = ["metadata", "--no-deps", "--format-version", "1"];
if (manifestPath) {
  metadataArgs.push("--manifest-path", manifestPath);
}
for (const flag of ["--locked", "--offline", "--frozen"]) {
  if (hasFlag([flag])) {
    metadataArgs.push(flag);
  }
}

const metadataResult = spawnSync("cargo", metadataArgs, {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
});

if (metadataResult.status !== 0) {
  console.error("Could not resolve Cargo target executable path.");
  if (metadataResult.stderr) {
    console.error(metadataResult.stderr.trim());
  }
  process.exit(0);
}

let metadata;
try {
  metadata = JSON.parse(metadataResult.stdout);
} catch {
  console.error("Could not parse Cargo metadata to resolve target executable.");
  process.exit(0);
}
const packageSpecs = flagValues(["--package", "-p"]);
const excludeSpecs = flagValues(["--exclude"]);
const binSpecs = flagValues(["--bin"]);

let selectedPackages;
if (packageSpecs.length > 0) {
  selectedPackages = metadata.packages.filter((pkg) =>
    packageSpecs.some((spec) => matchesPackage(pkg, spec)),
  );
} else {
  const selectedIds = hasFlag(["--workspace", "--all"])
    ? metadata.workspace_members
    : metadata.workspace_default_members;
  selectedPackages = metadata.packages.filter((pkg) =>
    selectedIds.includes(pkg.id),
  );
}

if (excludeSpecs.length > 0) {
  selectedPackages = selectedPackages.filter(
    (pkg) => !excludeSpecs.some((spec) => matchesPackage(pkg, spec)),
  );
}

const wantsOnlyNonBins =
  hasFlag(["--lib"]) ||
  hasFlag(["--tests"]) ||
  hasFlag(["--benches"]) ||
  hasFlag(["--examples"]);
const shouldPrintBins =
  binSpecs.length > 0 || hasFlag(["--bins"]) || !wantsOnlyNonBins;

if (!shouldPrintBins) {
  process.exit(0);
}

const profileName = flagValue(["--profile"]);
const profileDir =
  profileName === "dev"
    ? "debug"
    : profileName || (hasFlag(["--release"]) ? "release" : "debug");
const targetTriple = flagValue(["--target"]);
const targetDirArg = flagValue(["--target-dir"]);
let targetDir = metadata.target_directory;
if (process.env.CARGO_TARGET_DIR) {
  targetDir = path.resolve(process.env.CARGO_TARGET_DIR);
}
if (targetDirArg) {
  targetDir = path.resolve(targetDirArg);
}
const executableDir = targetTriple
  ? path.join(targetDir, targetTriple, profileDir)
  : path.join(targetDir, profileDir);
const suffix = executableSuffix(targetTriple);

const executablePaths = selectedPackages.flatMap((pkg) =>
  pkg.targets
    .filter((target) => target.kind.includes("bin"))
    .filter((target) => binSpecs.length === 0 || binSpecs.includes(target.name))
    .map((target) => path.join(executableDir, `${target.name}${suffix}`)),
);

if (executablePaths.length === 0) {
  process.exit(0);
}

const heading =
  executablePaths.length === 1 ? "Target executable:" : "Target executables:";
console.log(heading);
for (const executablePath of executablePaths) {
  const missing = existsSync(executablePath) ? "" : " (not found on disk)";
  console.log(`  ${executablePath}${missing}`);
}
