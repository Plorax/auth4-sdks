#!/usr/bin/env node
// AUTH4D-479: builds the GitHub Release archive for an SDK release tag from the tagged commit.
//
//   node scripts/sdk/archive.mjs --tag <tag> --out <dir> [--unity-tarball <file>]
//
// Writes the archive and release-notes.md (the version's CHANGELOG section, if the package has one)
// to <dir>, and prints the archive path. Archives come from `git archive` of the checked-out commit,
// so they hold only tracked files, carry the commit time and are byte-identical on every run. The
// file list is checked against a per-SDK allowlist before anything is written.
//
//   sdk-unreal/v*      Auth4/ with Auth4.uplugin, Source, Config, LICENSE.md, README.md (no Tests)
//   sdk-godot/v*       addons/auth4 only, to unzip into a project
//   sdk-dotnet/v*      source zip of packages/sdk-dotnet
//   sdk-python/v*      source zip of packages/sdk-python
//   packages/sdk-go/v* source zip of packages/sdk-go
//   dev.auth4.sdk/v*   the UPM tarball the gate packed (npm pack of packages/sdk-unity)
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

// Nothing below a build, dependency or secret directory ever ships.
const NEVER = /(^|\/)(bin|obj|node_modules|\.venv|__pycache__|TestResults|\.git|\.env[^/]*)(\/|$)/;

// `exclude` names directories left out wherever they occur. `root` is the directory the archive is cut from, `paths` the entries inside it (empty: all),
// `prefix` the folder every entry gets in the zip, `allow` the pattern each listed file must match.
export const ARCHIVES = [
  {
    prefix: "sdk-unreal/v",
    zip: (v) => `auth4-unreal-${v}.zip`,
    root: "packages/sdk-unreal",
    paths: ["Auth4.uplugin", "Source", "Config", "LICENSE.md", "README.md"],
    folder: () => "Auth4/",
    allow: /^(Auth4\.uplugin|LICENSE\.md|README\.md|Source\/.+|Config\/.+)$/,
    // Automation tests live inside Source/ (Private/Tests).
    exclude: "Tests",
    changelog: "packages/sdk-unreal/CHANGELOG.md",
  },
  {
    prefix: "sdk-godot/v",
    zip: (v) => `auth4-godot-${v}.zip`,
    root: "packages/sdk-godot/addons",
    paths: ["auth4"],
    folder: () => "addons/",
    allow: /^auth4\/.+$/,
  },
  {
    prefix: "sdk-dotnet/v",
    zip: (v) => `auth4-dotnet-${v}.zip`,
    root: "packages/sdk-dotnet",
    paths: [],
    folder: (v) => `auth4-dotnet-${v}/`,
    allow: /^.+$/,
  },
  {
    prefix: "sdk-python/v",
    zip: (v) => `auth4-python-${v}.zip`,
    root: "packages/sdk-python",
    paths: [],
    folder: (v) => `auth4-python-${v}/`,
    allow: /^.+$/,
    changelog: "packages/sdk-python/CHANGELOG.md",
  },
  {
    prefix: "packages/sdk-go/v",
    zip: (v) => `auth4-go-${v}.zip`,
    root: "packages/sdk-go",
    paths: [],
    folder: (v) => `auth4-go-${v}/`,
    allow: /^.+$/,
  },
];
const UNITY = { prefix: "dev.auth4.sdk/v", changelog: "packages/sdk-unity/CHANGELOG.md" };

export function git(args, input) {
  const result = spawnSync("git", args, { cwd: repoRoot, input, maxBuffer: 1 << 30 });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr?.toString().trim()}`);
  }
  return result.stdout;
}

/** The archive spec and version a release tag names, or undefined. */
export function archiveFor(tag) {
  for (const spec of [...ARCHIVES, UNITY]) {
    if (tag.startsWith(spec.prefix)) return { spec, version: tag.slice(spec.prefix.length) };
  }
  return undefined;
}

/** The files `git archive` will put in the zip for this spec at `commit`, relative to its root. */
export function listFiles(spec, commit = "HEAD") {
  const out = git(["ls-tree", "-r", "-z", "--name-only", `${commit}:${spec.root}`, ...spec.paths]);
  const skip = spec.exclude ? new RegExp(`(^|/)${spec.exclude}/`) : undefined;
  return out
    .toString("utf8")
    .split("\0")
    .filter((file) => file && !skip?.test(file))
    .sort();
}

/** Problems with a file list: files outside the allowlist or in a never-ship directory. */
export function allowlistProblems(spec, files) {
  const problems = [];
  if (files.length === 0) problems.push("the archive would be empty");
  for (const file of files) {
    if (!spec.allow.test(file)) problems.push(`${file} is not in the allowlist`);
    if (NEVER.test(file)) problems.push(`${file} is build output or a dependency directory`);
  }
  return problems;
}

/** The "## [version]" section of a changelog without its heading; "" when there is none. */
export function changelogSection(text, version) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((line) => line.startsWith(`## [${version}]`));
  if (start === -1) return "";
  let end = lines.findIndex((line, i) => i > start && line.startsWith("## "));
  if (end === -1) end = lines.length;
  return lines
    .slice(start + 1, end)
    .join("\n")
    .trim();
}

export function releaseNotes(spec, version, name) {
  const text =
    spec.changelog && existsSync(join(repoRoot, spec.changelog))
      ? readFileSync(join(repoRoot, spec.changelog), "utf8")
      : "";
  const section = changelogSection(text, version);
  return section
    ? `${section}\n`
    : `${name} ${version}. This package has no changelog entry for this version.\n`;
}

function main(argv) {
  const value = (flag) => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const tag = value("--tag");
  const out = value("--out");
  if (!tag || !out)
    fail("usage: node scripts/sdk/archive.mjs --tag <tag> --out <dir> [--unity-tarball <file>]");
  const found = archiveFor(tag);
  if (!found) fail(`${tag} is not a release tag with a GitHub Release archive`);
  const { spec, version } = found;
  mkdirSync(out, { recursive: true });

  let archive;
  if (spec === UNITY) {
    const tarball = value("--unity-tarball");
    if (!tarball || !existsSync(tarball)) fail("--unity-tarball must name the packed .tgz");
    archive = join(out, basename(tarball));
    copyFileSync(tarball, archive);
  } else {
    const files = listFiles(spec);
    const problems = allowlistProblems(spec, files);
    if (problems.length > 0) fail(problems.join("\n"));
    archive = join(out, spec.zip(version));
    // A tree (HEAD:dir) has no time of its own, so pin every entry to the commit's.
    const committed = git(["log", "-1", "--format=%cI", "HEAD"]).toString("utf8").trim();
    const excluded = spec.exclude ? [`:(exclude,glob)**/${spec.exclude}/**`] : [];
    const zip = git([
      "archive",
      "--format=zip",
      `--mtime=${committed}`,
      `--prefix=${spec.folder(version)}`,
      `HEAD:${spec.root}`,
      ...(spec.paths.length > 0 ? spec.paths : ["."]),
      ...excluded,
    ]);
    writeFileSync(archive, zip);
  }
  writeFileSync(join(out, "release-notes.md"), releaseNotes(spec, version, tag));
  console.log(archive);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
