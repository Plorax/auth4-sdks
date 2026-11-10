#!/usr/bin/env node
// AUTH4D-151: builds, packs and checks the publishable SDKs exactly as they would reach npm or a
// Unity registry, without publishing anything.
//
//   node scripts/sdk/check.mjs                         check every SDK (CI)
//   node scripts/sdk/check.mjs --release <tag>         also gate one release tag (publish workflow)
//
// Release tags: sdk-browser/v<version>, sdk-server/v<version>, sdk-nextjs/v<version>,
// dev.auth4.sdk/v<version> (Unity, the format OpenUPM expects with gitTagPrefix "dev.auth4.sdk/"),
// and the five source SDKs below (AUTH4D-479).
// A release needs the tag version to match package.json and a final licence: "UNLICENSED" or the
// placeholder Unity LICENSE.md fails.
// AUTH4D-478: the Unreal, Godot, .NET, Go and Python SDKs have no package registry pipeline here; their
// check only reads the directory, the MIT LICENSE and the version metadata, without engine or SDK
// builds. AUTH4D-479: they are released as GitHub Release archives (scripts/sdk/archive.mjs) on tags
// sdk-unreal/v<Auth4.uplugin VersionName>, sdk-godot/v<plugin.cfg version>, sdk-dotnet/v<csproj
// Version>, sdk-python/v<pyproject version> and packages/sdk-go/v<x.y.z> (the Go module tag form; Go
// has no version file, so the tag is the version).
// Tarballs and sdk-check.json go to .generated/auth4d-151/. With GITHUB_OUTPUT set, a release run
// also writes kind, name, version and tarball for the workflow.
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { privateFileProblems } from "./private-files.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const outDir = join(repoRoot, ".generated/auth4d-151");

const SDKS = [
  {
    kind: "npm",
    dir: "packages/sdk-browser",
    tagPrefix: "sdk-browser/v",
    exports: { ".": ["Auth4BrowserClient", "Auth4BrowserError"] },
  },
  {
    kind: "npm",
    dir: "packages/sdk-server",
    tagPrefix: "sdk-server/v",
    exports: { ".": ["Auth4ServerClient", "TokenVerificationError", "authenticateRequest"] },
  },
  // AUTH4D-238: two entry points; next and react are peer dependencies the application installs.
  {
    kind: "npm",
    dir: "packages/sdk-nextjs",
    tagPrefix: "sdk-nextjs/v",
    exports: {
      ".": ["Auth4Provider", "useUser", "getAccessToken", "AccessTokenRequestError"],
      "./server": ["Auth4Client", "AccessTokenError", "ConfigurationError"],
    },
  },
  { kind: "unity", dir: "packages/sdk-unity", tagPrefix: "dev.auth4.sdk/v" },
  // AUTH4D-478: version and licence metadata per ecosystem. AUTH4D-479: and the release tag.
  {
    kind: "source",
    dir: "packages/sdk-unreal",
    tagPrefix: "sdk-unreal/v",
    name: "Auth4 (Unreal plugin)",
    license: "LICENSE.md",
    versions: [["Auth4.uplugin", /"VersionName":\s*"([^"]+)"/]],
  },
  {
    kind: "source",
    dir: "packages/sdk-godot",
    tagPrefix: "sdk-godot/v",
    name: "auth4 (Godot addon)",
    versions: [["addons/auth4/plugin.cfg", /^version="([^"]+)"/m]],
    licenses: [["addons/auth4/plugin.cfg", /^license="MIT"$/m]],
  },
  {
    kind: "source",
    dir: "packages/sdk-dotnet",
    tagPrefix: "sdk-dotnet/v",
    name: "Auth4.Server (.NET)",
    versions: [
      ["src/Auth4.Server/Auth4.Server.csproj", /<Version>([^<]+)<\/Version>/],
      ["src/Auth4.Server.AspNetCore/Auth4.Server.AspNetCore.csproj", /<Version>([^<]+)<\/Version>/],
    ],
    licenses: [
      ["src/Auth4.Server/Auth4.Server.csproj", /<PackageLicenseExpression>MIT</],
      [
        "src/Auth4.Server.AspNetCore/Auth4.Server.AspNetCore.csproj",
        /<PackageLicenseExpression>MIT</,
      ],
    ],
  },
  {
    kind: "source",
    dir: "packages/sdk-go",
    tagPrefix: "packages/sdk-go/v",
    // No version file: the tag carries x.y.z, which must be a plain semantic version.
    tagOnlyVersion: true,
    name: "auth4 (Go module)",
    // Go versions are tags; go.mod must name this repository's path or the mirror's.
    versions: [
      ["go.mod", /^module github\.com\/Plorax\/(?:auth4\.dev|auth4-sdks)\/packages\/sdk-go\r?\n/],
    ],
  },
  {
    kind: "source",
    dir: "packages/sdk-python",
    tagPrefix: "sdk-python/v",
    name: "auth4 (Python)",
    versions: [["pyproject.toml", /^version = "([^"]+)"/m]],
    licenses: [["pyproject.toml", /^license = \{ text = "MIT" \}/m]],
  },
];
const ALLOWED_NPM_FILES =
  /^package\/(package\.json|README\.md|LICENSE(\.md|\.txt)?|dist\/.+\.(js|d\.ts))$/;
const UNITY_LICENSE_PLACEHOLDER = "not yet released under a public license";

const args = process.argv.slice(2);
const tagIndex = args.indexOf("--release");
const tag = tagIndex >= 0 ? args[tagIndex + 1] : undefined;
if (tagIndex >= 0 && !tag) usage("--release needs a tag");
const release = tag
  ? SDKS.find((sdk) => sdk.tagPrefix && tag.startsWith(sdk.tagPrefix))
  : undefined;
if (tag && !release) usage(`unknown release tag ${tag}`);

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

const report = { checkedAt: new Date().toISOString(), tag: tag ?? null, packages: [] };
const errors = [];
for (const sdk of release ? [release] : SDKS) {
  const entry = await checkSdk(sdk);
  // AUTH4D-479: the tag that releases this version; Go has no version file, so the owner picks it.
  entry.expectedTag = `${sdk.tagPrefix}${sdk.tagOnlyVersion && !tag ? "<x.y.z>" : entry.version}`;
  report.packages.push(entry);
  errors.push(...entry.errors.map((error) => `${entry.name}: ${error}`));
}
writeFileSync(join(outDir, "sdk-check.json"), `${JSON.stringify(report, null, 2)}\n`);

if (errors.length > 0) {
  for (const error of errors) console.error(`✗ ${error}`);
  process.exit(1);
}
for (const entry of report.packages) {
  const where = entry.tarball ? ` in ${entry.tarball}` : "";
  console.log(
    `✓ ${entry.name}@${entry.version}: ${entry.files.length} files${where}; tag ${entry.expectedTag}`,
  );
}
if (release && process.env.GITHUB_OUTPUT) {
  const [entry] = report.packages;
  const lines = [
    `kind=${release.kind}`,
    `name=${entry.name}`,
    `version=${entry.version}`,
    `tarball=${entry.tarball ?? ""}`,
  ];
  appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join("\n")}\n`);
}

async function checkSdk(sdk) {
  const packageDir = join(repoRoot, sdk.dir);
  if (sdk.kind === "source") return checkSourceSdk(sdk, packageDir);
  const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
  const errors = [];
  const fail = (message) => errors.push(message);

  if (sdk.kind === "npm") {
    run("pnpm", ["--filter", manifest.name, "build"]);
  } else {
    run("node", ["packages/sdk-unity/Tests~/validate-package.mjs"]);
  }
  const packed = JSON.parse(
    run("pnpm", ["--filter", manifest.name, "pack", "--json", "--pack-destination", outDir]),
  );
  const tarball = join(
    outDir,
    `${manifest.name.replace("@", "").replace("/", "-")}-${manifest.version}.tgz`,
  );
  if (resolve(packed.filename ?? tarball) !== tarball)
    fail(`unexpected tarball ${packed.filename}`);
  const files = readTarball(readFileSync(tarball));
  const packedManifest = JSON.parse(files.get("package/package.json") ?? "{}");

  if (sdk.kind === "npm") {
    for (const path of files.keys()) {
      if (!ALLOWED_NPM_FILES.test(path)) fail(`unexpected file in tarball: ${path}`);
    }
    // AUTH4D-240: inlined private workspace code is limited to the public SDK contracts module.
    for (const problem of privateFileProblems(sdk.dir, files.keys())) fail(problem);
    if (packedManifest.private) fail("packed package.json is private");
    if (JSON.stringify(packedManifest).includes("workspace:")) {
      fail("packed package.json still has a workspace: specifier");
    }
    for (const name of Object.keys(packedManifest.dependencies ?? {})) {
      if (name.startsWith("@auth4/")) fail(`depends on unpublished ${name}`);
    }
    if (!packedManifest.repository?.url?.includes("github.com/"))
      fail("repository.url must be set");
    // AUTH4D-238: every subpath the SDK publishes, so a broken secondary entry fails too.
    for (const [subpath, names] of Object.entries(sdk.exports)) {
      const target = packedManifest.exports?.[subpath];
      for (const condition of ["types", "default"]) {
        const path = target?.[condition];
        if (typeof path !== "string" || !files.has(`package/${path.replace(/^\.\//, "")}`)) {
          fail(`exports["${subpath}"].${condition} is missing from the tarball`);
        }
      }
      // Type-check the declarations as a strict Node ESM consumer would, then load the built entry
      // with the package's real dependencies and check its public exports. Errors inside the
      // dependencies' own declarations (next has some; Next.js apps set skipLibCheck) are not ours.
      if (typeof target?.types === "string") {
        const types = relative(repoRoot, join(packageDir, target.types)).replaceAll("\\", "/");
        const { status, output } = run(
          "pnpm",
          [
            "exec",
            "tsc",
            "--ignoreConfig",
            "--noEmit",
            "--strict",
            "--types",
            "node",
            "--lib",
            "es2022,dom",
            "--module",
            "nodenext",
            "--moduleResolution",
            "nodenext",
            types,
          ],
          { allowFailure: true },
        );
        const diagnostics = output.split(/\r?\n/).filter((line) => /error TS\d+/.test(line));
        if (status !== 0 && diagnostics.length === 0) fail(`tsc failed: ${output.trim()}`);
        const own = diagnostics.filter(
          (line) => !/(^|[\\/])node_modules[\\/]/.test(line.split("(")[0]),
        );
        for (const line of own) fail(`declarations: ${line}`);
      }
      if (typeof target?.default === "string") {
        const module = await import(pathToFileURL(join(packageDir, target.default)).href);
        for (const name of names) {
          if (!(name in module)) fail(`built entry "${subpath}" does not export ${name}`);
        }
      }
    }
  } else {
    for (const path of files.keys()) {
      if (/\/(bin|obj|TestResults)\//.test(path)) fail(`build output in tarball: ${path}`);
    }
  }

  if (tag) {
    const version = tag.slice(sdk.tagPrefix.length);
    if (version !== manifest.version) {
      fail(`tag version ${version} does not match package.json ${manifest.version}`);
    }
    if (!manifest.license || manifest.license === "UNLICENSED") {
      fail(
        "package.json license is not final (owner decision, see docs/operations/sdk-publishing.md)",
      );
    }
    const licenseFile = [...files.keys()].find((path) =>
      /^package\/LICENSE(\.md|\.txt)?$/.test(path),
    );
    if (!licenseFile) fail("the package has no LICENSE file");
    else if (files.get(licenseFile).includes(UNITY_LICENSE_PLACEHOLDER)) {
      fail(`${licenseFile.slice("package/".length)} is still the placeholder`);
    }
  }

  return {
    name: manifest.name,
    version: manifest.version,
    kind: sdk.kind,
    tarball: relative(repoRoot, tarball).replaceAll("\\", "/"),
    files: [...files.keys()].map((path) => path.slice("package/".length)).sort(),
    dependencies: packedManifest.dependencies ?? {},
    errors,
  };
}

// AUTH4D-478: the directory, an MIT LICENSE and readable version metadata, nothing built.
function checkSourceSdk(sdk, packageDir) {
  const errors = [];
  // The files the check read; build output and virtualenvs in the directory are not listed.
  const files = new Set();
  const read = (path) => {
    const file = join(packageDir, path);
    files.add(path);
    if (existsSync(file)) return readFileSync(file, "utf8");
    errors.push(`${path} is missing`);
    return "";
  };
  if (!existsSync(packageDir)) errors.push(`${sdk.dir} is missing`);
  const license = read(sdk.license ?? "LICENSE");
  if (license && !license.startsWith("MIT License")) errors.push("the LICENSE is not MIT");
  for (const [path, pattern] of sdk.licenses ?? []) {
    if (!pattern.test(read(path))) errors.push(`${path} does not declare the MIT licence`);
  }
  const versions = new Set();
  for (const [path, pattern] of sdk.versions) {
    const match = pattern.exec(read(path));
    if (!match) errors.push(`${path} has no version metadata`);
    else if (match[1]) versions.add(match[1]);
  }
  if (versions.size > 1) errors.push(`versions disagree: ${[...versions].join(", ")}`);
  let version = [...versions][0] ?? "untagged";
  if (tag) {
    const tagVersion = tag.slice(sdk.tagPrefix.length);
    if (sdk.tagOnlyVersion) {
      if (/^\d+\.\d+\.\d+$/.test(tagVersion)) version = tagVersion;
      else errors.push(`tag version ${tagVersion} is not x.y.z`);
    } else if (tagVersion !== version) {
      errors.push(`tag version ${tagVersion} does not match the metadata version ${version}`);
    }
  }
  return {
    name: sdk.name,
    version,
    kind: sdk.kind,
    tarball: null,
    files: [...files].sort(),
    dependencies: {},
    errors,
  };
}

function run(command, commandArgs, { allowFailure = false } = {}) {
  // pnpm is a .cmd shim on Windows, which needs a shell. Arguments here are fixed or package names.
  const result = spawnSync(command, commandArgs, {
    cwd: repoRoot,
    encoding: "utf8",
    shell: process.platform === "win32",
  });
  // tsc reports diagnostics on stdout; the caller decides which of them count.
  if (allowFailure) return { status: result.status, output: `${result.stdout}${result.stderr}` };
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`${command} ${commandArgs.join(" ")} failed`);
  }
  return result.stdout;
}

// Minimal ustar reader: regular files only, which is all npm and pnpm tarballs contain.
function readTarball(gzipped) {
  const data = gunzipSync(gzipped);
  const files = new Map();
  const text = (start, length) =>
    data
      .subarray(start, start + length)
      .toString("utf8")
      .replace(/\0.*$/s, "");
  for (let offset = 0; offset + 512 <= data.length;) {
    const name = text(offset, 100);
    if (!name) break;
    const prefix = text(offset + 345, 155);
    const size = Number.parseInt(text(offset + 124, 12).trim() || "0", 8);
    const type = text(offset + 156, 1);
    const body = offset + 512;
    if (type === "0" || type === "") {
      files.set(
        prefix ? `${prefix}/${name}` : name,
        data.subarray(body, body + size).toString("utf8"),
      );
    }
    offset = body + Math.ceil(size / 512) * 512;
  }
  return files;
}

function usage(message) {
  console.error(`${message}\nusage: node scripts/sdk/check.mjs [--release <tag>]`);
  process.exit(2);
}
