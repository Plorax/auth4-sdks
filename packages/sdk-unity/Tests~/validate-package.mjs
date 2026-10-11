#!/usr/bin/env node
// Structural validation for the dev.auth4.sdk UPM package. Run: node packages/sdk-unity/Tests~/validate-package.mjs
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];
const fail = (message) => errors.push(message);
const rel = (path) => relative(root, path).replaceAll("\\", "/");

// Unity ignores names ending in "~" and names starting with ".".
const hidden = (name) => name.endsWith("~") || name.startsWith(".");

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`${rel(path)} is not valid JSON: ${error.message}`);
    return null;
  }
}

const manifest = readJson(join(root, "package.json")) ?? {};
if (!/^[a-z0-9-]+(\.[a-z0-9-]+){2,}$/.test(manifest.name ?? "")) {
  fail("package.json name must be a lowercase reverse-domain name");
}
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(manifest.version ?? "")) {
  fail("package.json version must be semver");
}
if (!/^\d{4}\.\d+$/.test(manifest.unity ?? "")) fail("package.json unity must be like 2022.3");
for (const field of ["displayName", "description", "author"]) {
  if (!manifest[field]) fail(`package.json is missing ${field}`);
}
for (const file of ["README.md", "CHANGELOG.md", "LICENSE.md", "Documentation~/README.md"]) {
  if (!existsSync(join(root, file))) fail(`missing ${file}`);
}

const guids = new Map();
function checkMeta(metaPath) {
  const match = /^guid: ([0-9a-f]{32})$/m.exec(readFileSync(metaPath, "utf8"));
  if (!match) return fail(`${rel(metaPath)} has no valid guid`);
  const previous = guids.get(match[1]);
  if (previous) fail(`${rel(metaPath)} reuses the guid of ${previous}`);
  guids.set(match[1], rel(metaPath));
}

// Every imported asset needs a committed .meta so GUIDs are stable for consumers.
function walkImported(directory) {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (hidden(name)) continue;
    if (name.endsWith(".meta")) {
      if (!existsSync(path.slice(0, -5))) fail(`${rel(path)} has no matching asset`);
      checkMeta(path);
      continue;
    }
    if (!existsSync(`${path}.meta`)) fail(`${rel(path)} is missing its .meta file`);
    if (statSync(path).isDirectory()) walkImported(path);
  }
}
walkImported(root);

const samples = Array.isArray(manifest.samples) ? manifest.samples : [];
if (samples.length === 0) fail("package.json declares no samples");
for (const sample of samples) {
  const sampleRoot = join(root, sample.path ?? "");
  if (!sample.displayName || !sample.path?.startsWith("Samples~/") || !existsSync(sampleRoot)) {
    fail(`sample ${sample.displayName ?? "?"} must exist under Samples~/`);
    continue;
  }
  const files = readdirSync(sampleRoot).filter((name) => !name.endsWith(".meta"));
  if (!files.some((name) => name.endsWith(".unity"))) fail(`${sample.path} has no scene`);
  // Samples keep their .meta files so the scene's script GUID survives import.
  for (const name of files) {
    if (!existsSync(join(sampleRoot, `${name}.meta`)))
      fail(`${sample.path}/${name} is missing its .meta file`);
    else checkMeta(join(sampleRoot, `${name}.meta`));
  }
}

function collect(directory, predicate, found = []) {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (name === "Tests~" || name === "bin" || name === "obj") continue;
    if (statSync(path).isDirectory()) collect(path, predicate, found);
    else if (predicate(name)) found.push(path);
  }
  return found;
}

const asmdefs = collect(root, (name) => name.endsWith(".asmdef")).map((path) => ({
  path,
  json: readJson(path) ?? {},
}));
const names = new Set(asmdefs.map(({ json }) => json.name));
if (names.size !== asmdefs.length) fail("assembly definition names must be unique");
for (const { path, json } of asmdefs) {
  for (const reference of json.references ?? []) {
    if (!names.has(reference)) fail(`${rel(path)} references unknown assembly ${reference}`);
  }
}
const runtime = asmdefs.find(({ json }) => json.name === "Auth4.Runtime");
if (runtime?.json.noEngineReferences !== true) {
  fail("Auth4.Runtime must set noEngineReferences so the client stays portable");
}

for (const path of collect(root, (name) => name.endsWith(".cs"))) {
  if (/\bPlayerPrefs\s*\./.test(readFileSync(path, "utf8"))) {
    fail(`${rel(path)} uses PlayerPrefs; tokens may persist only through ISecureStorageAdapter`);
  }
}

if (errors.length > 0) {
  for (const error of errors) console.error(`✗ ${error}`);
  process.exit(1);
}
console.log(
  `✓ ${manifest.name}@${manifest.version}: ${guids.size} meta files, ${asmdefs.length} assemblies`,
);
