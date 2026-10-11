#!/usr/bin/env node
// AUTH4D-151: builds a publishable TypeScript SDK (run from its package directory, e.g. through
// `pnpm --filter @auth4/sdk-server build`). Emits ES2022 JavaScript and declarations into dist/ with
// the root tsconfig's strict settings. Private workspace packages the SDK imports (for example
// @auth4/contracts/sdk in the server SDK) are emitted alongside it and their imports rewritten to
// relative paths, so the published package depends only on its declared npm dependencies.
import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const packagesDir = join(repoRoot, "packages");

// AUTH4D-231: `entries` lets an SDK publish more than one entry point (for example a server one).
export function buildSdk(packageDir, entries = ["src/index.ts"]) {
  const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
  const outDir = join(packageDir, "dist");
  rmSync(outDir, { recursive: true, force: true });

  const config = ts.readConfigFile(join(repoRoot, "tsconfig.json"), ts.sys.readFile);
  const { options } = ts.parseJsonConfigFileContent(config.config, ts.sys, repoRoot);
  // Resolve workspace packages to their sources through `paths`; TypeScript never emits files it
  // reaches through node_modules. AUTH4D-240: one entry per export subpath, so an SDK that imports
  // @auth4/contracts/sdk emits only that module and its own imports, not the whole package.
  const workspaceDependencies = Object.entries(manifest.devDependencies ?? {})
    .filter(([, version]) => version.startsWith("workspace:"))
    .map(([name]) => name);
  const paths = Object.fromEntries(
    workspaceDependencies.flatMap((name) => {
      const dir = join(packagesDir, name.split("/")[1]);
      const { exports = {} } = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      return Object.entries(exports)
        .filter(([, target]) => typeof target === "string")
        .map(([subpath, target]) => [`${name}${subpath.slice(1)}`, [join(dir, target)]]);
    }),
  );
  const program = ts.createProgram(
    entries.map((entry) => join(packageDir, entry)),
    {
      ...options,
      noEmit: false,
      declaration: true,
      rewriteRelativeImportExtensions: true,
      // Published declarations must not depend on Workers or Node ambient types.
      types: [],
      lib: ["lib.es2022.d.ts", "lib.dom.d.ts", "lib.dom.iterable.d.ts"],
      paths,
      rootDir: packagesDir,
      outDir,
    },
  );
  const result = program.emit();
  const diagnostics = [...ts.getPreEmitDiagnostics(program), ...result.diagnostics];
  if (diagnostics.length > 0) {
    const host = {
      getCanonicalFileName: (name) => name,
      getCurrentDirectory: () => repoRoot,
      getNewLine: () => "\n",
    };
    throw new Error(ts.formatDiagnostics(diagnostics, host));
  }

  // Inline private workspace packages: "@auth4/contracts/sdk" -> "../../contracts/src/sdk.js".
  const inlined = new Set();
  // Peer dependencies (next and react for @auth4/nextjs) are installed by the application.
  const dependencies = new Set([
    ...Object.keys(manifest.dependencies ?? {}),
    ...Object.keys(manifest.peerDependencies ?? {}),
  ]);
  const builtins = new Set(builtinModules);
  for (const file of listFiles(outDir)) {
    if (!/\.(js|d\.ts)$/.test(file)) continue;
    const source = readFileSync(file, "utf8");
    const rewritten = source.replace(SPECIFIER, (match, keyword, quote, specifier) => {
      if (specifier.startsWith(".")) return match;
      if (specifier.startsWith("@auth4/")) {
        const [source] = paths[specifier] ?? [];
        if (!source) throw new Error(`${specifier} is not an export of a workspace dependency`);
        const entry = join(outDir, relative(packagesDir, source).replace(/\.ts$/, ".js"));
        if (!existsSync(entry)) throw new Error(`${specifier} was not emitted into dist/`);
        inlined.add(specifier);
        let path = relative(dirname(file), entry).replaceAll("\\", "/");
        if (!path.startsWith(".")) path = `./${path}`;
        return `${keyword}${quote}${path}${quote}`;
      }
      const name = specifier.startsWith("@")
        ? specifier.split("/").slice(0, 2).join("/")
        : specifier.split("/")[0];
      if (!dependencies.has(name) && !builtins.has(specifier.replace(/^node:/, ""))) {
        throw new Error(`${relative(repoRoot, file)} imports ${specifier}, not a dependency`);
      }
      return match;
    });
    if (rewritten !== source) writeFileSync(file, rewritten);
  }
  return { name: manifest.name, inlined: [...inlined] };
}

// Static import/export specifiers and dynamic import() calls in emitted JS and declarations.
const SPECIFIER = /(\bfrom\s*|\bimport\s*\(?\s*)(["'])([^"']+)\2/g;

function listFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? listFiles(join(directory, entry.name)) : [join(directory, entry.name)],
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { name, inlined } = buildSdk(process.cwd());
  console.log(`built ${name}${inlined.length > 0 ? ` (inlined ${inlined.join(", ")})` : ""}`);
}
