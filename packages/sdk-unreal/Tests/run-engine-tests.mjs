#!/usr/bin/env node
// Builds the plugin in Unreal Engine 5 and runs its automation tests (AUTH4D-218). Needs an installed
// engine and its C++ toolchain (Visual Studio on Windows, the engine's clang toolchain on Linux), so
// it runs on the self-hosted unreal runner in CI rather than on GitHub-hosted runners.
//
//   node packages/sdk-unreal/Tests/run-engine-tests.mjs [--engine <UE_5.x directory>]
//
// The engine comes from --engine, then UE_ROOT, then the newest UE 5 in the Windows registry. Steps:
//   1. RunUAT BuildPlugin with -StrictIncludes packages the plugin for the host platform, the way a
//      game or Fab would build it.
//   2. A copy of examples/unreal with the plugin under Plugins/Auth4 builds as an editor target.
//   3. The editor runs the Auth4.* automation tests headless, with Tests/mock-server.mjs on a loopback
//      port so Auth4.Engine.GuestRefreshSignOut exercises the FHttpModule transport and core ticker.
// Everything goes to .generated/auth4d-218/ (git-ignored); the summary is report.json.
import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { startMockServer } from "./mock-server.mjs";

const testsDir = dirname(fileURLToPath(import.meta.url));
const pluginDir = join(testsDir, "..");
const repoRoot = join(pluginDir, "..", "..");
const outDir = join(repoRoot, ".generated", "auth4d-218");
const windows = process.platform === "win32";

// Every test in Source/Auth4/Private/Tests must be listed here, so a test that is not compiled or
// not discovered fails the run instead of disappearing silently.
export const EXPECTED_TESTS = [
  "Auth4.Types.ErrorConversion",
  "Auth4.Types.Conversions",
  "Auth4.Settings.Registration",
  "Auth4.Client.Options",
  "Auth4.Engine.GuestRefreshSignOut",
];

// Engine and automation JSON files may start with a byte order mark.
function readJson(path) {
  const text = readFileSync(path, "utf8");
  return JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
}

function versionOf(engineDir) {
  try {
    const build = readJson(join(engineDir, "Engine", "Build", "Build.version"));
    return `${build.MajorVersion}.${build.MinorVersion}.${build.PatchVersion}`;
  } catch {
    return null;
  }
}

function findEngine(argv) {
  const flag = argv.indexOf("--engine");
  if (flag !== -1 && argv[flag + 1]) return resolve(argv[flag + 1]);
  if (process.env.UE_ROOT) return resolve(process.env.UE_ROOT);
  if (!windows) return null;
  const query = spawnSync(
    "reg",
    ["query", "HKLM\\SOFTWARE\\EpicGames\\Unreal Engine", "/s", "/v", "InstalledDirectory"],
    { encoding: "utf8" },
  );
  const candidates = [...(query.stdout ?? "").matchAll(/InstalledDirectory\s+REG_SZ\s+(.+)/gu)]
    .map((match) => match[1].trim())
    .filter((dir) => versionOf(dir)?.startsWith("5."));
  candidates.sort((a, b) => versionOf(b).localeCompare(versionOf(a), undefined, { numeric: true }));
  return candidates[0] ?? null;
}

// .bat files need a shell on Windows; arguments are quoted here, never taken from untrusted input.
function run(label, command, args, logName) {
  console.log(`\n== ${label}`);
  const quoted = [command, ...args].map((part) => (/[\s"]/u.test(part) ? `"${part}"` : part));
  const result = spawnSync(quoted.join(" "), { shell: true, stdio: "inherit" });
  if (result.status !== 0) {
    throw new Error(
      `${label} failed (${result.error?.message ?? `exit ${result.status}`}); see ${logName}.`,
    );
  }
}

function copyTree(from, to) {
  const skip = new Set(["Binaries", "Intermediate", "Saved", "DerivedDataCache", "Plugins", ".vs"]);
  cpSync(from, to, {
    recursive: true,
    filter: (source) => source === from || !skip.has(basename(source)),
  });
}

/** Reads index.json from -ReportExportPath and checks every expected test passed cleanly. */
export function checkAutomationReport(report, expected = EXPECTED_TESTS) {
  const tests = (report.tests ?? []).map((test) => ({
    name: test.fullTestPath,
    state: test.state,
    warnings: test.warnings ?? 0,
    errors: (test.entries ?? [])
      .filter((entry) => entry.event?.type === "Error")
      .map((entry) => entry.event.message),
  }));
  const problems = [];
  for (const name of expected) {
    const test = tests.find((entry) => entry.name === name);
    if (!test) problems.push(`${name} did not run`);
    else if (test.state !== "Success")
      problems.push(`${name}: ${test.state} ${test.errors.join("; ")}`);
    else if (test.warnings > 0) problems.push(`${name} passed with warnings (skipped?)`);
  }
  for (const test of tests) {
    if (!expected.includes(test.name)) problems.push(`${test.name} is not in EXPECTED_TESTS`);
  }
  return { tests, problems };
}

async function main() {
  const engineDir = findEngine(process.argv.slice(2));
  if (!engineDir || !versionOf(engineDir)) {
    throw new Error("No Unreal Engine 5 found. Pass --engine <dir> or set UE_ROOT.");
  }
  const engineVersion = versionOf(engineDir);
  const batchFiles = join(engineDir, "Engine", "Build", "BatchFiles");
  const runUat = join(batchFiles, windows ? "RunUAT.bat" : "RunUAT.sh");
  const buildTool = windows ? join(batchFiles, "Build.bat") : join(batchFiles, "Linux", "Build.sh");
  const editor = windows
    ? join(engineDir, "Engine", "Binaries", "Win64", "UnrealEditor-Cmd.exe")
    : join(engineDir, "Engine", "Binaries", "Linux", "UnrealEditor");
  const platform = windows ? "Win64" : "Linux";
  console.log(`Unreal Engine ${engineVersion} at ${engineDir}`);

  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  const started = new Date().toISOString();
  const steps = [];

  // 1. Package the plugin.
  const packageDir = join(outDir, "package");
  run(
    "BuildPlugin",
    runUat,
    [
      "BuildPlugin",
      `-Plugin=${join(pluginDir, "Auth4.uplugin")}`,
      `-Package=${packageDir}`,
      `-TargetPlatforms=${platform}`,
      "-StrictIncludes",
      "-unattended",
      "-nop4",
    ],
    "the BuildPlugin output above",
  );
  steps.push("BuildPlugin");

  // 2. Build a copy of the example project with the plugin sources in it.
  const projectDir = join(outDir, "project");
  copyTree(join(repoRoot, "examples", "unreal"), projectDir);
  copyTree(pluginDir, join(projectDir, "Plugins", "Auth4"));
  const project = join(projectDir, "Auth4Example.uproject");
  run(
    "Editor build",
    buildTool,
    [
      "Auth4ExampleEditor",
      platform,
      "Development",
      `-Project=${project}`,
      "-WaitMutex",
      "-NoHotReload",
    ],
    "the build output above",
  );
  steps.push("EditorBuild");

  // 3. Automation tests, headless, against the mock server.
  const mock = await startMockServer();
  const reportDir = join(outDir, "automation");
  const logFile = join(outDir, "editor.log");
  console.log(`\n== Automation tests (mock server ${mock.origin})`);
  const exitCode = await new Promise((done) => {
    const child = spawn(
      editor,
      [
        project,
        "-ExecCmds=Automation RunTests Auth4",
        "-TestExit=Automation Test Queue Empty",
        `-ReportExportPath=${reportDir}`,
        `-Auth4MockOrigin=${mock.origin}`,
        `-abslog=${logFile}`,
        "-unattended",
        "-nullrhi",
        "-nosplash",
        "-nosound",
        "-nop4",
        "-stdout",
        "-FullStdOutLogOutput",
      ],
      { stdio: ["ignore", "inherit", "inherit"] },
    );
    child.on("close", (code) => done(code ?? 1));
  });
  await mock.close();

  const indexFile = join(reportDir, "index.json");
  if (!existsSync(indexFile)) {
    throw new Error(
      `The editor exited with ${exitCode} and wrote no automation report; see ${logFile}.`,
    );
  }
  const { tests, problems } = checkAutomationReport(readJson(indexFile));
  steps.push("Automation");

  const packaged = existsSync(join(packageDir, "Binaries"))
    ? readdirSync(join(packageDir, "Binaries", platform)).filter((name) =>
        /\.(dll|so)$/u.test(name),
      )
    : [];
  const report = {
    ticket: "AUTH4D-218",
    started,
    finished: new Date().toISOString(),
    engineVersion,
    platform,
    steps,
    packagedBinaries: packaged,
    editorExitCode: exitCode,
    tests,
    problems,
    passed: problems.length === 0,
  };
  writeFileSync(join(outDir, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  for (const test of tests)
    console.log(`${test.state === "Success" ? "PASS" : "FAIL"} ${test.name}`);
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    process.exit(1);
  }
  console.log(`\nAll ${tests.length} automation tests passed in Unreal Engine ${engineVersion}.`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
