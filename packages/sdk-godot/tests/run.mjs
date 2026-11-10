// Runs the Godot addon checks (AUTH4D-152) with a Godot 4 binary:
//   1. the GDScript suite (tests/test_client.gd) against the local mock server;
//   2. the example project (examples/godot) with the addon copied in, loaded headless, which must
//      parse and start without script errors.
// The report goes to .generated/auth4d-152/godot-sdk.json.
//
//   GODOT_BIN=/path/to/godot node packages/sdk-godot/tests/run.mjs
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createMockServer } from "./mock-server.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(packageRoot, "..", "..");
const outputDir = join(repoRoot, ".generated", "auth4d-152");
const godot = process.env.GODOT_BIN ?? "godot";

// Asynchronous, so the in-process mock server keeps answering while Godot runs.
function spawnGodot(args) {
  return new Promise((resolveResult) => {
    const child = spawn(godot, ["--headless", ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill(), 300_000);
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", (error) => {
      clearTimeout(timer);
      resolveResult({ status: null, stdout, stderr, error });
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolveResult({ status, stdout, stderr });
    });
  });
}

async function run(args, label) {
  const started = Date.now();
  const result = await spawnGodot(args);
  const output = `${result.stdout}${result.stderr}`;
  // Godot exits 0 from --import even when a script fails to parse, so errors are read from output.
  const scriptErrors = output
    .split("\n")
    .filter((line) => /SCRIPT ERROR|Parse Error|Failed to load script/u.test(line));
  if (result.error) {
    console.error(`${label}: could not start ${godot} (${result.error.message}). Set GODOT_BIN.`);
  }
  return { label, status: result.status, output, scriptErrors, durationMs: Date.now() - started };
}

const version = spawnSync(godot, ["--version"], { encoding: "utf8" });
if (version.status !== 0) {
  console.error(`Godot 4 is required. Set GODOT_BIN to the Godot executable (tried "${godot}").`);
  process.exit(2);
}

const steps = [];
const mock = createMockServer();
const origin = await mock.listen();
try {
  steps.push(await run(["--path", packageRoot, "--import"], "import addon"));
  const suite = await run(
    ["--path", packageRoot, "-s", "res://tests/test_client.gd", "--", `--origin=${origin}`],
    "GDScript suite",
  );
  steps.push(suite);
  process.stdout.write(suite.output);
} finally {
  await mock.close();
}

// The example ships without the addon; copy it in, as the guide tells developers to. The public
// SDK mirror (AUTH4D-478) has no examples/ directory, so the suite alone runs there.
const exampleDir = join(outputDir, "example");
rmSync(exampleDir, { recursive: true, force: true });
mkdirSync(outputDir, { recursive: true });
if (existsSync(join(repoRoot, "examples", "godot"))) {
  cpSync(join(repoRoot, "examples", "godot"), exampleDir, {
    recursive: true,
    filter: (source) => !/[\\/](?:\.godot|addons)$/u.test(source),
  });
  cpSync(join(packageRoot, "addons", "auth4"), join(exampleDir, "addons", "auth4"), {
    recursive: true,
  });
  steps.push(await run(["--path", exampleDir, "--import"], "import example"));
  steps.push(await run(["--path", exampleDir, "--quit-after", "30"], "start example"));
}

const report = {
  ticket: "AUTH4D-152",
  generatedAt: new Date().toISOString(),
  godot: version.stdout.trim(),
  steps: steps.map(({ label, status, scriptErrors, durationMs }) => ({
    label,
    ok: status === 0 && scriptErrors.length === 0,
    status,
    scriptErrors,
    durationMs,
  })),
};
writeFileSync(join(outputDir, "godot-sdk.json"), `${JSON.stringify(report, null, 2)}\n`);

let failed = false;
for (const step of report.steps) {
  console.log(`${step.ok ? "ok  " : "FAIL"} ${step.label}`);
  for (const line of step.scriptErrors) console.log(`     ${line.trim()}`);
  failed ||= !step.ok;
}
process.exit(failed ? 1 : 0);
