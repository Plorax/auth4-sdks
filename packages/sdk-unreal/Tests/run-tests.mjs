#!/usr/bin/env node
// Builds the Auth4Core tests with CMake, starts the local mock server and runs the suite against it.
// Needs CMake and a C++17 compiler (MSVC, GCC or Clang); Unreal Engine is not required. Build output
// and a JSON report go to .generated/auth4d-153/ (git-ignored).
//
//   node packages/sdk-unreal/Tests/run-tests.mjs
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMockServer } from "./mock-server.mjs";

const testsDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(testsDir, "..", "..", "..");
const outDir = join(repoRoot, ".generated", "auth4d-153");
const buildDir = join(outDir, "cmake");
mkdirSync(buildDir, { recursive: true });

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) {
    console.error(
      `${command} ${args.join(" ")} failed (${result.error?.message ?? result.status}).`,
    );
    process.exit(1);
  }
}

run("cmake", ["-S", testsDir, "-B", buildDir, "-DCMAKE_BUILD_TYPE=Release"]);
run("cmake", ["--build", buildDir, "--config", "Release"]);

const executable = ["Release/auth4_core_tests.exe", "auth4_core_tests.exe", "auth4_core_tests"]
  .map((name) => join(buildDir, name))
  .find((path) => existsSync(path));
if (!executable) {
  console.error("The test executable was not built.");
  process.exit(1);
}

const mock = await startMockServer();
const started = new Date().toISOString();
// The mock server runs in this process, so the suite runs asynchronously beside it.
const output = [];
const status = await new Promise((resolve) => {
  const child = spawn(executable, ["--origin", mock.origin]);
  child.stdout.on("data", (chunk) => {
    process.stdout.write(chunk);
    output.push(chunk.toString("utf8"));
  });
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  child.on("close", (code) => resolve(code ?? 1));
});
await mock.close();

const lines = output.join("").split(/\r?\n/u);
writeFileSync(
  join(outDir, "report.json"),
  `${JSON.stringify(
    {
      ticket: "AUTH4D-153",
      started,
      finished: new Date().toISOString(),
      passed: lines.filter((line) => line.startsWith("PASS ")).map((line) => line.slice(5)),
      failed: lines.filter((line) => line.startsWith("FAIL ")).map((line) => line.slice(5)),
      exitCode: status,
    },
    null,
    2,
  )}\n`,
);
process.exit(status);
