#!/usr/bin/env node
// AUTH4D-231: builds both entry points, "@auth4/nextjs" (client) and "@auth4/nextjs/server".
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSdk } from "../../scripts/sdk/build.mjs";

const { name } = buildSdk(dirname(fileURLToPath(import.meta.url)), [
  "src/index.ts",
  "src/server.ts",
]);
console.log(`built ${name}`);
