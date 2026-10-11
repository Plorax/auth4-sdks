// AUTH4D-240: the only private workspace modules an SDK tarball may carry. build.mjs inlines what
// an SDK imports from private workspace packages under dist/<package>/; every other file there
// must belong to the SDK's own package. Billing, audit-archive, custom-claims, management and
// Flows internals stay out of published tarballs.
export const INLINED_PRIVATE_MODULES = Object.freeze([
  // @auth4/contracts/sdk: access-token claims and Flows call_backend wire shapes.
  "contracts/src/sdk",
  // Its only import besides zod.
  "contracts/src/primitives",
]);

/**
 * Problems with the dist/ files of one packed npm SDK. `sdkDir` is the SDK's repository directory
 * (packages/sdk-server) and `paths` the tarball paths (package/dist/sdk-server/src/index.js).
 */
export function privateFileProblems(sdkDir, paths) {
  const own = sdkDir.split("/").at(-1);
  const problems = [];
  for (const path of paths) {
    const module = /^package\/dist\/(.+?)(\.d\.ts|\.js)$/.exec(path)?.[1];
    if (module === undefined || module.startsWith(`${own}/`)) continue;
    if (!INLINED_PRIVATE_MODULES.includes(module)) {
      problems.push(`private workspace file in tarball: ${path.slice("package/".length)}`);
    }
  }
  return problems;
}
