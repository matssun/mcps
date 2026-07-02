import { defineConfig } from "vitest/config";

// The native addon + compiled TS must be built before tests run (npm test does this).
// Tests import the built package from ./dist and the native binding from ./native.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    // The native addon calls JS callbacks synchronously; keep a single fork so the
    // Node main thread owns them (no worker threading around the .node boundary).
    pool: "forks",
    poolOptions: { forks: { singleFork: true } },
  },
});
