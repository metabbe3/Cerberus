import path from "node:path";
import { defineConfig } from "vitest/config";

// "server-only" is a Next.js guard that throws outside RSC; under vitest it
// maps to an empty module so lib/engine.ts stays importable in tests.
export default defineConfig({
  test: {
    environment: "node",
    // e2e/ belongs to Playwright; vitest picking it up fails the run.
    exclude: ["e2e/**", "**/node_modules/**"],
  },
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "."),
      "server-only": path.resolve(import.meta.dirname, "test/server-only-stub.ts"),
    },
  },
});
