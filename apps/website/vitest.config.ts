import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
      // "server-only" throws outside React Server Components; unit tests import server modules directly.
      "server-only": path.resolve(import.meta.dirname, "tests/unit/empty.ts"),
    },
  },
  test: { include: ["tests/unit/**/*.test.ts"], environment: "node", env: { APP_SECRET: "unit-test-secret-unit-test-secret-0123456789" } },
});
