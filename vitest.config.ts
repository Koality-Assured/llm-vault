import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@llm-vault/ids": `${root}packages/ids/src/index.ts`,
      "@llm-vault/crypto": `${root}packages/crypto/src/index.ts`,
      "@llm-vault/schema/db/postgres": `${root}packages/schema/src/db/postgres.ts`,
      "@llm-vault/schema/db/sqlite": `${root}packages/schema/src/db/sqlite.ts`,
      "@llm-vault/schema": `${root}packages/schema/src/index.ts`,
    },
  },
  test: {
    environment: "node",
    include: ["packages/**/*.test.ts", "apps/**/*.test.ts"],
    fileParallelism: false,
  },
});
