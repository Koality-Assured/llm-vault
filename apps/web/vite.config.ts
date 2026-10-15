import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const root = fileURLToPath(new URL("../..", import.meta.url));

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@llm-vault/ids": `${root}/packages/ids/src/index.ts`,
      "@llm-vault/crypto": `${root}/packages/crypto/src/index.ts`,
      "@llm-vault/schema/db/postgres": `${root}/packages/schema/src/db/postgres.ts`,
      "@llm-vault/schema/db/sqlite": `${root}/packages/schema/src/db/sqlite.ts`,
      "@llm-vault/schema": `${root}/packages/schema/src/index.ts`,
    },
  },
  server: {
    port: 5173,
    headers: {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    },
  },
});
