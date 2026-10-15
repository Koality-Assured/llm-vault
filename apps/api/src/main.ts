import { buildServer } from "./server.js";

const port = Number(process.env["PORT"] ?? 3000);
const host = process.env["HOST"] ?? "127.0.0.1";

const app = buildServer();

app.listen({ port, host }, (err, address) => {
  if (err) {
    console.error("Failed to start llm-vault API server:", err);
    process.exit(1);
  }
  console.log(`llm-vault API server listening at ${address}`);
});

const handleShutdown = async () => {
  console.log("Shutting down llm-vault API server...");
  await app.close();
  process.exit(0);
};

process.on("SIGINT", handleShutdown);
process.on("SIGTERM", handleShutdown);
