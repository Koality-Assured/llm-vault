#!/usr/bin/env node
import { parseArgs } from "node:util";
import {
  loadSession,
  saveSession,
  clearSession,
  isSessionValid,
  getDefaultSessionFilePath,
} from "./session.js";
import { SecretResolver, type SecretPayloadData } from "./resolver.js";
import { runCommand } from "./runner.js";
import { injectTemplate } from "./injector.js";

const HELP_TEXT = `
llm-vault - Developer CLI for zero-knowledge secret management and zero-file process injection.

USAGE:
  llm-vault <command> [options] [-- <child-command> [args...]]

COMMANDS:
  run             Execute a child process with in-memory decrypted environment variables
  inject          Render a template into an ephemeral in-memory FIFO and run a child command
  login           Cache an authentication token and server endpoint in local session store
  logout          Clear active local session cache
  status, whoami  Display active session and connection status

OPTIONS:
  -h, --help       Show this help message
  -v, --version    Show version information

RUN OPTIONS:
  --env-file <path>   Path to .env / .env.vault template file with {{vault:sec_...}} references
  --stream            Stream stdout/stderr directly to terminal with real-time secret scrubbing

INJECT OPTIONS:
  --template <path>   Path to configuration template file (e.g. app.config.tpl)
  --fifo-env <name>   Environment variable name to pass the FIFO path (default: VAULT_CONFIG_FIFO)

LOGIN OPTIONS:
  --endpoint <url>    Vault API server URL (e.g. http://localhost:3000)
  --token <token>     Bearer authentication token or agent token (agt_...)
  --tenant <id>       Tenant ID (e.g. tnt_default)
  --actor <id>        User or agent ID (usr_... / agt_...)

EXAMPLES:
  llm-vault run --env-file .env.vault -- npm start
  llm-vault inject --template config.json.tpl -- node server.js --config {{FIFO_PATH}}
  llm-vault login --endpoint http://localhost:3000 --token tok_123 --tenant tnt_prod --actor usr_admin
  llm-vault status
`;

async function createRemoteFetcher(session: { endpoint: string; token: string; tenantId: string }) {
  return async (secretId: string): Promise<SecretPayloadData | null> => {
    const url = `${session.endpoint.replace(/\/+$/, "")}/api/v1/secrets/${secretId}/reveal`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${session.token}`,
      },
      body: JSON.stringify({ reason: "cli-process-injection" }),
    });

    if (!res.ok) {
      if (res.status === 404) return null;
      throw new Error(
        `Failed to reveal secret "${secretId}": HTTP ${res.status} ${res.statusText}`,
      );
    }

    const json = (await res.json()) as {
      secret?: {
        encryptedPayload?: { ciphertext: string };
        metadata?: { name?: string };
        plaintextPayload?: SecretPayloadData;
      };
      payload?: SecretPayloadData;
      value?: string;
    };

    if (json.payload) return json.payload;
    if (json.secret?.plaintextPayload) return json.secret.plaintextPayload;
    if (json.value) return { value: json.value };

    throw new Error(
      `Remote endpoint returned encrypted payload for secret "${secretId}" without a local unwrapping key.`,
    );
  };
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  if (argv.length === 0 || argv.includes("-h") || argv.includes("--help") || argv[0] === "help") {
    console.log(HELP_TEXT.trim());
    return 0;
  }

  if (argv.includes("-v") || argv.includes("--version")) {
    console.log("llm-vault CLI v0.1.0");
    return 0;
  }

  const command = argv[0];
  const commandArgs = argv.slice(1);

  // Separate args before "--" (CLI options) and after "--" (child command)
  const dashDashIdx = commandArgs.indexOf("--");
  const cliOptionsArgs = dashDashIdx !== -1 ? commandArgs.slice(0, dashDashIdx) : commandArgs;
  const childCommandParts = dashDashIdx !== -1 ? commandArgs.slice(dashDashIdx + 1) : [];

  switch (command) {
    case "status":
    case "whoami": {
      const session = await loadSession();
      if (!session) {
        console.log("No active session found. Use `llm-vault login` to authenticate.");
        console.log(`Session file path: ${getDefaultSessionFilePath()}`);
        return 1;
      }
      const valid = isSessionValid(session);
      console.log("Active Session:");
      console.log(`  Endpoint:    ${session.endpoint}`);
      console.log(`  Tenant ID:   ${session.tenantId}`);
      console.log(`  Actor ID:    ${session.actorId}`);
      if (session.agentId) {
        console.log(`  Agent ID:    ${session.agentId}`);
      }
      if (session.vaultId) {
        console.log(`  Vault ID:    ${session.vaultId}`);
      }
      console.log(`  Status:      ${valid ? "Valid" : "EXPIRED"}`);
      if (session.expiresAt) {
        console.log(`  Expires At:  ${session.expiresAt}`);
      }
      console.log(`  File:        ${getDefaultSessionFilePath()}`);
      return valid ? 0 : 1;
    }

    case "logout": {
      const removed = await clearSession();
      if (removed) {
        console.log("Session cleared successfully.");
      } else {
        console.log("No active session was found.");
      }
      return 0;
    }

    case "login": {
      const { values } = parseArgs({
        args: cliOptionsArgs,
        options: {
          endpoint: { type: "string" },
          token: { type: "string" },
          tenant: { type: "string" },
          actor: { type: "string" },
          agent: { type: "string" },
          vault: { type: "string" },
        },
        allowPositionals: true,
      });

      if (!values.endpoint || !values.token || !values.tenant || !values.actor) {
        console.error("Error: --endpoint, --token, --tenant, and --actor are required for login.");
        return 1;
      }

      await saveSession({
        endpoint: values.endpoint,
        token: values.token,
        tenantId: values.tenant,
        actorId: values.actor,
        agentId: values.agent,
        vaultId: values.vault,
      });

      console.log(
        `Successfully logged in to ${values.endpoint} as ${values.actor} (Tenant: ${values.tenant}).`,
      );
      return 0;
    }

    case "run": {
      if (childCommandParts.length === 0) {
        console.error(
          "Error: No command specified to run. Syntax: llm-vault run [options] -- <command> [args...]",
        );
        return 1;
      }

      const { values } = parseArgs({
        args: cliOptionsArgs,
        options: {
          "env-file": { type: "string" },
          stream: { type: "boolean", default: true },
        },
        allowPositionals: true,
      });

      const session = await loadSession();
      if (!session || !isSessionValid(session)) {
        console.error(
          "Error: No valid session found. Run `llm-vault login` first or export LLM_VAULT_SESSION_FILE.",
        );
        return 1;
      }

      const fetcher = await createRemoteFetcher(session);
      const resolver = new SecretResolver(fetcher);

      const [childCmd, ...childArgs] = childCommandParts;
      if (!childCmd) {
        console.error("Error: Child command is empty.");
        return 1;
      }

      const result = await runCommand({
        command: childCmd,
        args: childArgs,
        envFile: values["env-file"],
        resolver,
        streamOutput: values.stream ?? true,
        captureOutput: false,
      });

      return result.exitCode;
    }

    case "inject": {
      if (childCommandParts.length === 0) {
        console.error(
          "Error: No command specified to run. Syntax: llm-vault inject --template <file> -- <command>",
        );
        return 1;
      }

      const { values } = parseArgs({
        args: cliOptionsArgs,
        options: {
          template: { type: "string" },
          "fifo-env": { type: "string", default: "VAULT_CONFIG_FIFO" },
          stream: { type: "boolean", default: true },
        },
        allowPositionals: true,
      });

      if (!values.template) {
        console.error("Error: --template <path> is required for inject.");
        return 1;
      }

      const session = await loadSession();
      if (!session || !isSessionValid(session)) {
        console.error("Error: No valid session found. Run `llm-vault login` first.");
        return 1;
      }

      const fetcher = await createRemoteFetcher(session);
      const resolver = new SecretResolver(fetcher);

      const [childCmd, ...childArgs] = childCommandParts;
      if (!childCmd) {
        console.error("Error: Child command is empty.");
        return 1;
      }

      const result = await injectTemplate({
        templatePath: values.template,
        command: childCmd,
        args: childArgs,
        envVarName: values["fifo-env"] ?? "VAULT_CONFIG_FIFO",
        resolver,
        streamOutput: values.stream ?? true,
        captureOutput: false,
      });

      return result.exitCode;
    }

    default:
      console.error(
        `Unknown command: "${command}". Run \`llm-vault --help\` for available commands.`,
      );
      return 1;
  }
}

if (process.argv[1] && (process.argv[1].endsWith("cli.js") || process.argv[1].endsWith("cli.ts"))) {
  main()
    .then((code) => {
      process.exit(code);
    })
    .catch((err) => {
      console.error("Fatal error:", err instanceof Error ? err.message : String(err));
      process.exit(1);
    });
}
