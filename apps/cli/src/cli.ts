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
import { scanWorkspace } from "./scanner.js";
import { absorbFile } from "./absorb.js";
import { installPreCommitHook, removePreCommitHook, getPreCommitHookStatus } from "./hook.js";
import { startSshAgentServer, querySshAgentIdentities, type ApprovalMode } from "./ssh-agent.js";
import { syncSecretsToVolume } from "./sidecar.js";
import { generateEntityId } from "@llm-vault/ids";

const HELP_TEXT = `
llm-vault - Developer CLI for zero-knowledge secret management and zero-file process injection.

USAGE:
  llm-vault <command> [options] [-- <child-command> [args...]]

COMMANDS:
  run             Execute a child process with in-memory decrypted environment variables
  inject          Render a template into an ephemeral in-memory FIFO and run a child command
  scan            Scan workspace files or staged changes for unencrypted credentials
  absorb          Migrate hardcoded secrets into vault records and rewrite files to templates
  hook            Manage git pre-commit hooks (install, remove, status)
  ssh-agent       Manage embedded SSH agent and Git commit signing keys
  sidecar         Synchronize vault secrets into container volume mounts (tmpfs)
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

SCAN OPTIONS:
  --staged            Only scan files staged in git index
  --fail-on-found     Exit with code 1 if unencrypted credentials are found
  --json              Output findings as formatted JSON

ABSORB OPTIONS:
  --file <path>       Target file to scan and migrate (e.g. .env)
  --dry-run           Preview tokenization and template output without modifying disk
  --in-place          Rewrite target file in place instead of creating .tpl

HOOK OPTIONS:
  llm-vault hook [status|install|remove]

SSH AGENT OPTIONS:
  llm-vault ssh-agent [start|status] [--socket <path>] [--approval-mode <auto|interactive|oob>]

SIDECAR OPTIONS:
  llm-vault sidecar sync [--mount-path <path>] [--file <name:content>] [--clean-stale|--prune]

LOGIN OPTIONS:
  --endpoint <url>    Vault API server URL (e.g. http://localhost:3000)
  --token <token>     Bearer authentication token or agent token (agt_...)
  --tenant <id>       Tenant ID (e.g. tnt_default)
  --actor <id>        User or agent ID (usr_... / agt_...)

EXAMPLES:
  llm-vault scan --staged --fail-on-found
  llm-vault absorb .env --dry-run
  llm-vault hook install
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
  const dashDashIdx = argv.indexOf("--");
  const cliArgs = dashDashIdx !== -1 ? argv.slice(0, dashDashIdx) : argv;

  if (cliArgs.length === 0 || cliArgs.includes("-h") || cliArgs.includes("--help") || cliArgs[0] === "help") {
    console.log(HELP_TEXT.trim());
    return 0;
  }

  if (cliArgs.includes("-v") || cliArgs.includes("--version") || cliArgs[0] === "version") {
    console.log("llm-vault CLI v0.1.0");
    return 0;
  }

  const command = argv[0];
  const commandArgs = argv.slice(1);

  // Separate args before "--" (CLI options) and after "--" (child command)
  const cmdDashDashIdx = commandArgs.indexOf("--");
  const cliOptionsArgs = cmdDashDashIdx !== -1 ? commandArgs.slice(0, cmdDashDashIdx) : commandArgs;
  const childCommandParts = cmdDashDashIdx !== -1 ? commandArgs.slice(cmdDashDashIdx + 1) : [];

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

      const [childCmd, ...childArgs] = childCommandParts;
      if (!childCmd) {
        console.error("Error: Child command is empty.");
        return 1;
      }

      try {
        const fetcher = await createRemoteFetcher(session);
        const resolver = new SecretResolver(fetcher);

        const result = await runCommand({
          command: childCmd,
          args: childArgs,
          envFile: values["env-file"],
          resolver,
          streamOutput: values.stream ?? true,
          captureOutput: false,
        });

        return result.exitCode;
      } catch (err) {
        console.error("Run error:", err instanceof Error ? err.message : String(err));
        return 1;
      }
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

      const [childCmd, ...childArgs] = childCommandParts;
      if (!childCmd) {
        console.error("Error: Child command is empty.");
        return 1;
      }

      try {
        const fetcher = await createRemoteFetcher(session);
        const resolver = new SecretResolver(fetcher);

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
      } catch (err) {
        console.error("Inject error:", err instanceof Error ? err.message : String(err));
        return 1;
      }
    }

    case "scan": {
      const { values, positionals } = parseArgs({
        args: cliOptionsArgs,
        options: {
          staged: { type: "boolean", default: false },
          json: { type: "boolean", default: false },
          "fail-on-found": { type: "boolean", default: false },
          dir: { type: "string" },
        },
        allowPositionals: true,
      });

      const targetFiles = positionals.length > 0 ? positionals : undefined;
      const targetDir = values.dir ?? process.cwd();

      const scanResult = await scanWorkspace({
        directory: targetDir,
        files: targetFiles,
        stagedOnly: values.staged,
      });

      if (values.json) {
        console.log(JSON.stringify(scanResult, null, 2));
      } else {
        console.log(`Scanned ${scanResult.scannedFiles} file(s) in ${scanResult.durationMs}ms.`);
        if (scanResult.findings.length === 0) {
          console.log("No unencrypted credentials detected. Workspace is clean.");
        } else {
          console.log(`Found ${scanResult.findings.length} unencrypted credential(s):\n`);
          for (const f of scanResult.findings) {
            console.log(`  [${f.ruleId}] ${f.filePath}:${f.line}:${f.column}`);
            console.log(`    Description: ${f.description}`);
            console.log(`    Redacted:    ${f.redactedValue} (entropy: ${f.entropy})`);
            if (f.suggestedHandle) {
              console.log(`    Suggested:   ${f.suggestedHandle}`);
            }
            console.log("");
          }
          console.log(
            "Run `llm-vault absorb <file>` to tokenize credentials into {{vault:sec_...}} templates.",
          );
        }
      }

      if (scanResult.findings.length > 0 && values["fail-on-found"]) {
        return 1;
      }
      return 0;
    }

    case "absorb": {
      const { values, positionals } = parseArgs({
        args: cliOptionsArgs,
        options: {
          file: { type: "string" },
          "dry-run": { type: "boolean", default: false },
          "in-place": { type: "boolean", default: false },
          vault: { type: "string" },
          json: { type: "boolean", default: false },
        },
        allowPositionals: true,
      });

      const targetFile = values.file ?? positionals[0];
      if (!targetFile) {
        console.error("Error: Target file required. Usage: llm-vault absorb <file> [--dry-run]");
        return 1;
      }

      const session = await loadSession();
      const absorbRes = await absorbFile({
        targetFile,
        dryRun: values["dry-run"],
        inPlace: values["in-place"],
        vaultId: values.vault ?? session?.vaultId,
        endpoint: session?.endpoint,
        token: session?.token,
      });

      if (values.json) {
        console.log(JSON.stringify(absorbRes, null, 2));
      } else {
        if (absorbRes.dryRun) {
          console.log(`[DRY-RUN] Absorbing secrets from ${targetFile}:`);
        } else {
          console.log(
            `Successfully absorbed ${absorbRes.absorbedCount} secret(s) from ${targetFile}:`,
          );
        }

        for (const act of absorbRes.actions) {
          console.log(`  - ${act.secretName} (line ${act.line}) -> ${act.handle}`);
          if (act.templatePath) {
            console.log(`    Template created: ${act.templatePath}`);
          }
        }

        if (absorbRes.dryRun) {
          console.log("\nRun without --dry-run to commit template and encrypt secrets.");
        }
      }

      return 0;
    }

    case "hook": {
      const subAction = commandArgs[0];
      if (!subAction || subAction === "status") {
        const status = getPreCommitHookStatus();
        console.log("Git Pre-Commit Hook Status:");
        console.log(`  Installed:      ${status.installed ? "YES" : "NO"}`);
        console.log(`  Path:           ${status.hookPath || "(none)"}`);
        console.log(`  Executable:     ${status.executable ? "YES" : "NO"}`);
        console.log(`  llm-vault Hook: ${status.isLlmVaultHook ? "YES" : "NO"}`);
        return status.installed ? 0 : 1;
      }

      if (subAction === "install") {
        try {
          const status = installPreCommitHook();
          console.log(`Pre-commit hook successfully installed at: ${status.hookPath}`);
          return 0;
        } catch (err) {
          console.error(
            "Failed to install hook:",
            err instanceof Error ? err.message : String(err),
          );
          return 1;
        }
      }

      if (subAction === "remove") {
        const status = removePreCommitHook();
        console.log(`Pre-commit hook removed. (Installed: ${status.installed})`);
        return 0;
      }

      console.error(
        `Unknown hook action: "${subAction}". Usage: llm-vault hook [status|install|remove]`,
      );
      return 1;
    }

    case "ssh-agent": {
      const subAction = commandArgs[0];
      const { values } = parseArgs({
        args: cliOptionsArgs.slice(1),
        options: {
          socket: { type: "string" },
          "approval-mode": { type: "string" },
        },
        allowPositionals: true,
      });

      if (!subAction || subAction === "status") {
        const socketPath = values.socket || process.env["SSH_AUTH_SOCK"];
        if (!socketPath) {
          console.error(
            "No socket path specified and SSH_AUTH_SOCK environment variable is unset.",
          );
          return 1;
        }

        try {
          const identities = await querySshAgentIdentities(socketPath);
          console.log(`SSH Agent active at: ${socketPath}`);
          console.log(`Loaded Identities (${identities.length}):`);
          for (const id of identities) {
            console.log(`  ${id.fingerprint} ${id.comment} (ED25519)`);
          }
          return 0;
        } catch (err) {
          console.error(
            "Failed to query SSH agent status:",
            err instanceof Error ? err.message : String(err),
          );
          return 1;
        }
      }

      if (subAction === "start") {
        const mode = (values["approval-mode"] as ApprovalMode) || "interactive";
        try {
          const instance = await startSshAgentServer({
            socketPath: values.socket,
            approvalMode: mode,
          });
          console.log(`SSH_AUTH_SOCK=${instance.socketPath}; export SSH_AUTH_SOCK;`);
          console.log(`echo SSH agent started with pid ${process.pid};`);
          return 0;
        } catch (err) {
          console.error(
            "Failed to start SSH agent server:",
            err instanceof Error ? err.message : String(err),
          );
          return 1;
        }
      }

      console.error(
        `Unknown ssh-agent action: "${subAction}". Usage: llm-vault ssh-agent [start|status]`,
      );
      return 1;
    }

    case "sidecar": {
      const subAction = commandArgs[0];
      const { values } = parseArgs({
        args: cliOptionsArgs.slice(1),
        options: {
          "mount-path": { type: "string" },
          file: { type: "string" },
          "clean-stale": { type: "boolean", default: false },
          prune: { type: "boolean", default: false },
        },
        allowPositionals: true,
      });

      if (!subAction || subAction === "sync") {
        const mountPath = values["mount-path"] || "/vault/secrets";
        const secretsList = [];

        if (values.file) {
          const firstColon = values.file.indexOf(":");
          if (firstColon !== -1) {
            const filename = values.file.slice(0, firstColon);
            const content = values.file.slice(firstColon + 1);
            secretsList.push({
              secretId: generateEntityId("sec_"),
              outputFilename: filename,
              content,
            });
          }
        }

        try {
          const res = await syncSecretsToVolume({
            mountPath,
            secrets: secretsList,
            cleanStaleFiles: Boolean(values["clean-stale"] || values.prune),
          });
          console.log(
            `Sidecar successfully synchronized ${res.syncedCount} secret file(s) into ${mountPath}`,
          );
          return 0;
        } catch (err) {
          console.error("Sidecar sync failed:", err instanceof Error ? err.message : String(err));
          return 1;
        }
      }

      console.error(
        `Unknown sidecar action: "${subAction}". Usage: llm-vault sidecar sync [--mount-path <path>] [--file <name:content>] [--clean-stale|--prune]`,
      );
      return 1;
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
