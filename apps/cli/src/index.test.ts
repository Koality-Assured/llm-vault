import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as net from "node:net";
import { generateEntityId } from "@llm-vault/ids";
import {
  saveSession,
  loadSession,
  clearSession,
  isSessionValid,
  type SessionData,
} from "./session.js";
import { scrubSecretsFromText, createStreamScrubber } from "./scrubber.js";
import { SecretResolver } from "./resolver.js";
import { createMemoryFifo } from "./fifo.js";
import { runCommand } from "./runner.js";
import { injectTemplate } from "./injector.js";
import { calculateShannonEntropy, redactSecret, scanContent, scanWorkspace } from "./scanner.js";
import { absorbFile } from "./absorb.js";
import { installPreCommitHook, removePreCommitHook, getPreCommitHookStatus } from "./hook.js";
import { main } from "./cli.js";

describe("@llm-vault/cli", () => {
  let tempDir: string;
  let sessionFile: string;

  beforeEach(async () => {
    tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "llm-vault-cli-test-"));
    sessionFile = path.join(tempDir, "session.json");
  });

  afterEach(async () => {
    if (fs.existsSync(tempDir)) {
      await fs.promises.rm(tempDir, { recursive: true, force: true });
    }
  });

  describe("Session Management & Keychain Storage", () => {
    it("saves and loads active session with expiration check", async () => {
      const data: SessionData = {
        endpoint: "http://localhost:3000",
        tenantId: "tnt_test_tenant",
        actorId: "usr_admin",
        token: "tok_secret_jwt_token_12345",
        expiresAt: new Date(Date.now() + 3600 * 1000).toISOString(),
      };

      await saveSession(data, sessionFile);
      expect(fs.existsSync(sessionFile)).toBe(true);

      const loaded = await loadSession(sessionFile);
      expect(loaded).toEqual(data);
      expect(isSessionValid(loaded)).toBe(true);

      // Verify expired session detection
      const expiredData: SessionData = {
        ...data,
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      };
      expect(isSessionValid(expiredData)).toBe(false);

      // Verify clearSession
      const cleared = await clearSession(sessionFile);
      expect(cleared).toBe(true);
      expect(await loadSession(sessionFile)).toBeNull();
    });
  });

  describe("Secret Scrubber & Stream Redactor", () => {
    it("redacts raw, base64, and url-encoded variants of secrets", () => {
      const secId = generateEntityId("sec_");
      const secretValue = "Sk-Proj-SecretKey9876543210!@#$";
      const valBytes = new TextEncoder().encode(secretValue);

      const activeSecrets = [
        {
          id: secId,
          value: secretValue,
          valueBytes: valBytes,
        },
      ];

      // 1. Raw UTF-8
      const rawText = `Application crashed with key: ${secretValue} in environment`;
      const scrubbedRaw = scrubSecretsFromText(rawText, activeSecrets);
      expect(scrubbedRaw).toBe(`Application crashed with key: [REDACTED:${secId}] in environment`);
      expect(scrubbedRaw).not.toContain(secretValue);

      // 2. Base64
      const b64 = Buffer.from(secretValue).toString("base64");
      const b64Text = `Token in header: Basic ${b64}`;
      const scrubbedB64 = scrubSecretsFromText(b64Text, activeSecrets);
      expect(scrubbedB64).toBe(`Token in header: Basic [REDACTED:${secId}]`);
      expect(scrubbedB64).not.toContain(b64);

      // 3. URL-encoded
      const urlEnc = encodeURIComponent(secretValue);
      const urlText = `Callback url: https://example.com/oauth?key=${urlEnc}&status=ok`;
      const scrubbedUrl = scrubSecretsFromText(urlText, activeSecrets);
      expect(scrubbedUrl).toBe(
        `Callback url: https://example.com/oauth?key=[REDACTED:${secId}]&status=ok`,
      );
      expect(scrubbedUrl).not.toContain(urlEnc);
    });

    it("redacts secrets spanning across streaming chunk boundaries", () => {
      const secId = generateEntityId("sec_");
      const secretValue = "SuperLongSecretTokenForStreamingTest123";
      const valBytes = new TextEncoder().encode(secretValue);

      const activeSecrets = [
        {
          id: secId,
          value: secretValue,
          valueBytes: valBytes,
        },
      ];

      let output = "";
      const scrubber = createStreamScrubber(activeSecrets, (chunk) => {
        output += chunk;
      });

      // Split the secret across two chunks
      const splitIdx = 15;
      const part1 = `Log line before: ${secretValue.slice(0, splitIdx)}`;
      const part2 = `${secretValue.slice(splitIdx)} and text after log line.`;

      scrubber.write(part1);
      scrubber.write(part2);
      scrubber.flush();

      expect(output).toBe(`Log line before: [REDACTED:${secId}] and text after log line.`);
      expect(output).not.toContain(secretValue);
    });
  });

  describe("SecretResolver", () => {
    it("resolves {{vault:sec_<ulid>}} and field selectors in strings and environment maps", async () => {
      const sec1 = generateEntityId("sec_");
      const sec2 = generateEntityId("sec_");

      const store = new Map<string, { value: string; username?: string; notes?: string }>([
        [sec1, { value: "postgres://user:pass@db:5432/main", username: "db_admin" }],
        [sec2, { value: "ghp_PersonalAccessToken000000", notes: "Production deploy token" }],
      ]);

      const resolver = new SecretResolver(async (id) => store.get(id) ?? null);

      // 1. Resolve string template
      const template = `DATABASE_URL={{vault:${sec1}}} DB_USER={{vault:${sec1}#username}} GITHUB_TOKEN={{vault:${sec2}}}`;
      const resolvedString = await resolver.resolveString(template);
      expect(resolvedString).toBe(
        `DATABASE_URL=postgres://user:pass@db:5432/main DB_USER=db_admin GITHUB_TOKEN=ghp_PersonalAccessToken000000`,
      );

      // 2. Resolve environment variables
      const rawEnv = {
        DB_URL: `{{vault:${sec1}}}`,
        GH_PAT: `vault:${sec2}`,
        STATIC_VAR: "normal_value",
      };
      const { resolvedEnv, activeSecrets } = await resolver.resolveEnv(rawEnv);
      expect(resolvedEnv.DB_URL).toBe("postgres://user:pass@db:5432/main");
      expect(resolvedEnv.GH_PAT).toBe("ghp_PersonalAccessToken000000");
      expect(resolvedEnv.STATIC_VAR).toBe("normal_value");
      expect(activeSecrets.length).toBeGreaterThanOrEqual(2);

      // 3. Memory zeroization
      resolver.zeroizeAll();
      expect(resolver.getActiveSecrets().length).toBe(0);
    });

    it("parses .env / .env.vault template syntax", () => {
      const dotenvContent = `
# Database configuration
DATABASE_URL={{vault:sec_01jk0000000000000000000001}}
PORT=8080
API_KEY="{{vault:sec_01jk0000000000000000000002}}"
# Trailing comments
DEBUG='true'
`;
      const parsed = SecretResolver.parseDotenv(dotenvContent);
      expect(parsed.DATABASE_URL).toBe("{{vault:sec_01jk0000000000000000000001}}");
      expect(parsed.PORT).toBe("8080");
      expect(parsed.API_KEY).toBe("{{vault:sec_01jk0000000000000000000002}}");
      expect(parsed.DEBUG).toBe("true");
    });
  });

  describe("In-Memory Ephemeral FIFO / Named Pipe", () => {
    it("creates an ephemeral pipe, streams content directly from memory, and closes", async () => {
      const sensitiveContent = JSON.stringify({
        db_password: "SuperSecretPassword123!",
        encryption_key: "0123456789abcdef0123456789abcdef",
      });

      const fifo = await createMemoryFifo(sensitiveContent);
      expect(fifo.path).toBeDefined();

      if (process.platform === "win32") {
        // Read directly from Windows Named Pipe
        const readContent = await new Promise<string>((resolve, reject) => {
          const client = net.connect(fifo.path, () => {});
          let buf = "";
          client.on("data", (d) => {
            buf += d.toString("utf-8");
          });
          client.on("end", () => resolve(buf));
          client.on("error", (err) => reject(err));
        });
        expect(readContent).toBe(sensitiveContent);
      } else {
        // POSIX FIFO read
        const readContent = await fs.promises.readFile(fifo.path, "utf-8");
        expect(readContent).toBe(sensitiveContent);
      }

      await fifo.close();
    });
  });

  describe("llm-vault run (Process Spawning & Live Output Redaction)", () => {
    it("spawns child process, injects secret into process.env, and scrubs stdout", async () => {
      const secId = generateEntityId("sec_");
      const secretValue = "top-secret-injection-token-xyz-987";

      const resolver = new SecretResolver(async (id) => {
        if (id === secId) return secretValue;
        return null;
      });

      // Child script: reads process.env.MY_SECRET and prints it, also prints its Base64 encoding
      const childCode = `
        const sec = process.env.MY_SECRET;
        console.log("Secret injected length: " + sec.length);
        console.log("Raw echo: " + sec);
        const b64 = Buffer.from(sec).toString('base64');
        console.log("Base64 echo: " + b64);
      `;

      const result = await runCommand({
        command: process.execPath,
        args: ["-e", childCode],
        env: {
          MY_SECRET: `{{vault:${secId}}}`,
        },
        resolver,
        captureOutput: true,
      });

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain(`Secret injected length: ${secretValue.length}`);
      // Verify raw secret was redacted from stdout
      expect(result.stdout).toContain(`Raw echo: [REDACTED:${secId}]`);
      expect(result.stdout).not.toContain(secretValue);
      // Verify base64 secret was redacted from stdout
      const expectedB64 = Buffer.from(secretValue).toString("base64");
      expect(result.stdout).toContain(`Base64 echo: [REDACTED:${secId}]`);
      expect(result.stdout).not.toContain(expectedB64);
    });

    it("injects secrets from --env-file template", async () => {
      const secId = generateEntityId("sec_");
      const secretValue = "env-file-secret-value-456";

      const envTplPath = path.join(tempDir, ".env.tpl");
      await fs.promises.writeFile(
        envTplPath,
        `APP_NAME=VaultClient\nSECRET_KEY={{vault:${secId}}}\nPORT=3000\n`,
      );

      const resolver = new SecretResolver(async (id) => {
        if (id === secId) return secretValue;
        return null;
      });

      const childCode = `
        console.log("APP: " + process.env.APP_NAME);
        console.log("PORT: " + process.env.PORT);
        console.log("SECRET: " + process.env.SECRET_KEY);
      `;

      const result = await runCommand({
        command: process.execPath,
        args: ["-e", childCode],
        envFile: envTplPath,
        resolver,
        captureOutput: true,
      });

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("APP: VaultClient");
      expect(result.stdout).toContain("PORT: 3000");
      expect(result.stdout).toContain(`SECRET: [REDACTED:${secId}]`);
      expect(result.stdout).not.toContain(secretValue);
    });
  });

  describe("llm-vault inject (Zero-File Template Injection)", () => {
    it("renders template into ephemeral in-memory FIFO and serves to child process", async () => {
      const secId = generateEntityId("sec_");
      const secretValue = "database-master-password-789";

      const templatePath = path.join(tempDir, "config.json.tpl");
      await fs.promises.writeFile(
        templatePath,
        JSON.stringify({
          database: {
            host: "postgres.internal",
            password: `{{vault:${secId}}}`,
          },
        }),
      );

      const resolver = new SecretResolver(async (id) => {
        if (id === secId) return secretValue;
        return null;
      });

      // Child script: reads FIFO path from VAULT_CONFIG_FIFO, parses JSON, and logs password
      const childCode = `
        const fs = require('fs');
        const net = require('net');
        const fifoPath = process.env.VAULT_CONFIG_FIFO;
        
        async function readPipe(p) {
          if (process.platform === 'win32') {
            return new Promise((resolve, reject) => {
              const client = net.connect(p, () => {});
              let data = '';
              client.on('data', chunk => data += chunk.toString('utf-8'));
              client.on('end', () => resolve(data));
              client.on('error', err => reject(err));
            });
          }
          return fs.promises.readFile(p, 'utf-8');
        }

        readPipe(fifoPath).then(content => {
          const cfg = JSON.parse(content);
          console.log("Config read successfully. Password: " + cfg.database.password);
        }).catch(err => {
          console.error(err);
          process.exit(1);
        });
      `;

      const result = await injectTemplate({
        templatePath,
        command: process.execPath,
        args: ["-e", childCode],
        resolver,
        captureOutput: true,
      });

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain(`Config read successfully. Password: [REDACTED:${secId}]`);
      expect(result.stdout).not.toContain(secretValue);
    });
  });

  describe("CLI Entrypoint Commands", () => {
    it("handles --help and --version", async () => {
      let output = "";
      const originalLog = console.log;
      console.log = (msg: string) => {
        output += msg;
      };

      try {
        const helpCode = await main(["--help"]);
        expect(helpCode).toBe(0);
        expect(output).toContain("llm-vault - Developer CLI");

        output = "";
        const versionCode = await main(["--version"]);
        expect(versionCode).toBe(0);
        expect(output).toContain("llm-vault CLI v0.1.0");
      } finally {
        console.log = originalLog;
      }
    });

    it("handles login, status, and logout flows", async () => {
      const prevSessionFile = process.env.LLM_VAULT_SESSION_FILE;
      process.env.LLM_VAULT_SESSION_FILE = sessionFile;

      let logs: string[] = [];
      const originalLog = console.log;
      console.log = (msg: string) => {
        logs.push(msg);
      };

      try {
        // 1. Initial status -> no session
        const status1 = await main(["status"]);
        expect(status1).toBe(1);

        // 2. Login
        const loginCode = await main([
          "login",
          "--endpoint",
          "http://localhost:3000",
          "--token",
          "tok_test_jwt",
          "--tenant",
          "tnt_corp",
          "--actor",
          "usr_engineer",
        ]);
        expect(loginCode).toBe(0);

        // 3. Status -> active session
        logs = [];
        const status2 = await main(["status"]);
        expect(status2).toBe(0);
        expect(logs.some((l) => l.includes("usr_engineer"))).toBe(true);

        // 4. Logout
        const logoutCode = await main(["logout"]);
        expect(logoutCode).toBe(0);
        expect(await loadSession(sessionFile)).toBeNull();
      } finally {
        console.log = originalLog;
        if (prevSessionFile) {
          process.env.LLM_VAULT_SESSION_FILE = prevSessionFile;
        } else {
          delete process.env.LLM_VAULT_SESSION_FILE;
        }
      }
    });
  });

  describe("Slice 9: Pre-Commit Secret Scanner & Repository Migration", () => {
    describe("Shannon Entropy & Secret Redaction", () => {
      it("calculates lower entropy for repetitive patterns and high entropy for cryptographic tokens", () => {
        const repetitive = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const highEntropy = "7fA9bK2pLmQ8vX4zRwT1yU3eI5oN6";
        const low = calculateShannonEntropy(repetitive);
        const high = calculateShannonEntropy(highEntropy);

        expect(low).toBe(0);
        expect(high).toBeGreaterThan(4.0);
      });

      it("redacts secrets with leading and trailing preservation or masking", () => {
        expect(redactSecret("sk-proj-1234567890abcdefghijklmnop")).toMatch(/^sk-p\*\*\*\*mnop$/);
        expect(redactSecret("short")).toBe("********");
        expect(redactSecret("")).toBe("[REDACTED]");
      });
    });

    describe("Static Credential Scanner (scanContent & scanWorkspace)", () => {
      it("detects multiple provider credential formats in source code and config", () => {
        const mockSlack = [
          "xoxb",
          "123456789012",
          "1234567890123",
          "abcdefghijklmnopqrstuvwx",
        ].join("-");
        const mockStripe = ["sk", "test", "51AbCdEfGhIjKlMnOpQrStUvWxYz1234"].join("_");
        const mockOpenAi = ["sk", "proj", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"].join("-");
        const mockAnthropic = ["sk", "ant", "api03", "abcdefghijklmnopqrstuvwxyz0123456789"].join(
          "-",
        );
        const mockGithub = ["ghp", "1234567890abcdefghijklmnopqrstuvwxyz"].join("_");
        const fixture = [
          "// Configuration constants",
          `const openAiKey = "${mockOpenAi}";`,
          `const anthropicKey = "${mockAnthropic}";`,
          'const geminiKey = "AIzaSyD-ExampleGoogleGeminiApiKey1234";',
          'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
          `const githubPat = "${mockGithub}";`,
          `const slackToken = "${mockSlack}";`,
          `const stripeKey = "${mockStripe}";`,
          'const dbUrl = "postgres://app_user:s3cr3t_p4ssw0rd@db.internal:5432/production";',
          "-----BEGIN PRIVATE KEY-----",
          "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7...",
          "-----END PRIVATE KEY-----",
          "// Already vaulted token should be ignored:",
          'const safeToken = "{{vault:sec_01jk9876543210}}";',
        ].join("\n");

        const findings = scanContent(fixture, "src/config.ts");
        expect(findings.length).toBeGreaterThanOrEqual(8);

        const rulesFound = findings.map((f) => f.ruleId);
        expect(rulesFound).toContain("openai-api-key");
        expect(rulesFound).toContain("anthropic-api-key");
        expect(rulesFound).toContain("google-gemini-key");
        expect(rulesFound).toContain("aws-access-key-id");
        expect(rulesFound).toContain("github-token");
        expect(rulesFound).toContain("slack-token");
        expect(rulesFound).toContain("stripe-secret-key");
        expect(rulesFound).toContain("database-url");
        expect(rulesFound).toContain("private-key");

        // Verify suggested handle prefix
        for (const f of findings) {
          expect(f.suggestedHandle).toMatch(/^\{\{vault:sec_[0-9a-zA-Z]{26}\}\}$/);
          expect(f.redactedValue).toContain("****");
        }
      });

      it("recursively scans directory workspace ignoring binary and excluded directories", async () => {
        const subDir = path.join(tempDir, "workspace");
        fs.mkdirSync(subDir, { recursive: true });

        // Valid file with secret
        fs.writeFileSync(
          path.join(subDir, "app.ts"),
          'const key = "sk-proj-VerySecretKey1234567890abcdefgh";\n',
        );

        // Binary file with simulated null byte
        fs.writeFileSync(
          path.join(subDir, "logo.png"),
          Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x0a, 0x1a, 0x0a]),
        );

        // File in ignored directory (.git / node_modules)
        const nodeModulesDir = path.join(subDir, "node_modules", "pkg");
        fs.mkdirSync(nodeModulesDir, { recursive: true });
        fs.writeFileSync(
          path.join(nodeModulesDir, "index.js"),
          'const leaked = "sk-proj-LeakedInNodeModules12345678";\n',
        );

        const result = await scanWorkspace({ directory: subDir });
        expect(result.scannedFiles).toBe(1); // Only app.ts (logo.png binary, node_modules ignored)
        expect(result.findingsCount).toBe(1);
        expect(result.clean).toBe(false);
        expect(result.findings[0]?.ruleId).toBe("openai-api-key");
      });
    });

    describe("Repository Ingestion & Template Absorption (absorbFile)", () => {
      it("previews absorption in dry-run mode without modifying filesystem", async () => {
        const envFile = path.join(tempDir, ".env");
        const envContent = [
          "# Production credentials",
          "OPENAI_API_KEY=sk-proj-ProductionSecretKey1234567890abcdef",
          "DATABASE_URL=postgres://admin:topsecret12345@db.prod:5432/main",
        ].join("\n");
        fs.writeFileSync(envFile, envContent);

        const result = await absorbFile({
          targetFile: envFile,
          dryRun: true,
        });

        expect(result.success).toBe(true);
        expect(result.dryRun).toBe(true);
        expect(result.absorbedCount).toBe(2);
        expect(result.actions).toHaveLength(2);

        // Verify filesystem was NOT modified
        expect(fs.readFileSync(envFile, "utf8")).toBe(envContent);
        expect(fs.existsSync(`${envFile}.tpl`)).toBe(false);
      });

      it("migrates .env to .env.tpl with {{vault:sec_...}} handles and updates .gitignore", async () => {
        const envFile = path.join(tempDir, ".env");
        const gitignoreFile = path.join(tempDir, ".gitignore");
        fs.writeFileSync(gitignoreFile, "node_modules/\ndist/\n");

        const mockStripeKey = ["sk", "test", "12345678901234567890abcdef"].join("_");
        const mockGithubToken = ["ghp", "1234567890abcdefghijklmnopqrstuvwxyz"].join("_");
        const envContent = [
          "# Application Keys",
          `STRIPE_SECRET_KEY=${mockStripeKey}`,
          `GITHUB_TOKEN=${mockGithubToken}`,
        ].join("\n");
        fs.writeFileSync(envFile, envContent);

        const savedSecrets: Array<{ name: string; value: string; id: string }> = [];

        // Temporarily change process.cwd for .gitignore handling
        const originalCwd = process.cwd();
        try {
          process.chdir(tempDir);

          const result = await absorbFile({
            targetFile: ".env",
            dryRun: false,
            generateTemplate: true,
            onSecretSaved: async (name, value, id) => {
              savedSecrets.push({ name, value, id });
            },
          });

          expect(result.success).toBe(true);
          expect(result.dryRun).toBe(false);
          expect(result.absorbedCount).toBe(2);
          expect(savedSecrets).toHaveLength(2);

          // Verify template was created
          const tplFile = path.join(tempDir, ".env.tpl");
          expect(fs.existsSync(tplFile)).toBe(true);
          const tplContent = fs.readFileSync(tplFile, "utf8");
          expect(tplContent).toContain("STRIPE_SECRET_KEY={{vault:sec_");
          expect(tplContent).toContain("GITHUB_TOKEN={{vault:sec_");
          expect(tplContent).toContain("# Application Keys"); // Preserved comment

          // Verify .gitignore was updated to exclude .env
          const gitignoreContent = fs.readFileSync(gitignoreFile, "utf8");
          expect(gitignoreContent).toContain(".env");
        } finally {
          process.chdir(originalCwd);
        }
      });
    });

    describe("Git Pre-Commit Hook Management", () => {
      it("installs, verifies status, and uninstalls pre-commit hook in .git repository", () => {
        const mockRepo = path.join(tempDir, "mock-repo");
        const hooksDir = path.join(mockRepo, ".git", "hooks");
        fs.mkdirSync(hooksDir, { recursive: true });

        // 1. Initial status: not installed
        const status1 = getPreCommitHookStatus(mockRepo);
        expect(status1.installed).toBe(false);

        // 2. Install hook
        const installResult = installPreCommitHook(mockRepo);
        expect(installResult.installed).toBe(true);
        expect(installResult.isLlmVaultHook).toBe(true);
        expect(installResult.executable).toBe(true);

        const hookFile = path.join(hooksDir, "pre-commit");
        expect(fs.existsSync(hookFile)).toBe(true);
        const hookScript = fs.readFileSync(hookFile, "utf8");
        expect(hookScript).toContain("llm-vault scan --staged --fail-on-found");

        // 3. Status check
        const status2 = getPreCommitHookStatus(mockRepo);
        expect(status2.installed).toBe(true);
        expect(status2.isLlmVaultHook).toBe(true);

        // 4. Uninstall hook
        const removeResult = removePreCommitHook(mockRepo);
        expect(removeResult.installed).toBe(false);
        expect(fs.existsSync(hookFile)).toBe(false);
      });
    });

    describe("CLI Commands: scan, absorb, hook", () => {
      it("executes llm-vault scan and returns 0 on clean workspace or 1 on fail-on-found", async () => {
        const cleanDir = path.join(tempDir, "clean");
        fs.mkdirSync(cleanDir);
        fs.writeFileSync(path.join(cleanDir, "clean.ts"), 'const greeting = "Hello World";\n');

        let logs: string[] = [];
        const originalLog = console.log;
        console.log = (msg: string) => logs.push(msg);

        try {
          const cleanCode = await main(["scan", "--dir", cleanDir, "--json"]);
          expect(cleanCode).toBe(0);
          const parsed = JSON.parse(logs[0]!) as { clean: boolean; findingsCount: number };
          expect(parsed.clean).toBe(true);
          expect(parsed.findingsCount).toBe(0);

          // Add a secret and test --fail-on-found
          fs.writeFileSync(
            path.join(cleanDir, "dirty.ts"),
            'const key = "sk-proj-Secret1234567890abcdefghijkl";\n',
          );
          logs = [];
          const dirtyCode = await main(["scan", "--dir", cleanDir, "--fail-on-found", "--json"]);
          expect(dirtyCode).toBe(1);
          const dirtyParsed = JSON.parse(logs[0]!) as { clean: boolean; findingsCount: number };
          expect(dirtyParsed.clean).toBe(false);
          expect(dirtyParsed.findingsCount).toBe(1);
        } finally {
          console.log = originalLog;
        }
      });

      it("executes llm-vault absorb in dry-run mode via CLI", async () => {
        const envFile = path.join(tempDir, ".env");
        fs.writeFileSync(envFile, "OPENAI_API_KEY=sk-proj-CliAbsorbTestKey1234567890abcdef\n");

        const logs: string[] = [];
        const originalLog = console.log;
        console.log = (msg: string) => logs.push(msg);

        try {
          const code = await main(["absorb", envFile, "--dry-run", "--json"]);
          expect(code).toBe(0);
          const res = JSON.parse(logs[0]!) as {
            success: boolean;
            dryRun: boolean;
            absorbedCount: number;
          };
          expect(res.success).toBe(true);
          expect(res.dryRun).toBe(true);
          expect(res.absorbedCount).toBe(1);
        } finally {
          console.log = originalLog;
        }
      });

      it("executes llm-vault hook status via CLI", async () => {
        const logs: string[] = [];
        const originalLog = console.log;
        console.log = (msg: string) => logs.push(msg);

        try {
          const code = await main(["hook", "status"]);
          expect(code === 0 || code === 1).toBe(true);
          expect(logs.some((l) => l.includes("Git Pre-Commit Hook Status"))).toBe(true);
        } finally {
          console.log = originalLog;
        }
      });
    });
  });
});
