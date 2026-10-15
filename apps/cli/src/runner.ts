import { spawn, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import { SecretResolver } from "./resolver.js";
import { createStreamScrubber } from "./scrubber.js";

export interface RunCommandOptions {
  command: string;
  args?: string[] | undefined;
  env?: Record<string, string | undefined> | undefined;
  envFile?: string | undefined;
  resolver: SecretResolver;
  cwd?: string | undefined;
  captureOutput?: boolean | undefined;
  streamOutput?: boolean | undefined;
  onChildSpawn?: ((child: ChildProcess) => void) | undefined;
}

export interface RunCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  activeSecretsCount: number;
}

/**
 * Executes a child process with direct in-memory environment variable secret injection
 * and real-time stream scrubbing on stdout and stderr. Plaintext secrets are never written to disk.
 */
export async function runCommand(options: RunCommandOptions): Promise<RunCommandResult> {
  const {
    command,
    args = [],
    env = {},
    envFile,
    resolver,
    cwd = process.cwd(),
    captureOutput = true,
    streamOutput = false,
    onChildSpawn,
  } = options;

  let mergedRawEnv: Record<string, string | undefined> = { ...process.env, ...env };

  // If --env-file is specified, parse and merge variables
  if (envFile) {
    if (!fs.existsSync(envFile)) {
      throw new Error(`Environment template file not found: "${envFile}"`);
    }
    const content = await fs.promises.readFile(envFile, "utf-8");
    const parsedFileEnv = SecretResolver.parseDotenv(content);
    mergedRawEnv = { ...mergedRawEnv, ...parsedFileEnv };
  }

  // Resolve all {{vault:...}} references in memory
  const { resolvedEnv, activeSecrets } = await resolver.resolveEnv(mergedRawEnv);

  let capturedStdout = "";
  let capturedStderr = "";

  const stdoutScrubber = createStreamScrubber(activeSecrets, (chunk) => {
    if (captureOutput) {
      capturedStdout += chunk;
    }
    if (streamOutput) {
      process.stdout.write(chunk);
    }
  });

  const stderrScrubber = createStreamScrubber(activeSecrets, (chunk) => {
    if (captureOutput) {
      capturedStderr += chunk;
    }
    if (streamOutput) {
      process.stderr.write(chunk);
    }
  });

  try {
    const exitCode = await new Promise<number>((resolve, reject) => {
      const child = spawn(command, args, {
        cwd,
        env: resolvedEnv,
        stdio: ["inherit", "pipe", "pipe"],
      });

      if (onChildSpawn) {
        onChildSpawn(child);
      }

      child.stdout?.on("data", (data: Buffer | string) => {
        stdoutScrubber.write(data);
      });

      child.stderr?.on("data", (data: Buffer | string) => {
        stderrScrubber.write(data);
      });

      child.on("error", (err) => {
        reject(err);
      });

      child.on("close", (code) => {
        stdoutScrubber.flush();
        stderrScrubber.flush();
        resolve(code ?? 0);
      });
    });

    return {
      exitCode,
      stdout: capturedStdout,
      stderr: capturedStderr,
      activeSecretsCount: activeSecrets.length,
    };
  } finally {
    // In-memory zeroization of all revealed secrets
    resolver.zeroizeAll();
  }
}
