import * as fs from "node:fs";
import type { SecretResolver } from "./resolver.js";
import { createMemoryFifo, type MemoryFifo } from "./fifo.js";
import { runCommand, type RunCommandResult } from "./runner.js";

export interface InjectOptions {
  templatePath: string;
  command: string;
  args?: string[] | undefined;
  envVarName?: string | undefined;
  resolver: SecretResolver;
  cwd?: string | undefined;
  captureOutput?: boolean | undefined;
  streamOutput?: boolean | undefined;
  extraEnv?: Record<string, string | undefined> | undefined;
}

export interface InjectResult extends RunCommandResult {
  fifoPath: string;
}

/**
 * Renders a configuration template containing {{vault:...}} references in memory
 * and serves it via an ephemeral zero-file in-memory FIFO (Named Pipe on Windows / POSIX FIFO)
 * to a child command without writing plaintext secrets to disk.
 */
export async function injectTemplate(options: InjectOptions): Promise<InjectResult> {
  const {
    templatePath,
    command,
    args = [],
    envVarName = "VAULT_CONFIG_FIFO",
    resolver,
    cwd,
    captureOutput,
    streamOutput,
    extraEnv = {},
  } = options;

  if (!fs.existsSync(templatePath)) {
    throw new Error(`Template file not found at path: "${templatePath}"`);
  }

  const rawTemplate = await fs.promises.readFile(templatePath, "utf-8");
  const renderedContent = await resolver.resolveString(rawTemplate);

  let fifo: MemoryFifo | null = null;
  try {
    fifo = await createMemoryFifo(renderedContent);

    // Merge FIFO path into environment and replace any {{FIFO_PATH}} placeholders in args
    const injectedEnv: Record<string, string | undefined> = {
      ...extraEnv,
      [envVarName]: fifo.path,
    };

    const substitutedArgs = args.map((arg) =>
      arg.includes("{{FIFO_PATH}}") ? arg.split("{{FIFO_PATH}}").join(fifo!.path) : arg,
    );

    const result = await runCommand({
      command,
      args: substitutedArgs,
      env: injectedEnv,
      resolver,
      cwd,
      captureOutput,
      streamOutput,
    });

    return {
      ...result,
      fifoPath: fifo.path,
    };
  } finally {
    if (fifo) {
      await fifo.close();
    }
  }
}
