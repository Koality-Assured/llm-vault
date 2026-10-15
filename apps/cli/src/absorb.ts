import * as fs from "node:fs";
import * as path from "node:path";
import { generateEntityId } from "@llm-vault/ids";
import type { AbsorbAction, AbsorbSecretsResponse } from "@llm-vault/schema";
import { scanContent } from "./scanner.js";

export interface AbsorbOptions {
  targetFile: string;
  dryRun?: boolean | undefined;
  inPlace?: boolean | undefined;
  generateTemplate?: boolean | undefined;
  vaultId?: string | undefined;
  tenantId?: string | undefined;
  endpoint?: string | undefined;
  token?: string | undefined;
  onSecretSaved?: ((name: string, value: string, secId: string) => Promise<void>) | undefined;
}

export async function absorbFile(options: AbsorbOptions): Promise<AbsorbSecretsResponse> {
  const filePath = path.resolve(process.cwd(), options.targetFile);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Target file does not exist: "${filePath}"`);
  }

  const content = fs.readFileSync(filePath, "utf8");
  const relativePath = path.relative(process.cwd(), filePath).replace(/\\/g, "/");
  const findings = scanContent(content, relativePath);

  if (findings.length === 0) {
    return {
      success: true,
      dryRun: Boolean(options.dryRun),
      vaultId: options.vaultId,
      absorbedCount: 0,
      actions: [],
    };
  }

  const actions: AbsorbAction[] = [];
  let updatedContent = content;
  const isEnvFile = path.basename(filePath).startsWith(".env");
  const templatePath = isEnvFile ? `${filePath}.tpl` : undefined;

  // Process unique secrets to avoid duplicate replacement issues
  const processedValues = new Set<string>();

  for (const finding of findings) {
    if (processedValues.has(finding.rawValue)) continue;
    processedValues.add(finding.rawValue);

    // Derive secret name from the line (e.g. KEY=VALUE)
    const lineStr = content.split(/\r?\n/)[finding.line - 1] ?? "";
    const keyMatch = /^([A-Za-z0-9_-]+)\s*[:=]/.exec(lineStr.trim());
    const secretName = keyMatch ? keyMatch[1]! : `${finding.ruleId}_${path.basename(filePath)}`;

    const secId = generateEntityId("sec_");
    const handle = `{{vault:${secId}}}`;

    actions.push({
      filePath: relativePath,
      line: finding.line,
      secretName,
      secretId: secId,
      handle,
      templatePath: templatePath
        ? path.relative(process.cwd(), templatePath).replace(/\\/g, "/")
        : undefined,
      replaced: !options.dryRun,
    });

    // Replace all occurrences of this exact secret value in the content
    updatedContent = updatedContent.split(finding.rawValue).join(handle);

    // If caller provided callback to persist secret to vault
    if (!options.dryRun && options.onSecretSaved) {
      await options.onSecretSaved(secretName, finding.rawValue, secId);
    }
  }

  if (!options.dryRun) {
    if (isEnvFile && options.generateTemplate !== false) {
      // Write to .env.tpl
      const targetTpl = templatePath ?? `${filePath}.tpl`;
      fs.writeFileSync(targetTpl, updatedContent, "utf8");

      // Ensure original .env file is in .gitignore
      ensureGitIgnored(path.basename(filePath));

      if (options.inPlace) {
        fs.writeFileSync(filePath, updatedContent, "utf8");
      }
    } else {
      // Overwrite file in place
      fs.writeFileSync(filePath, updatedContent, "utf8");
    }
  }

  return {
    success: true,
    dryRun: Boolean(options.dryRun),
    vaultId: options.vaultId,
    absorbedCount: actions.length,
    actions,
  };
}

function ensureGitIgnored(filename: string): void {
  const gitignorePath = path.resolve(process.cwd(), ".gitignore");
  try {
    if (fs.existsSync(gitignorePath)) {
      const gitignore = fs.readFileSync(gitignorePath, "utf8");
      const lines = gitignore.split(/\r?\n/).map((l) => l.trim());
      if (
        !lines.includes(filename) &&
        !lines.includes(`/${filename}`) &&
        !lines.includes("*.env")
      ) {
        fs.appendFileSync(gitignorePath, `\n# llm-vault absorbed secrets\n${filename}\n`);
      }
    } else {
      fs.writeFileSync(gitignorePath, `# llm-vault absorbed secrets\n${filename}\n`, "utf8");
    }
  } catch {
    // Ignore .gitignore modification errors
  }
}
