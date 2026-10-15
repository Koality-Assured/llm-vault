import * as fs from "node:fs";
import * as path from "node:path";
import type { PreCommitHookStatus } from "@llm-vault/schema";

const HOOK_MARKER = "# llm-vault pre-commit secret scanner";

const HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER}
# Blocks unencrypted credentials from git staging.

echo "[llm-vault] Running pre-commit secret scan on staged files..."

if command -v llm-vault >/dev/null 2>&1; then
  llm-vault scan --staged --fail-on-found
  EXIT_CODE=$?
elif [ -f "./node_modules/.bin/llm-vault" ]; then
  ./node_modules/.bin/llm-vault scan --staged --fail-on-found
  EXIT_CODE=$?
elif command -v npx >/dev/null 2>&1; then
  npx --no-install @llm-vault/cli scan --staged --fail-on-found
  EXIT_CODE=$?
else
  echo "[llm-vault] Notice: llm-vault CLI not installed globally; proceeding."
  exit 0
fi

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "[llm-vault] ERROR: Unencrypted credentials detected in staged files!"
  echo "[llm-vault] Run 'llm-vault absorb <file>' to migrate them to {{vault:sec_...}} handles,"
  echo "[llm-vault] or unstage sensitive files before committing."
  echo ""
  exit 1
fi

exit 0
`;

export function getGitHooksDir(rootDir = process.cwd()): string | null {
  const gitDir = path.resolve(rootDir, ".git");
  if (!fs.existsSync(gitDir)) return null;

  const stat = fs.statSync(gitDir);
  if (stat.isDirectory()) {
    return path.join(gitDir, "hooks");
  }

  // Worktree or git submodule: .git is a file containing "gitdir: ..."
  try {
    const gitFileContent = fs.readFileSync(gitDir, "utf8");
    const match = /gitdir:\s*(.+)/.exec(gitFileContent);
    if (match && match[1]) {
      const resolvedGitDir = path.resolve(rootDir, match[1].trim());
      return path.join(resolvedGitDir, "hooks");
    }
  } catch {
    // Ignore read errors
  }

  return null;
}

export function getPreCommitHookStatus(rootDir = process.cwd()): PreCommitHookStatus {
  const hooksDir = getGitHooksDir(rootDir);
  if (!hooksDir) {
    return {
      installed: false,
      hookPath: "",
      executable: false,
      isLlmVaultHook: false,
    };
  }

  const hookPath = path.join(hooksDir, "pre-commit");
  if (!fs.existsSync(hookPath)) {
    return {
      installed: false,
      hookPath,
      executable: false,
      isLlmVaultHook: false,
    };
  }

  try {
    const content = fs.readFileSync(hookPath, "utf8");
    const isLlmVaultHook = content.includes(HOOK_MARKER);
    const stats = fs.statSync(hookPath);
    // Check if executable bit is set (or true on Windows)
    const executable = process.platform === "win32" || Boolean(stats.mode & 0o111);

    return {
      installed: true,
      hookPath,
      executable,
      isLlmVaultHook,
    };
  } catch {
    return {
      installed: false,
      hookPath,
      executable: false,
      isLlmVaultHook: false,
    };
  }
}

export function installPreCommitHook(rootDir = process.cwd()): PreCommitHookStatus {
  const hooksDir = getGitHooksDir(rootDir);
  if (!hooksDir) {
    throw new Error(
      `Cannot install git hook: Not a git repository (no .git directory found at ${rootDir})`,
    );
  }

  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const hookPath = path.join(hooksDir, "pre-commit");

  // If a non-llm-vault pre-commit hook exists, backup or chain it
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, "utf8");
    if (!existing.includes(HOOK_MARKER)) {
      // Append our check to existing hook
      const chained = `${existing.trim()}\n\n# Chained llm-vault hook\n${HOOK_SCRIPT}\n`;
      fs.writeFileSync(hookPath, chained, { encoding: "utf8", mode: 0o755 });
    }
  } else {
    fs.writeFileSync(hookPath, HOOK_SCRIPT, { encoding: "utf8", mode: 0o755 });
  }

  try {
    fs.chmodSync(hookPath, 0o755);
  } catch {
    // Windows chmod may be no-op
  }

  return getPreCommitHookStatus(rootDir);
}

export function removePreCommitHook(rootDir = process.cwd()): PreCommitHookStatus {
  const status = getPreCommitHookStatus(rootDir);
  if (!status.installed || !status.hookPath) {
    return status;
  }

  try {
    const content = fs.readFileSync(status.hookPath, "utf8");
    if (content.trim() === HOOK_SCRIPT.trim()) {
      fs.unlinkSync(status.hookPath);
    } else if (content.includes(HOOK_MARKER)) {
      // Remove only the llm-vault script block
      const lines = content.split(/\r?\n/);
      const filtered = lines.filter((line) => !line.includes("llm-vault"));
      fs.writeFileSync(status.hookPath, filtered.join("\n"), { encoding: "utf8", mode: 0o755 });
    }
  } catch {
    // Ignore removal error
  }

  return getPreCommitHookStatus(rootDir);
}
