import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

export interface SessionData {
  endpoint: string;
  tenantId: string;
  actorId: string;
  token: string;
  agentId?: string | undefined;
  vaultId?: string | undefined;
  masterKeyHex?: string | undefined;
  expiresAt?: string | undefined;
}

/**
 * Returns the canonical cross-platform path to the session cache file.
 */
export function getDefaultSessionFilePath(): string {
  if (process.env.LLM_VAULT_SESSION_FILE) {
    return process.env.LLM_VAULT_SESSION_FILE;
  }
  const home = os.homedir();
  return path.join(home, ".llm-vault", "session.json");
}

/**
 * Ensures the session directory exists with secure permissions (0700 on POSIX).
 */
export function ensureSessionDirectory(filePath: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

/**
 * Persists session data with restricted file permissions (0600 on POSIX).
 */
export async function saveSession(data: SessionData, customPath?: string): Promise<string> {
  const targetPath = customPath ?? getDefaultSessionFilePath();
  ensureSessionDirectory(targetPath);

  const payload = JSON.stringify(data, null, 2);
  await fs.promises.writeFile(targetPath, payload, {
    encoding: "utf-8",
    mode: 0o600,
  });

  return targetPath;
}

/**
 * Loads session data from disk, validating that the file exists and is valid JSON.
 */
export async function loadSession(customPath?: string): Promise<SessionData | null> {
  const targetPath = customPath ?? getDefaultSessionFilePath();
  if (!fs.existsSync(targetPath)) {
    return null;
  }

  try {
    const raw = await fs.promises.readFile(targetPath, "utf-8");
    const parsed = JSON.parse(raw) as SessionData;
    if (!parsed || typeof parsed !== "object" || !parsed.token || !parsed.endpoint) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Clears the persisted session file.
 */
export async function clearSession(customPath?: string): Promise<boolean> {
  const targetPath = customPath ?? getDefaultSessionFilePath();
  if (fs.existsSync(targetPath)) {
    await fs.promises.unlink(targetPath);
    return true;
  }
  return false;
}

/**
 * Verifies if a session is currently active and not expired.
 */
export function isSessionValid(session: SessionData | null): boolean {
  if (!session || !session.token) {
    return false;
  }
  if (session.expiresAt) {
    const expiry = new Date(session.expiresAt).getTime();
    if (Date.now() >= expiry) {
      return false;
    }
  }
  return true;
}
