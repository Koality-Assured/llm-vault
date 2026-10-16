import fs from "node:fs";
import path from "node:path";

export interface SidecarSecretFile {
  secretId: string;
  outputFilename: string;
  content: string;
  permissions?: string | undefined;
}

export interface SidecarSyncOptions {
  mountPath: string;
  secrets: SidecarSecretFile[];
  inMemoryVolume?: boolean | undefined;
  cleanStaleFiles?: boolean | undefined;
}

export interface SidecarSyncResult {
  syncedCount: number;
  writtenFiles: string[];
  cleanedFiles: string[];
  timestamp: string;
}

export interface SidecarDaemonOptions {
  mountPath: string;
  intervalSeconds?: number | undefined;
  inMemoryVolume?: boolean | undefined;
  fetchSecrets: () => Promise<SidecarSecretFile[]>;
  onSync?: ((result: SidecarSyncResult) => void) | undefined;
  onError?: ((error: Error) => void) | undefined;
}

export interface SidecarDaemonInstance {
  stop(): void;
  forceSync(): Promise<SidecarSyncResult>;
}

export function sanitizeFilename(filename: string, mountDir?: string): string {
  if (!filename || !filename.trim()) {
    throw new Error("Invalid output filename: filename cannot be empty");
  }
  const trimmed = filename.trim();
  if (trimmed.includes("..") || path.isAbsolute(trimmed)) {
    throw new Error(`Invalid output filename (directory traversal blocked): ${filename}`);
  }
  const normalized = path.normalize(trimmed);
  if (normalized.startsWith("..") || path.isAbsolute(normalized) || normalized === ".") {
    throw new Error(`Invalid output filename (directory traversal blocked): ${filename}`);
  }
  if (mountDir) {
    const resolvedMount = path.resolve(mountDir);
    const resolvedTarget = path.resolve(resolvedMount, normalized);
    if (!resolvedTarget.startsWith(resolvedMount + path.sep)) {
      throw new Error(`Invalid output filename (directory traversal blocked): ${filename}`);
    }
  }
  return normalized;
}

export async function syncSecretsToVolume(options: SidecarSyncOptions): Promise<SidecarSyncResult> {
  const mountDir = path.resolve(options.mountPath);

  // Ensure volume directory exists with 0700 permissions
  if (!fs.existsSync(mountDir)) {
    fs.mkdirSync(mountDir, { recursive: true, mode: 0o700 });
  } else {
    try {
      fs.chmodSync(mountDir, 0o700);
    } catch {
      // ignore on systems where chmod 0700 on dir is not supported
    }
  }

  const writtenFiles: string[] = [];
  const validFilePaths = new Set<string>();

  for (const item of options.secrets) {
    const safeName = sanitizeFilename(item.outputFilename, mountDir);
    const destPath = path.join(mountDir, safeName);
    const targetDir = path.dirname(destPath);

    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });
    }

    // Atomic write via temp file
    const tempPath = `${destPath}.tmp.${Date.now()}`;
    const fileMode = item.permissions ? Number.parseInt(item.permissions, 8) : 0o600;

    fs.writeFileSync(tempPath, item.content, { mode: fileMode, encoding: "utf8" });
    try {
      fs.chmodSync(tempPath, fileMode);
    } catch {
      // ignore
    }

    fs.renameSync(tempPath, destPath);
    try {
      fs.chmodSync(destPath, fileMode);
    } catch {
      // ignore
    }

    writtenFiles.push(destPath);
    validFilePaths.add(destPath);
  }

  const cleanedFiles: string[] = [];
  if (options.cleanStaleFiles) {
    const collectFiles = (dir: string): string[] => {
      let results: string[] = [];
      if (!fs.existsSync(dir)) return results;
      const entries = fs.readdirSync(dir);
      for (const entry of entries) {
        const fullPath = path.join(dir, entry);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          results = results.concat(collectFiles(fullPath));
        } else {
          results.push(fullPath);
        }
      }
      return results;
    };

    const allExistingFiles = collectFiles(mountDir);
    for (const fullPath of allExistingFiles) {
      if (!validFilePaths.has(fullPath)) {
        fs.unlinkSync(fullPath);
        cleanedFiles.push(fullPath);
      }
    }

    const pruneEmptyDirs = (dir: string) => {
      if (!fs.existsSync(dir) || dir === mountDir) return;
      const files = fs.readdirSync(dir);
      if (files.length === 0) {
        try {
          fs.rmdirSync(dir);
        } catch {
          // ignore
        }
        pruneEmptyDirs(path.dirname(dir));
      }
    };

    for (const cleanedPath of cleanedFiles) {
      pruneEmptyDirs(path.dirname(cleanedPath));
    }
  }

  return {
    syncedCount: writtenFiles.length,
    writtenFiles,
    cleanedFiles,
    timestamp: new Date().toISOString(),
  };
}

export function startSidecarDaemon(options: SidecarDaemonOptions): SidecarDaemonInstance {
  const intervalSeconds = Math.max(1, options.intervalSeconds ?? 30);
  let timer: NodeJS.Timeout | null = null;
  let running = true;

  const runSync = async (): Promise<SidecarSyncResult> => {
    try {
      const secrets = await options.fetchSecrets();
      const result = await syncSecretsToVolume({
        mountPath: options.mountPath,
        secrets,
        inMemoryVolume: options.inMemoryVolume,
        cleanStaleFiles: true,
      });
      options.onSync?.(result);
      return result;
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      options.onError?.(error);
      throw error;
    }
  };

  // Run initial sync asynchronously
  void runSync();

  // Schedule periodic refresh
  timer = setInterval(() => {
    if (!running) return;
    void runSync();
  }, intervalSeconds * 1000);

  return {
    stop(): void {
      running = false;
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
    async forceSync(): Promise<SidecarSyncResult> {
      return runSync();
    },
  };
}
