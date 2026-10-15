import type {
  EncryptedVaultRecord,
  StoredSecretRecord,
  StoredSecretVersion,
  UserPreferences,
} from "../types.js";

const DB_NAME = "llm_vault_client_db";
const DB_VERSION = 1;
const PREFERENCES_STORAGE_KEY = "llm_vault_user_preferences";

let dbInstance: IDBDatabase | null = null;

export async function getIndexedDb(): Promise<IDBDatabase> {
  if (dbInstance) {
    return dbInstance;
  }

  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not supported or available in this runtime environment.");
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      if (!db.objectStoreNames.contains("vaults")) {
        db.createObjectStore("vaults", { keyPath: "id" });
      }

      if (!db.objectStoreNames.contains("secrets")) {
        const secretStore = db.createObjectStore("secrets", { keyPath: "id" });
        secretStore.createIndex("by_vault_id", "vaultId", { unique: false });
      }

      if (!db.objectStoreNames.contains("secret_versions")) {
        const versionStore = db.createObjectStore("secret_versions", {
          keyPath: ["secretId", "version"],
        });
        versionStore.createIndex("by_secret_id", "secretId", { unique: false });
      }
    };

    request.onsuccess = () => {
      dbInstance = request.result;
      resolve(dbInstance);
    };

    request.onerror = () => {
      reject(request.error ?? new Error("Failed to open IndexedDB"));
    };
  });
}

// ---------------------------------------------------------------------------
// Vault Persistence
// ---------------------------------------------------------------------------

export async function saveVaultRecord(record: EncryptedVaultRecord): Promise<void> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("vaults", "readwrite");
    const store = tx.objectStore("vaults");
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function getVaultRecord(id: string): Promise<EncryptedVaultRecord | null> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("vaults", "readonly");
    const store = tx.objectStore("vaults");
    const req = store.get(id);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

export async function listVaultRecords(): Promise<EncryptedVaultRecord[]> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("vaults", "readonly");
    const store = tx.objectStore("vaults");
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result ?? []);
    req.onerror = () => reject(req.error);
  });
}

export async function deleteVaultRecord(id: string): Promise<void> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(["vaults", "secrets", "secret_versions"], "readwrite");
    const vaultStore = tx.objectStore("vaults");
    vaultStore.delete(id);

    const secretStore = tx.objectStore("secrets");
    const secretIndex = secretStore.index("by_vault_id");
    const secretsReq = secretIndex.getAllKeys(id);

    secretsReq.onsuccess = () => {
      const secretIds = secretsReq.result;
      for (const secretId of secretIds) {
        secretStore.delete(secretId);
      }
    };

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------------
// Secret Persistence
// ---------------------------------------------------------------------------

export async function saveSecretRecord(record: StoredSecretRecord): Promise<void> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(["secrets", "secret_versions"], "readwrite");
    const store = tx.objectStore("secrets");
    store.put(record);

    const versionStore = tx.objectStore("secret_versions");
    const versionRecord: StoredSecretVersion = {
      secretId: record.id,
      version: record.version,
      keyVersion: record.keyVersion,
      encryptedMetadata: record.encryptedMetadata,
      encryptedPayload: record.encryptedPayload,
      createdAt: record.updatedAt,
    };
    versionStore.put(versionRecord);

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getSecretRecord(id: string): Promise<StoredSecretRecord | null> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("secrets", "readonly");
    const store = tx.objectStore("secrets");
    const req = store.get(id);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

export async function listSecretRecords(vaultId: string): Promise<StoredSecretRecord[]> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("secrets", "readonly");
    const store = tx.objectStore("secrets");
    const index = store.index("by_vault_id");
    const req = index.getAll(vaultId);
    req.onsuccess = () => resolve(req.result ?? []);
    req.onerror = () => reject(req.error);
  });
}

export async function deleteSecretRecord(id: string): Promise<void> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(["secrets", "secret_versions"], "readwrite");
    const store = tx.objectStore("secrets");
    store.delete(id);

    const versionStore = tx.objectStore("secret_versions");
    const index = versionStore.index("by_secret_id");
    const keysReq = index.getAllKeys(id);
    keysReq.onsuccess = () => {
      for (const key of keysReq.result) {
        versionStore.delete(key);
      }
    };

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function listSecretVersions(secretId: string): Promise<StoredSecretVersion[]> {
  const db = await getIndexedDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("secret_versions", "readonly");
    const store = tx.objectStore("secret_versions");
    const index = store.index("by_secret_id");
    const req = index.getAll(secretId);
    req.onsuccess = () => {
      const records = (req.result ?? []) as StoredSecretVersion[];
      records.sort((a, b) => b.version - a.version);
      resolve(records);
    };
    req.onerror = () => reject(req.error);
  });
}

// ---------------------------------------------------------------------------
// localStorage Preference Controls (Strict Non-Sensitive Enforcement)
// ---------------------------------------------------------------------------

const DEFAULT_PREFERENCES: UserPreferences = {
  theme: "dark",
  autoLockTimeoutMinutes: 15,
};

export function getUserPreferences(): UserPreferences {
  if (typeof localStorage === "undefined") {
    return DEFAULT_PREFERENCES;
  }

  try {
    const raw = localStorage.getItem(PREFERENCES_STORAGE_KEY);
    if (!raw) {
      return DEFAULT_PREFERENCES;
    }
    const parsed = JSON.parse(raw) as Partial<UserPreferences>;
    return {
      theme: parsed.theme === "light" ? "light" : "dark",
      autoLockTimeoutMinutes:
        typeof parsed.autoLockTimeoutMinutes === "number" && parsed.autoLockTimeoutMinutes > 0
          ? parsed.autoLockTimeoutMinutes
          : 15,
      ...(parsed.lastVaultId ? { lastVaultId: String(parsed.lastVaultId) } : {}),
    };
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

export function saveUserPreferences(prefs: UserPreferences): void {
  if (typeof localStorage === "undefined") {
    return;
  }

  // Cryptographic Invariant Guard: Assert that no sensitive keys or payloads are stored in localStorage
  const sanitized: UserPreferences = {
    theme: prefs.theme === "light" ? "light" : "dark",
    autoLockTimeoutMinutes: Math.max(1, Math.min(120, prefs.autoLockTimeoutMinutes)),
    ...(prefs.lastVaultId ? { lastVaultId: String(prefs.lastVaultId) } : {}),
  };

  const payload = JSON.stringify(sanitized);
  if (payload.includes("password") || payload.includes("ciphertext") || payload.includes("sec_")) {
    throw new Error("Security violation: Refusing to write sensitive secret data to localStorage.");
  }

  localStorage.setItem(PREFERENCES_STORAGE_KEY, payload);
}
