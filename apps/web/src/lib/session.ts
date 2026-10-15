import {
  computePublicKeyFingerprint,
  computeTagBlindIndex,
  decryptSecretMetadata,
  decryptSecretPayload,
  deriveMasterSubkeys,
  deriveVaultSearchKey,
  encryptSecretMetadata,
  encryptSecretPayload,
  encryptWithAad,
  decryptWithAad,
  generateUserKeyPairs,
  generateVaultKeyBytes,
  wrapUserPrivateKey,
  zeroizeBuffer,
} from "@llm-vault/crypto";
import { generateEntityId } from "@llm-vault/ids";
import type {
  DecryptedSecretItem,
  EncryptedVaultRecord,
  SecretMetadataPayload,
  SecretValuePayload,
  StoredSecretRecord,
} from "../types.js";
import {
  deleteSecretRecord,
  getSecretRecord,
  getVaultRecord,
  listSecretRecords,
  listSecretVersions,
  saveSecretRecord,
  saveVaultRecord,
} from "./storage.js";

export type SessionListener = (session: VaultSessionState | null) => void;

export interface VaultSessionState {
  vaultId: string;
  vaultName: string;
  vaultKeyBytes: Uint8Array;
  vaultSearchKey: CryptoKey;
  iterations: number;
  unlockedAt: number;
  lastActiveAt: number;
  autoLockMinutes: number;
}

let activeSession: VaultSessionState | null = null;
const sessionListeners = new Set<SessionListener>();
let inactivityInterval: ReturnType<typeof setInterval> | null = null;
let lastBoundWindow: unknown = null;

function notifySessionListeners(): void {
  for (const listener of sessionListeners) {
    listener(activeSession ? { ...activeSession } : null);
  }
}

function recordActivity(): void {
  if (activeSession) {
    activeSession.lastActiveAt = Date.now();
  }
}

function initActivityListeners(): void {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return;
  }
  if (lastBoundWindow === window) {
    return;
  }

  const events = ["pointerdown", "keydown", "scroll", "touchstart"];
  for (const event of events) {
    window.addEventListener(event, recordActivity, { passive: true });
  }

  // Automatic lock trigger on tab background / visibility change
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      lockVaultSession();
    }
  });

  // Zeroize memory on beforeunload
  window.addEventListener("beforeunload", () => {
    lockVaultSession();
  });

  lastBoundWindow = window;
}

export function subscribeVaultSession(listener: SessionListener): () => void {
  initActivityListeners();
  sessionListeners.add(listener);
  listener(activeSession ? { ...activeSession } : null);
  return () => {
    sessionListeners.delete(listener);
  };
}

export function getActiveSession(): VaultSessionState | null {
  return activeSession ? { ...activeSession } : null;
}

export function lockVaultSession(): void {
  if (inactivityInterval) {
    clearInterval(inactivityInterval);
    inactivityInterval = null;
  }

  if (activeSession) {
    // Cryptographic Invariant: In-place memory zeroization of raw symmetric key bytes
    zeroizeBuffer(activeSession.vaultKeyBytes);
    activeSession = null;
    notifySessionListeners();
  }
}

function startInactivityCheck(): void {
  if (inactivityInterval) {
    clearInterval(inactivityInterval);
  }

  inactivityInterval = setInterval(() => {
    if (!activeSession) return;
    const elapsedMinutes = (Date.now() - activeSession.lastActiveAt) / 60000;
    if (elapsedMinutes >= activeSession.autoLockMinutes) {
      lockVaultSession();
    }
  }, 5000);
}

// ---------------------------------------------------------------------------
// Vault Initialization & Unlock
// ---------------------------------------------------------------------------

export async function createNewVault(
  vaultName: string,
  passphrase: string,
  iterations: number = 600_000,
  autoLockMinutes: number = 15,
): Promise<EncryptedVaultRecord> {
  const vaultId = generateEntityId("vlt_");
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);

  const { masterEncryptionKey } = await deriveMasterSubkeys(passphrase, salt, iterations);

  const vaultKeyBytes = generateVaultKeyBytes();
  const vaultSearchKey = await deriveVaultSearchKey(vaultKeyBytes);

  // Generate asymmetric keypairs for sharing
  const userKeyPairs = await generateUserKeyPairs();
  const publicKeyFingerprint = await computePublicKeyFingerprint(
    userKeyPairs.x25519.publicKeyBase64,
    userKeyPairs.ed25519.publicKeyBase64,
  );

  const rawPrivateKeyBuffer = (await crypto.subtle.exportKey(
    "pkcs8",
    userKeyPairs.x25519.privateKey,
  )) as ArrayBuffer;
  const rawPrivateKeyBytes = new Uint8Array(rawPrivateKeyBuffer);
  const wrappedKeyBlob = await wrapUserPrivateKey(rawPrivateKeyBytes, masterEncryptionKey);
  zeroizeBuffer(rawPrivateKeyBytes);

  const wrappedPrivateKey = {
    algorithm: "AES-256-GCM" as const,
    ciphertext: wrappedKeyBlob.ciphertext,
    iv: wrappedKeyBlob.iv,
    authTag: wrappedKeyBlob.authTag,
    aad: wrappedKeyBlob.aad,
    keyVersion: 1,
  };

  // Wrap personal VaultKey with MasterEncryptionKey with canonical AAD
  const keyWrapAadContext = {
    tenantId: "local",
    vaultId,
    secretId: "key",
    version: 1,
    keyVersion: 1,
  };

  const encryptedVaultKey = await encryptWithAad(
    masterEncryptionKey,
    vaultKeyBytes,
    keyWrapAadContext,
  );

  const now = new Date().toISOString();
  const vaultRecord: EncryptedVaultRecord = {
    id: vaultId,
    name: vaultName.trim() || "Personal Vault",
    saltHex: Array.from(salt)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
    iterations,
    encryptedVaultKey,
    wrappedPrivateKey,
    publicKeyFingerprint,
    createdAt: now,
    updatedAt: now,
  };

  await saveVaultRecord(vaultRecord);

  // Establish active session
  activeSession = {
    vaultId,
    vaultName: vaultRecord.name,
    vaultKeyBytes,
    vaultSearchKey,
    iterations,
    unlockedAt: Date.now(),
    lastActiveAt: Date.now(),
    autoLockMinutes,
  };

  initActivityListeners();
  startInactivityCheck();
  notifySessionListeners();
  return vaultRecord;
}

export async function unlockVault(
  vaultId: string,
  passphrase: string,
  autoLockMinutes: number = 15,
): Promise<VaultSessionState> {
  const record = await getVaultRecord(vaultId);
  if (!record) {
    throw new Error(`Vault with ID ${vaultId} was not found.`);
  }

  const saltBytes = new Uint8Array(
    record.saltHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
  );

  const { masterEncryptionKey } = await deriveMasterSubkeys(
    passphrase,
    saltBytes,
    record.iterations,
  );

  // Unwrap VaultKey with canonical AAD
  const keyWrapAadContext = {
    tenantId: "local",
    vaultId,
    secretId: "key",
    version: 1,
    keyVersion: 1,
  };

  let vaultKeyBytes: Uint8Array;
  try {
    vaultKeyBytes = await decryptWithAad(
      masterEncryptionKey,
      record.encryptedVaultKey,
      keyWrapAadContext,
    );
  } catch {
    throw new Error("Invalid vault passphrase or corrupted vault key envelope.");
  }

  const vaultSearchKey = await deriveVaultSearchKey(vaultKeyBytes);

  activeSession = {
    vaultId,
    vaultName: record.name,
    vaultKeyBytes,
    vaultSearchKey,
    iterations: record.iterations,
    unlockedAt: Date.now(),
    lastActiveAt: Date.now(),
    autoLockMinutes,
  };

  initActivityListeners();
  startInactivityCheck();
  notifySessionListeners();
  return { ...activeSession };
}

// ---------------------------------------------------------------------------
// Secret Operations (Client-Side Encrypted CRUD)
// ---------------------------------------------------------------------------

export async function createSecretItem(
  session: VaultSessionState,
  input: {
    name: string;
    value: string;
    description?: string | undefined;
    notes?: string | undefined;
    tags?: string[] | undefined;
    customFields?: Record<string, string> | undefined;
    folderId?: string | undefined;
  },
): Promise<StoredSecretRecord> {
  const secretId = generateEntityId("sec_");
  const version = 1;
  const keyVersion = 1;

  const aadContext = {
    tenantId: "local",
    vaultId: session.vaultId,
    secretId,
    version,
    keyVersion,
  };

  const metadata: SecretMetadataPayload = {
    name: input.name.trim(),
    description: input.description?.trim(),
    tags: (input.tags ?? []).map((t) => t.trim().toLowerCase()).filter(Boolean),
    customFields: input.customFields,
  };

  const payload: SecretValuePayload = {
    value: input.value,
    notes: input.notes,
    customFields: input.customFields,
  };

  const encryptedMetadata = await encryptSecretMetadata(
    session.vaultKeyBytes,
    metadata,
    aadContext,
  );
  const encryptedPayload = await encryptSecretPayload(session.vaultKeyBytes, payload, aadContext);

  const tagBlindIndexes: string[] = [];
  for (const tag of metadata.tags) {
    const blindIndex = await computeTagBlindIndex(session.vaultSearchKey, tag);
    tagBlindIndexes.push(blindIndex);
  }

  const now = new Date().toISOString();
  const record: StoredSecretRecord = {
    id: secretId,
    vaultId: session.vaultId,
    folderId: input.folderId,
    version,
    keyVersion,
    encryptedMetadata,
    encryptedPayload,
    tagBlindIndexes,
    createdAt: now,
    updatedAt: now,
  };

  await saveSecretRecord(record);
  return record;
}

export async function updateSecretItem(
  session: VaultSessionState,
  secretId: string,
  input: {
    name: string;
    value: string;
    description?: string | undefined;
    notes?: string | undefined;
    tags?: string[] | undefined;
    customFields?: Record<string, string> | undefined;
    folderId?: string | undefined;
  },
): Promise<StoredSecretRecord> {
  const current = await getSecretRecord(secretId);
  if (!current) {
    throw new Error(`Secret ${secretId} not found.`);
  }

  const version = current.version + 1;
  const keyVersion = current.keyVersion;

  const aadContext = {
    tenantId: "local",
    vaultId: session.vaultId,
    secretId,
    version,
    keyVersion,
  };

  const metadata: SecretMetadataPayload = {
    name: input.name.trim(),
    description: input.description?.trim(),
    tags: (input.tags ?? []).map((t) => t.trim().toLowerCase()).filter(Boolean),
    customFields: input.customFields,
  };

  const payload: SecretValuePayload = {
    value: input.value,
    notes: input.notes,
    customFields: input.customFields,
  };

  const encryptedMetadata = await encryptSecretMetadata(
    session.vaultKeyBytes,
    metadata,
    aadContext,
  );
  const encryptedPayload = await encryptSecretPayload(session.vaultKeyBytes, payload, aadContext);

  const tagBlindIndexes: string[] = [];
  for (const tag of metadata.tags) {
    const blindIndex = await computeTagBlindIndex(session.vaultSearchKey, tag);
    tagBlindIndexes.push(blindIndex);
  }

  const now = new Date().toISOString();
  const record: StoredSecretRecord = {
    id: secretId,
    vaultId: session.vaultId,
    folderId: input.folderId ?? current.folderId,
    version,
    keyVersion,
    encryptedMetadata,
    encryptedPayload,
    tagBlindIndexes,
    createdAt: current.createdAt,
    updatedAt: now,
  };

  await saveSecretRecord(record);
  return record;
}

export async function rollbackSecretItem(
  session: VaultSessionState,
  secretId: string,
  targetVersion: number,
): Promise<StoredSecretRecord> {
  const current = await getSecretRecord(secretId);
  if (!current) {
    throw new Error(`Secret ${secretId} not found.`);
  }

  const versions = await listSecretVersions(secretId);
  const matched = versions.find((v) => v.version === targetVersion);
  if (!matched) {
    throw new Error(`Version ${targetVersion} for secret ${secretId} was not found.`);
  }

  // Decrypt target historical version
  const oldAad = {
    tenantId: "local",
    vaultId: session.vaultId,
    secretId,
    version: matched.version,
    keyVersion: matched.keyVersion,
  };

  const metadata = await decryptSecretMetadata(
    session.vaultKeyBytes,
    matched.encryptedMetadata,
    oldAad,
  );
  const payload = await decryptSecretPayload(
    session.vaultKeyBytes,
    matched.encryptedPayload,
    oldAad,
  );

  // Commit as monotonic new version N + 1
  return updateSecretItem(session, secretId, {
    name: metadata.name,
    value: payload.value,
    description: metadata.description,
    notes: payload.notes,
    tags: metadata.tags,
    customFields: payload.customFields,
    folderId: current.folderId,
  });
}

export async function loadDecryptedSecretList(
  session: VaultSessionState,
): Promise<DecryptedSecretItem[]> {
  const storedList = await listSecretRecords(session.vaultId);
  const results: DecryptedSecretItem[] = [];

  for (const record of storedList) {
    const aadContext = {
      tenantId: "local",
      vaultId: session.vaultId,
      secretId: record.id,
      version: record.version,
      keyVersion: record.keyVersion,
    };

    try {
      const metadata = await decryptSecretMetadata(
        session.vaultKeyBytes,
        record.encryptedMetadata,
        aadContext,
      );
      results.push({
        id: record.id,
        vaultId: record.vaultId,
        folderId: record.folderId,
        version: record.version,
        keyVersion: record.keyVersion,
        metadata: {
          name: metadata.name,
          description: metadata.description,
          tags: metadata.tags ?? [],
        },
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      });
    } catch {
      // If decryption fails due to key mismatch or corrupted AAD, report degraded entry
      results.push({
        id: record.id,
        vaultId: record.vaultId,
        folderId: record.folderId,
        version: record.version,
        keyVersion: record.keyVersion,
        metadata: {
          name: "[Corrupted or Unreadable Metadata]",
          tags: [],
        },
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      });
    }
  }

  return results;
}

export async function revealSecretPayload(
  session: VaultSessionState,
  secretId: string,
): Promise<{ payload: SecretValuePayload; cleanup: () => void }> {
  const record = await getSecretRecord(secretId);
  if (!record) {
    throw new Error(`Secret ${secretId} not found.`);
  }

  const aadContext = {
    tenantId: "local",
    vaultId: session.vaultId,
    secretId: record.id,
    version: record.version,
    keyVersion: record.keyVersion,
  };

  const payload = await decryptSecretPayload(
    session.vaultKeyBytes,
    record.encryptedPayload,
    aadContext,
  );

  return {
    payload: {
      value: payload.value,
      notes: payload.notes,
      customFields: payload.customFields,
    },
    cleanup: () => {
      // Immediate cleanup hook
      payload.value = "";
      if (payload.notes) payload.notes = "";
    },
  };
}

export async function deleteSecret(secretId: string): Promise<void> {
  await deleteSecretRecord(secretId);
}
