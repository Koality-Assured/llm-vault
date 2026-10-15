import type { EncryptedEnvelope } from "@llm-vault/crypto";

export type { EncryptedEnvelope };

export interface EncryptedVaultRecord {
  id: string; // vlt_<ulid>
  name: string;
  saltHex: string;
  iterations: number;
  encryptedVaultKey: EncryptedEnvelope;
  wrappedPrivateKey?: EncryptedEnvelope | undefined;
  publicKeyFingerprint?: string | undefined;
  createdAt: string;
  updatedAt: string;
}

export interface SecretMetadataPayload {
  name: string;
  description?: string | undefined;
  tags: string[];
  customFields?: Record<string, string> | undefined;
}

export interface SecretValuePayload {
  value: string;
  notes?: string | undefined;
  customFields?: Record<string, string> | undefined;
}

export interface StoredSecretRecord {
  id: string; // sec_<ulid>
  vaultId: string; // vlt_<ulid>
  folderId?: string | undefined; // fld_<ulid>
  version: number;
  keyVersion: number;
  encryptedMetadata: EncryptedEnvelope;
  encryptedPayload: EncryptedEnvelope;
  tagBlindIndexes: string[];
  createdAt: string;
  updatedAt: string;
}

export interface StoredSecretVersion {
  secretId: string;
  version: number;
  keyVersion: number;
  encryptedMetadata: EncryptedEnvelope;
  encryptedPayload: EncryptedEnvelope;
  createdAt: string;
}

export interface DecryptedSecretItem {
  id: string;
  vaultId: string;
  folderId?: string | undefined;
  version: number;
  keyVersion: number;
  metadata: SecretMetadataPayload;
  createdAt: string;
  updatedAt: string;
}

export interface UserPreferences {
  theme: "dark" | "light";
  autoLockTimeoutMinutes: number; // e.g. 5, 15, 30, 60
  lastVaultId?: string | undefined;
}

export interface PasswordGeneratorOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
  excludeAmbiguous: boolean; // 1, l, I, 0, O, o
}

export interface PassphraseGeneratorOptions {
  wordCount: number;
  delimiter: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export interface ClipboardState {
  activeSecretId: string | null;
  secondsRemaining: number;
  totalDurationSeconds: number;
  pendingFocusPurge: boolean;
}
