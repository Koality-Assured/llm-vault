import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import type { EncryptedVaultRecord, StoredSecretRecord } from "../types.js";
import {
  deleteSecretRecord,
  deleteVaultRecord,
  getSecretRecord,
  getUserPreferences,
  getVaultRecord,
  listSecretRecords,
  listSecretVersions,
  listVaultRecords,
  saveSecretRecord,
  saveUserPreferences,
  saveVaultRecord,
} from "./storage.js";

// Mock localStorage for preference testing
const localStore = new Map<string, string>();
const mockLocalStorage = {
  getItem: (key: string) => localStore.get(key) ?? null,
  setItem: (key: string, val: string) => {
    localStore.set(key, val);
  },
  removeItem: (key: string) => {
    localStore.delete(key);
  },
  clear: () => {
    localStore.clear();
  },
  key: (index: number) => Array.from(localStore.keys())[index] ?? null,
  get length() {
    return localStore.size;
  },
};

Object.defineProperty(globalThis, "localStorage", {
  value: mockLocalStorage,
  writable: true,
  configurable: true,
});

describe("storage", () => {
  beforeEach(() => {
    localStore.clear();
  });

  describe("user preferences (localStorage)", () => {
    it("returns default preferences if none are saved", () => {
      const prefs = getUserPreferences();
      expect(prefs).toEqual({
        theme: "dark",
        autoLockTimeoutMinutes: 15,
      });
    });

    it("saves and retrieves valid non-sensitive preferences", () => {
      saveUserPreferences({
        theme: "light",
        autoLockTimeoutMinutes: 30,
        lastVaultId: "vlt_01jk9876543210abcdefghjkmn",
      });

      const prefs = getUserPreferences();
      expect(prefs).toEqual({
        theme: "light",
        autoLockTimeoutMinutes: 30,
        lastVaultId: "vlt_01jk9876543210abcdefghjkmn",
      });
    });

    it("clamps autoLockTimeoutMinutes between 1 and 120", () => {
      saveUserPreferences({
        theme: "dark",
        autoLockTimeoutMinutes: 9999,
      });
      expect(getUserPreferences().autoLockTimeoutMinutes).toBe(120);

      saveUserPreferences({
        theme: "dark",
        autoLockTimeoutMinutes: 0,
      });
      expect(getUserPreferences().autoLockTimeoutMinutes).toBe(1);
    });

    it("throws a security error if attempting to save sensitive strings to localStorage", () => {
      expect(() => {
        saveUserPreferences({
          theme: "dark",
          autoLockTimeoutMinutes: 15,
          lastVaultId: "sec_forbidden_secret_id",
        });
      }).toThrow(/Security violation/);

      expect(() => {
        saveUserPreferences({
          theme: "dark",
          autoLockTimeoutMinutes: 15,
          lastVaultId: "my_password_leak",
        });
      }).toThrow(/Security violation/);
    });
  });

  describe("vault persistence (IndexedDB)", () => {
    const mockVault: EncryptedVaultRecord = {
      id: "vlt_01test00000000000000000001",
      name: "Engineering Production",
      saltHex: "aabbccddeeff",
      iterations: 600000,
      encryptedVaultKey: {
        algorithm: "AES-256-GCM",
        ciphertext: "base64_ct",
        iv: "base64_iv",
        authTag: "base64_tag",
        aad: "base64_aad",
        keyVersion: 1,
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    it("saves, retrieves, and lists encrypted vault records", async () => {
      await saveVaultRecord(mockVault);

      const retrieved = await getVaultRecord(mockVault.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.name).toBe("Engineering Production");

      const all = await listVaultRecords();
      expect(all.length).toBeGreaterThanOrEqual(1);
      expect(all.some((v) => v.id === mockVault.id)).toBe(true);
    });

    it("deletes a vault record and its cascaded secrets", async () => {
      const vaultId = "vlt_01delete0000000000000001";
      await saveVaultRecord({
        ...mockVault,
        id: vaultId,
      });

      const secretId = "sec_01delete0000000000000001";
      await saveSecretRecord({
        id: secretId,
        vaultId,
        version: 1,
        keyVersion: 1,
        encryptedMetadata: mockVault.encryptedVaultKey,
        encryptedPayload: mockVault.encryptedVaultKey,
        tagBlindIndexes: ["tag1"],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      expect(await getVaultRecord(vaultId)).not.toBeNull();
      expect(await getSecretRecord(secretId)).not.toBeNull();

      await deleteVaultRecord(vaultId);

      expect(await getVaultRecord(vaultId)).toBeNull();
      expect(await getSecretRecord(secretId)).toBeNull();
    });
  });

  describe("secret persistence and versioning (IndexedDB)", () => {
    const vaultId = "vlt_01secrets0000000000000001";
    const secretId = "sec_01secrets0000000000000001";

    const baseRecord: StoredSecretRecord = {
      id: secretId,
      vaultId,
      version: 1,
      keyVersion: 1,
      encryptedMetadata: {
        algorithm: "AES-256-GCM",
        ciphertext: "meta_ct_1",
        iv: "meta_iv_1",
        authTag: "meta_tag_1",
        aad: "meta_aad_1",
        keyVersion: 1,
      },
      encryptedPayload: {
        algorithm: "AES-256-GCM",
        ciphertext: "pay_ct_1",
        iv: "pay_iv_1",
        authTag: "pay_tag_1",
        aad: "pay_aad_1",
        keyVersion: 1,
      },
      tagBlindIndexes: ["tag_idx_1"],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    it("saves and retrieves secrets, and tracks version history monotonically", async () => {
      await saveSecretRecord(baseRecord);

      const fetched = await getSecretRecord(secretId);
      expect(fetched?.version).toBe(1);
      expect(fetched?.encryptedPayload.ciphertext).toBe("pay_ct_1");

      // Save version 2
      await saveSecretRecord({
        ...baseRecord,
        version: 2,
        encryptedPayload: {
          ...baseRecord.encryptedPayload,
          ciphertext: "pay_ct_2",
        },
        updatedAt: new Date().toISOString(),
      });

      const fetchedV2 = await getSecretRecord(secretId);
      expect(fetchedV2?.version).toBe(2);
      expect(fetchedV2?.encryptedPayload.ciphertext).toBe("pay_ct_2");

      // Check version history
      const versions = await listSecretVersions(secretId);
      expect(versions.length).toBe(2);
      expect(versions[0]?.version).toBe(2);
      expect(versions[1]?.version).toBe(1);

      // List secrets in vault
      const inVault = await listSecretRecords(vaultId);
      expect(inVault.length).toBe(1);
      expect(inVault[0]?.id).toBe(secretId);

      // Delete secret and verify versions are also purged
      await deleteSecretRecord(secretId);
      expect(await getSecretRecord(secretId)).toBeNull();
      const afterDeleteVersions = await listSecretVersions(secretId);
      expect(afterDeleteVersions.length).toBe(0);
    });
  });
});
