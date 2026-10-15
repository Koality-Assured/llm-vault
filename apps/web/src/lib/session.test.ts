import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createNewVault,
  createSecretItem,
  getActiveSession,
  lockVaultSession,
  revealSecretPayload,
  unlockVault,
} from "./session.js";

describe("session", () => {
  const listeners: Record<string, ((event?: unknown) => void)[]> = {};

  beforeEach(() => {
    // Mock minimal DOM listeners for session activity & visibility
    const mockWindow = {
      addEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (!listeners[type]) listeners[type] = [];
        listeners[type]?.push(listener);
      },
      removeEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (listeners[type]) {
          listeners[type] = listeners[type]?.filter((l) => l !== listener);
        }
      },
    };

    const mockDocument = {
      visibilityState: "visible",
      addEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (!listeners[type]) listeners[type] = [];
        listeners[type]?.push(listener);
      },
      removeEventListener: (type: string, listener: (event?: unknown) => void) => {
        if (listeners[type]) {
          listeners[type] = listeners[type]?.filter((l) => l !== listener);
        }
      },
    };

    Object.defineProperty(globalThis, "window", {
      value: mockWindow,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(globalThis, "document", {
      value: mockDocument,
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    lockVaultSession();
  });

  it("creates a vault and unlocks a zero-knowledge session", async () => {
    const vault = await createNewVault("Engineering Vault", "Master-Passphrase-123!", 600_000, 15);
    expect(vault.id).toMatch(/^vlt_/);
    expect(vault.name).toBe("Engineering Vault");

    const session = await unlockVault(vault.id, "Master-Passphrase-123!");
    expect(session.vaultId).toBe(vault.id);
    expect(session.vaultKeyBytes.length).toBe(32);
    expect(getActiveSession()).not.toBeNull();
  });

  it("zeroizes raw symmetric key bytes in memory when locked", async () => {
    const vault = await createNewVault("Zeroize Vault", "Key-Zeroize-Test-999!", 600_000, 15);
    const session = await unlockVault(vault.id, "Key-Zeroize-Test-999!");

    // Keep reference to underlying key buffer
    const keyBytesRef = session.vaultKeyBytes;
    expect(keyBytesRef.some((b) => b !== 0)).toBe(true);

    lockVaultSession();

    // Verify all bytes have been wiped with 0
    expect(keyBytesRef.every((b) => b === 0)).toBe(true);
    expect(getActiveSession()).toBeNull();
  });

  it("creates and reveals secret on-demand with zeroizable cleanup callback", async () => {
    const vault = await createNewVault("Secrets Vault", "Secrets-Passphrase-456!", 600_000, 15);
    const session = await unlockVault(vault.id, "Secrets-Passphrase-456!");

    const secret = await createSecretItem(session, {
      name: "Stripe API Key",
      value: "sk_live_1234567890abcdef",
      description: "Production Stripe billing key",
      notes: "Rotate every 90 days",
      tags: ["billing", "stripe", "prod"],
    });

    expect(secret.id).toMatch(/^sec_/);
    expect(secret.encryptedMetadata).toBeDefined();
    expect(secret.encryptedPayload).toBeDefined();

    const { payload, cleanup } = await revealSecretPayload(session, secret.id);
    expect(payload.value).toBe("sk_live_1234567890abcdef");
    expect(payload.notes).toBe("Rotate every 90 days");

    // Cleanup should execute cleanly without error
    expect(() => cleanup()).not.toThrow();
  });

  it("automatically locks the session and zeroizes memory when tab is hidden", async () => {
    const vault = await createNewVault("AutoLock Vault", "Autolock-Passphrase-789!", 600_000, 15);
    const session = await unlockVault(vault.id, "Autolock-Passphrase-789!");

    const keyBytesRef = session.vaultKeyBytes;
    expect(keyBytesRef.some((b) => b !== 0)).toBe(true);

    // Simulate tab backgrounding (visibilityState = "hidden")
    (document as { visibilityState: string }).visibilityState = "hidden";
    for (const listener of listeners["visibilitychange"] ?? []) {
      listener();
    }

    expect(getActiveSession()).toBeNull();
    expect(keyBytesRef.every((b) => b === 0)).toBe(true);
  });
});
