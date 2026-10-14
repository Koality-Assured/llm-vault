import { describe, expect, it } from "vitest";

import { generateEntityId } from "@llm-vault/ids";

import {
  GENESIS_AUDIT_EVENT_HASH,
  MIN_PBKDF2_ITERATIONS,
  base64ToBytes,
  buildCanonicalAad,
  bytesToBase64,
  computeAuditEventHash,
  computeTagBlindIndex,
  createArgon2idKdfProvider,
  decryptSecretMetadata,
  decryptSecretPayload,
  decryptWithAad,
  deriveMasterKeyMaterial,
  deriveMasterSubkeys,
  deriveVaultSearchKey,
  encryptSecretMetadata,
  encryptSecretPayload,
  encryptWithAad,
  formatCanonicalAadString,
  generateAgentDecryptionKey,
  generateSalt,
  generateUserKeyPairs,
  generateVaultKey,
  generateVaultKeyBytes,
  signAuditOrKeyPayload,
  unwrapUserPrivateKey,
  unwrapVaultKeyForAgent,
  unwrapVaultKeyFromSender,
  verifyAuditHashChain,
  verifyPayloadSignature,
  wrapUserPrivateKey,
  wrapVaultKeyForAgent,
  wrapVaultKeyForRecipient,
  zeroizeBuffer,
} from "./index.js";

describe("@llm-vault/crypto", () => {
  it("stretches master passphrases via PBKDF2-HMAC-SHA256 (600,000+ iterations) and separates HKDF-SHA256 subkeys", async () => {
    const salt = generateSalt();
    expect(salt.byteLength).toBe(32);

    await expect(
      deriveMasterKeyMaterial("correct-horse-battery-staple", salt, 100_000),
    ).rejects.toThrow(RangeError);

    await expect(
      deriveMasterKeyMaterial(
        "correct-horse-battery-staple",
        new Uint8Array(16),
        MIN_PBKDF2_ITERATIONS,
      ),
    ).rejects.toThrow(RangeError);

    const subkeys1 = await deriveMasterSubkeys(
      "correct-horse-battery-staple",
      salt,
      MIN_PBKDF2_ITERATIONS,
    );
    const subkeys2 = await deriveMasterSubkeys(
      "correct-horse-battery-staple",
      salt,
      MIN_PBKDF2_ITERATIONS,
    );

    expect(subkeys1.masterEncryptionKey.extractable).toBe(false);
    expect(subkeys1.masterEncryptionKey.algorithm).toMatchObject({
      name: "AES-GCM",
      length: 256,
    });
    expect(subkeys1.clientAuthKey.byteLength).toBe(32);
    expect(subkeys1.clientAuthKeyHex).toHaveLength(64);
    expect(subkeys1.clientAuthKeyHex).toBe(subkeys2.clientAuthKeyHex);

    // Non-extractable MasterEncryptionKey must reject exportKey
    await expect(
      globalThis.crypto.subtle.exportKey("raw", subkeys1.masterEncryptionKey),
    ).rejects.toThrow();
  });

  it("supports extensible WASM Argon2id KDF provider", async () => {
    const salt = generateSalt();
    const argon2Provider = createArgon2idKdfProvider({
      memoryKiB: 16_384,
      iterations: 2,
      parallelism: 2,
    });

    const subkeys = await deriveMasterSubkeys(
      "argon2id-vault-passphrase",
      salt,
      MIN_PBKDF2_ITERATIONS,
      argon2Provider,
    );

    expect(subkeys.masterEncryptionKey.extractable).toBe(false);
    expect(subkeys.clientAuthKey.byteLength).toBe(32);
  });

  it("encrypts and decrypts payloads with AES-256-GCM and canonical AAD, rejecting any AAD or ciphertext tampering", async () => {
    const vaultKey = await generateVaultKey();
    const aadContext = {
      tenantId: "tnt_enterprise_01",
      vaultId: generateEntityId("vlt_"),
      secretId: generateEntityId("sec_"),
      version: 1,
      keyVersion: 1,
    };

    const aadBytes = buildCanonicalAad(aadContext);
    expect(new TextDecoder().decode(aadBytes)).toBe(
      `${aadContext.tenantId}:${aadContext.vaultId}:${aadContext.secretId}:1:1`,
    );

    const rawPlaintext = new TextEncoder().encode("raw-secret-bytes");
    const rawEnvelope = await encryptWithAad(vaultKey, rawPlaintext, aadContext);
    expect(await decryptWithAad(vaultKey, rawEnvelope, aadContext)).toEqual(rawPlaintext);

    const metadata = {
      name: "PRODUCTION_STRIPE_SECRET_KEY",
      description: "Primary billing API credential",
      tags: ["stripe", "billing", "prod"],
    };
    const payload = {
      value: "rk_test_FAKE_DO_NOT_USE_0123456789abcdef",
      notes: "Rotate every 30 days via MCP",
      customFields: { environment: "production" },
    };

    const encryptedMeta = await encryptSecretMetadata(vaultKey, metadata, aadContext);
    const encryptedPayload = await encryptSecretPayload(vaultKey, payload, aadContext);

    // Fresh IVs per encryption operation
    expect(encryptedMeta.iv).not.toBe(encryptedPayload.iv);
    expect(base64ToBytes(encryptedMeta.iv).byteLength).toBe(12);
    expect(base64ToBytes(encryptedMeta.authTag).byteLength).toBe(16);

    const decryptedMeta = await decryptSecretMetadata(vaultKey, encryptedMeta, aadContext);
    const decryptedPayload = await decryptSecretPayload(vaultKey, encryptedPayload, aadContext);

    expect(decryptedMeta).toEqual(metadata);
    expect(decryptedPayload).toEqual(payload);

    // Reject cross-secret AAD transplant
    await expect(
      decryptSecretPayload(vaultKey, encryptedPayload, {
        ...aadContext,
        secretId: generateEntityId("sec_"),
      }),
    ).rejects.toThrow();

    // Reject version rollback / mismatch even if envelope.aad string is forged
    const forgedEnvelope = {
      ...encryptedPayload,
      aad: formatCanonicalAadString({ ...aadContext, version: 2 }),
    };
    await expect(
      decryptWithAad(vaultKey, forgedEnvelope, {
        ...aadContext,
        version: 2,
      }),
    ).rejects.toThrow();

    // Reject tampered ciphertext bytes
    const rawCipher = base64ToBytes(encryptedPayload.ciphertext);
    rawCipher[0] = (rawCipher[0]! ^ 0xff) & 0xff;
    await expect(
      decryptWithAad(
        vaultKey,
        {
          ...encryptedPayload,
          ciphertext: bytesToBase64(rawCipher),
        },
        aadContext,
      ),
    ).rejects.toThrow();
  });

  it("wraps user private keys, shares VaultKey via X25519 + HKDF-SHA256, and signs/verifies with Ed25519", async () => {
    const salt = generateSalt();
    const { masterEncryptionKey } = await deriveMasterSubkeys("alice-master-passphrase", salt);

    const aliceKeys = await generateUserKeyPairs();
    const bobKeys = await generateUserKeyPairs();

    expect(aliceKeys.publicKeyFingerprint).toHaveLength(64);
    expect(aliceKeys.publicKeyFingerprint).not.toBe(bobKeys.publicKeyFingerprint);

    const wrappedAlicePriv = await wrapUserPrivateKey(
      aliceKeys.x25519.privateKeyPkcs8,
      masterEncryptionKey,
    );
    const unwrappedAlicePriv = await unwrapUserPrivateKey(wrappedAlicePriv, masterEncryptionKey);
    expect(unwrappedAlicePriv).toEqual(aliceKeys.x25519.privateKeyPkcs8);

    // Share a 256-bit VaultKey from Alice to Bob
    const vaultId = generateEntityId("vlt_");
    const vaultKeyBytes = generateVaultKeyBytes();

    const wrappedForBob = await wrapVaultKeyForRecipient(
      vaultKeyBytes,
      unwrappedAlicePriv,
      bobKeys.x25519.publicKeyBase64,
      vaultId,
      1,
    );

    const bobUnwrappedVaultKey = await unwrapVaultKeyFromSender(
      wrappedForBob,
      bobKeys.x25519.privateKeyPkcs8,
      aliceKeys.x25519.publicKeyBase64,
      vaultId,
      1,
    );
    expect(bobUnwrappedVaultKey).toEqual(vaultKeyBytes);

    // Reject unwrapping for a different vaultId or keyVersion
    await expect(
      unwrapVaultKeyFromSender(
        wrappedForBob,
        bobKeys.x25519.privateKeyPkcs8,
        aliceKeys.x25519.publicKeyBase64,
        vaultId,
        2,
      ),
    ).rejects.toThrow();

    // Ed25519 signature verification
    const message = new TextEncoder().encode(`grant:${vaultId}:${bobKeys.publicKeyFingerprint}`);
    const sig = await signAuditOrKeyPayload(aliceKeys.ed25519.privateKey, message);
    expect(await verifyPayloadSignature(aliceKeys.ed25519.publicKeyBase64, message, sig)).toBe(
      true,
    );
    expect(await verifyPayloadSignature(bobKeys.ed25519.publicKeyBase64, message, sig)).toBe(false);
  });

  it("delegates and unwraps AgentEncryptedVaultKey for autonomous agents", async () => {
    const agentId = generateEntityId("agt_");
    const vaultId = generateEntityId("vlt_");
    const vaultKeyBytes = generateVaultKeyBytes();
    const agentDecryptionKey = generateAgentDecryptionKey();

    const wrapped = await wrapVaultKeyForAgent(
      vaultKeyBytes,
      agentDecryptionKey,
      agentId,
      vaultId,
      1,
    );

    const unwrapped = await unwrapVaultKeyForAgent(
      wrapped,
      agentDecryptionKey,
      agentId,
      vaultId,
      1,
    );
    expect(unwrapped).toEqual(vaultKeyBytes);

    // Reject wrong agentId
    await expect(
      unwrapVaultKeyForAgent(wrapped, agentDecryptionKey, generateEntityId("agt_"), vaultId, 1),
    ).rejects.toThrow();
  });

  it("computes domain-separated HMAC-SHA256 tag blind indexes and verifies hash-chained audit logs", async () => {
    const vaultKeyA = generateVaultKeyBytes();
    const vaultKeyB = generateVaultKeyBytes();

    const searchKeyA = await deriveVaultSearchKey(vaultKeyA);
    const searchKeyB = await deriveVaultSearchKey(vaultKeyB);

    const idxA1 = await computeTagBlindIndex(searchKeyA, "  Production ");
    const idxA2 = await computeTagBlindIndex(searchKeyA, "production");
    const idxB = await computeTagBlindIndex(searchKeyB, "production");

    expect(idxA1).toBe(idxA2);
    expect(idxA1).toHaveLength(64);
    expect(idxA1).not.toBe(idxB);

    // Audit hash chain verification
    const auditKey = generateVaultKeyBytes();
    const event1Json = JSON.stringify({
      action: "secrets:create",
      actorId: "usr_01jk7a89b2c3d4e5f6g7h8j9k3",
      targetId: "sec_01jk7a89b2c3d4e5f6g7h8j9k0",
    });
    const hash1 = await computeAuditEventHash(auditKey, GENESIS_AUDIT_EVENT_HASH, event1Json);

    const event2Json = JSON.stringify({
      action: "secrets:reveal",
      actorId: "agt_01jk7a89b2c3d4e5f6g7h8j9k4",
      targetId: "sec_01jk7a89b2c3d4e5f6g7h8j9k0",
    });
    const hash2 = await computeAuditEventHash(auditKey, hash1, event2Json);

    const chain = [
      {
        id: generateEntityId("aud_"),
        prevEventHash: GENESIS_AUDIT_EVENT_HASH,
        eventHash: hash1,
        canonicalEventJson: event1Json,
      },
      {
        id: generateEntityId("aud_"),
        prevEventHash: hash1,
        eventHash: hash2,
        canonicalEventJson: event2Json,
      },
    ];

    const verification = await verifyAuditHashChain(chain, auditKey);
    expect(verification.valid).toBe(true);

    // Tamper with first event JSON
    const tamperedChain = [
      {
        ...chain[0]!,
        canonicalEventJson: JSON.stringify({
          action: "secrets:read",
          actorId: "usr_01jk7a89b2c3d4e5f6g7h8j9k3",
          targetId: "sec_01jk7a89b2c3d4e5f6g7h8j9k0",
        }),
      },
      chain[1]!,
    ];

    const tamperedResult = await verifyAuditHashChain(tamperedChain, auditKey);
    expect(tamperedResult.valid).toBe(false);
    expect(tamperedResult.failedEventId).toBe(chain[0]!.id);
  });

  it("zeroizes Uint8Array and ArrayBuffer instances in place", () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 255]);
    zeroizeBuffer(bytes);
    expect(Array.from(bytes)).toEqual([0, 0, 0, 0, 0]);

    const ab = new Uint8Array([9, 8, 7, 6]).buffer;
    zeroizeBuffer(ab);
    expect(Array.from(new Uint8Array(ab))).toEqual([0, 0, 0, 0]);
  });
});
