import { argon2id } from "hash-wasm";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const MIN_PBKDF2_ITERATIONS = 600_000;
export const MASTER_SALT_BYTES = 32;
export const AES_GCM_KEY_BYTES = 32;
export const AES_GCM_IV_BYTES = 12;
export const AES_GCM_TAG_BYTES = 16;
export const AES_GCM_TAG_BITS = 128;

export const HKDF_INFO_MASTER_ENCRYPTION_KEY = "llm-vault/v1/master-encryption-key";
export const HKDF_INFO_CLIENT_AUTH_KEY = "llm-vault/v1/client-auth-key";
export const HKDF_INFO_VAULT_SEARCH_KEY = "llm-vault/v1/vault-search-key";

export interface Argon2idParams {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export const DEFAULT_ARGON2ID_PARAMS: Argon2idParams = {
  memoryKiB: 65_536,
  iterations: 3,
  parallelism: 4,
};

export interface KdfProvider {
  readonly algorithm: "PBKDF2-HMAC-SHA256" | "Argon2id";
  deriveKeyBytes(passphrase: string | Uint8Array, salt: Uint8Array): Promise<Uint8Array>;
}

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
}

export function base64ToBytes(base64: string): Uint8Array {
  const buf = Buffer.from(base64, "base64");
  const out = new Uint8Array(buf.byteLength);
  out.set(buf);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("hex");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hexadecimal string");
  }
  const buf = Buffer.from(hex, "hex");
  const out = new Uint8Array(buf.byteLength);
  out.set(buf);
  return out;
}

export function zeroizeBuffer(buffer: Uint8Array | ArrayBuffer): void {
  if (buffer instanceof Uint8Array) {
    buffer.fill(0);
    return;
  }
  new Uint8Array(buffer).fill(0);
}

export function generateSalt(byteLength: number = MASTER_SALT_BYTES): Uint8Array {
  if (!Number.isInteger(byteLength) || byteLength < MASTER_SALT_BYTES) {
    throw new RangeError(
      `Salt length must be at least ${MASTER_SALT_BYTES} bytes, received ${byteLength}`,
    );
  }
  const salt = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(salt);
  return salt;
}

function assertSalt(salt: Uint8Array): void {
  if (salt.byteLength < MASTER_SALT_BYTES) {
    throw new RangeError(
      `Master key derivation requires at least a ${MASTER_SALT_BYTES}-byte salt, received ${salt.byteLength} bytes`,
    );
  }
}

function normalizePassphraseBytes(passphrase: string | Uint8Array): Uint8Array {
  const bytes =
    typeof passphrase === "string" ? textEncoder.encode(passphrase) : new Uint8Array(passphrase);
  if (bytes.byteLength === 0) {
    throw new Error("Passphrase must not be empty");
  }
  return bytes;
}

export function createPbkdf2KdfProvider(iterations: number = MIN_PBKDF2_ITERATIONS): KdfProvider {
  if (!Number.isInteger(iterations) || iterations < MIN_PBKDF2_ITERATIONS) {
    throw new RangeError(
      `PBKDF2-HMAC-SHA256 iterations must be an integer >= ${MIN_PBKDF2_ITERATIONS}, received ${iterations}`,
    );
  }

  return {
    algorithm: "PBKDF2-HMAC-SHA256",
    async deriveKeyBytes(passphrase: string | Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
      assertSalt(salt);
      const passphraseBytes = normalizePassphraseBytes(passphrase);
      try {
        const baseKey = await globalThis.crypto.subtle.importKey(
          "raw",
          toBuffer(passphraseBytes),
          "PBKDF2",
          false,
          ["deriveBits"],
        );
        const bits = await globalThis.crypto.subtle.deriveBits(
          {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: toBuffer(salt),
            iterations,
          },
          baseKey,
          AES_GCM_KEY_BYTES * 8,
        );
        return new Uint8Array(bits);
      } finally {
        zeroizeBuffer(passphraseBytes);
      }
    },
  };
}

export function createArgon2idKdfProvider(
  params: Argon2idParams = DEFAULT_ARGON2ID_PARAMS,
): KdfProvider {
  if (params.memoryKiB < 16_384 || params.iterations < 1 || params.parallelism < 1) {
    throw new RangeError("Invalid Argon2id parameters");
  }

  return {
    algorithm: "Argon2id",
    async deriveKeyBytes(passphrase: string | Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
      assertSalt(salt);
      const passphraseBytes = normalizePassphraseBytes(passphrase);
      try {
        const derived = await argon2id({
          password: passphraseBytes,
          salt,
          parallelism: params.parallelism,
          iterations: params.iterations,
          memorySize: params.memoryKiB,
          hashLength: AES_GCM_KEY_BYTES,
          outputType: "binary",
        });
        const out = new Uint8Array(derived.byteLength);
        out.set(derived);
        return out;
      } finally {
        zeroizeBuffer(passphraseBytes);
      }
    },
  };
}

export async function deriveMasterKeyMaterial(
  passphrase: string | Uint8Array,
  salt: Uint8Array,
  iterations: number = MIN_PBKDF2_ITERATIONS,
  kdfProvider?: KdfProvider,
): Promise<Uint8Array> {
  const provider = kdfProvider ?? createPbkdf2KdfProvider(iterations);
  return provider.deriveKeyBytes(passphrase, salt);
}

export interface DerivedMasterSubkeys {
  masterEncryptionKey: CryptoKey;
  clientAuthKey: Uint8Array;
  clientAuthKeyHex: string;
}

export async function deriveMasterSubkeys(
  passphrase: string | Uint8Array,
  salt: Uint8Array,
  iterations: number = MIN_PBKDF2_ITERATIONS,
  kdfProvider?: KdfProvider,
): Promise<DerivedMasterSubkeys> {
  const ikm = await deriveMasterKeyMaterial(passphrase, salt, iterations, kdfProvider);
  try {
    const hkdfKey = await globalThis.crypto.subtle.importKey("raw", toBuffer(ikm), "HKDF", false, [
      "deriveKey",
      "deriveBits",
    ]);

    const masterEncryptionKey = await globalThis.crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: toBuffer(salt),
        info: toBuffer(textEncoder.encode(HKDF_INFO_MASTER_ENCRYPTION_KEY)),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false, // Non-extractable client-side KEK
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    );

    const clientAuthBits = await globalThis.crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: toBuffer(salt),
        info: toBuffer(textEncoder.encode(HKDF_INFO_CLIENT_AUTH_KEY)),
      },
      hkdfKey,
      256,
    );

    const clientAuthKey = new Uint8Array(clientAuthBits);
    return {
      masterEncryptionKey,
      clientAuthKey,
      clientAuthKeyHex: bytesToHex(clientAuthKey),
    };
  } finally {
    zeroizeBuffer(ikm);
  }
}

export interface CanonicalAadContext {
  tenantId: string;
  vaultId: string;
  secretId: string;
  version: number;
  keyVersion: number;
}

function validateAadToken(label: string, value: string): void {
  if (!value || value.trim().length === 0) {
    throw new Error(`Canonical AAD ${label} must be a non-empty string`);
  }
  if (value.includes(":")) {
    throw new Error(`Canonical AAD ${label} must not contain ":" delimiter`);
  }
}

export function formatCanonicalAadString(context: CanonicalAadContext): string {
  validateAadToken("tenantId", context.tenantId);
  validateAadToken("vaultId", context.vaultId);
  validateAadToken("secretId", context.secretId);
  if (!Number.isInteger(context.version) || context.version < 1) {
    throw new RangeError(
      `Canonical AAD version must be a positive integer, received ${context.version}`,
    );
  }
  if (!Number.isInteger(context.keyVersion) || context.keyVersion < 1) {
    throw new RangeError(
      `Canonical AAD keyVersion must be a positive integer, received ${context.keyVersion}`,
    );
  }
  return `${context.tenantId}:${context.vaultId}:${context.secretId}:${context.version}:${context.keyVersion}`;
}

export function buildCanonicalAad(context: CanonicalAadContext): Uint8Array {
  return textEncoder.encode(formatCanonicalAadString(context));
}

export function generateVaultKeyBytes(): Uint8Array {
  const bytes = new Uint8Array(AES_GCM_KEY_BYTES);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export async function generateVaultKey(extractable: boolean = true): Promise<CryptoKey> {
  return globalThis.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, extractable, [
    "encrypt",
    "decrypt",
  ]);
}

export async function importAesGcmKey(
  rawKeyBytes: Uint8Array,
  extractable: boolean = false,
): Promise<CryptoKey> {
  if (rawKeyBytes.byteLength !== AES_GCM_KEY_BYTES) {
    throw new RangeError(
      `AES-256-GCM key must be ${AES_GCM_KEY_BYTES} bytes, received ${rawKeyBytes.byteLength}`,
    );
  }
  return globalThis.crypto.subtle.importKey(
    "raw",
    toBuffer(rawKeyBytes),
    { name: "AES-GCM", length: 256 },
    extractable,
    ["encrypt", "decrypt"],
  );
}

export async function exportAesGcmKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await globalThis.crypto.subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

async function resolveAesKey(key: CryptoKey | Uint8Array): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    return importAesGcmKey(key, false);
  }
  return key;
}

export interface EncryptedEnvelope {
  algorithm: "AES-256-GCM";
  ciphertext: string;
  iv: string;
  authTag: string;
  aad: string;
  keyVersion: number;
}

export async function encryptWithAad(
  key: CryptoKey | Uint8Array,
  plaintextBytes: Uint8Array,
  aadContext: CanonicalAadContext,
): Promise<EncryptedEnvelope> {
  const cryptoKey = await resolveAesKey(key);
  const aadString = formatCanonicalAadString(aadContext);
  const aadBytes = textEncoder.encode(aadString);
  const iv = new Uint8Array(AES_GCM_IV_BYTES);
  globalThis.crypto.getRandomValues(iv);

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(aadBytes),
      tagLength: AES_GCM_TAG_BITS,
    },
    cryptoKey,
    toBuffer(plaintextBytes),
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const ciphertextLength = encryptedBytes.byteLength - AES_GCM_TAG_BYTES;
  const ciphertextBytes = encryptedBytes.subarray(0, ciphertextLength);
  const authTagBytes = encryptedBytes.subarray(ciphertextLength);

  return {
    algorithm: "AES-256-GCM",
    ciphertext: bytesToBase64(ciphertextBytes),
    iv: bytesToBase64(iv),
    authTag: bytesToBase64(authTagBytes),
    aad: aadString,
    keyVersion: aadContext.keyVersion,
  };
}

export async function decryptWithAad(
  key: CryptoKey | Uint8Array,
  envelope: EncryptedEnvelope,
  aadContext: CanonicalAadContext,
): Promise<Uint8Array> {
  if (envelope.algorithm !== "AES-256-GCM") {
    throw new Error(`Unsupported encryption algorithm: ${envelope.algorithm}`);
  }
  const expectedAad = formatCanonicalAadString(aadContext);
  if (envelope.aad !== expectedAad) {
    throw new Error(
      `Canonical AAD mismatch: expected "${expectedAad}", received "${envelope.aad}"`,
    );
  }
  if (envelope.keyVersion !== aadContext.keyVersion) {
    throw new Error(
      `Envelope keyVersion (${envelope.keyVersion}) does not match expected keyVersion (${aadContext.keyVersion})`,
    );
  }

  const iv = base64ToBytes(envelope.iv);
  if (iv.byteLength !== AES_GCM_IV_BYTES) {
    throw new Error(
      `Invalid AES-GCM IV length: expected ${AES_GCM_IV_BYTES} bytes, received ${iv.byteLength}`,
    );
  }

  const authTag = base64ToBytes(envelope.authTag);
  if (authTag.byteLength !== AES_GCM_TAG_BYTES) {
    throw new Error(
      `Invalid AES-GCM authentication tag length: expected ${AES_GCM_TAG_BYTES} bytes, received ${authTag.byteLength}`,
    );
  }

  const ciphertext = base64ToBytes(envelope.ciphertext);
  const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  combined.set(ciphertext, 0);
  combined.set(authTag, ciphertext.byteLength);

  const cryptoKey = await resolveAesKey(key);
  const aadBytes = textEncoder.encode(expectedAad);

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(aadBytes),
      tagLength: AES_GCM_TAG_BITS,
    },
    cryptoKey,
    toBuffer(combined),
  );

  return new Uint8Array(decryptedBuffer);
}

export interface SecretMetadataPlaintext {
  name: string;
  description?: string | undefined;
  tags?: string[] | undefined;
  customFieldMetadata?:
    | Array<{
        key: string;
        label?: string | undefined;
        kind?: "text" | "secret" | "url" | undefined;
      }>
    | undefined;
}

export interface SecretPayloadPlaintext {
  value: string;
  notes?: string | undefined;
  customFields?: Record<string, string> | undefined;
}

export async function encryptSecretMetadata(
  key: CryptoKey | Uint8Array,
  metadata: SecretMetadataPlaintext,
  aadContext: CanonicalAadContext,
): Promise<EncryptedEnvelope> {
  const bytes = textEncoder.encode(JSON.stringify(metadata));
  try {
    return await encryptWithAad(key, bytes, aadContext);
  } finally {
    zeroizeBuffer(bytes);
  }
}

export async function decryptSecretMetadata(
  key: CryptoKey | Uint8Array,
  envelope: EncryptedEnvelope,
  aadContext: CanonicalAadContext,
): Promise<SecretMetadataPlaintext> {
  const bytes = await decryptWithAad(key, envelope, aadContext);
  try {
    return JSON.parse(textDecoder.decode(bytes)) as SecretMetadataPlaintext;
  } finally {
    zeroizeBuffer(bytes);
  }
}

export async function encryptSecretPayload(
  key: CryptoKey | Uint8Array,
  payload: SecretPayloadPlaintext,
  aadContext: CanonicalAadContext,
): Promise<EncryptedEnvelope> {
  const bytes = textEncoder.encode(JSON.stringify(payload));
  try {
    return await encryptWithAad(key, bytes, aadContext);
  } finally {
    zeroizeBuffer(bytes);
  }
}

export async function decryptSecretPayload(
  key: CryptoKey | Uint8Array,
  envelope: EncryptedEnvelope,
  aadContext: CanonicalAadContext,
): Promise<SecretPayloadPlaintext> {
  const bytes = await decryptWithAad(key, envelope, aadContext);
  try {
    return JSON.parse(textDecoder.decode(bytes)) as SecretPayloadPlaintext;
  } finally {
    zeroizeBuffer(bytes);
  }
}

export interface UserKeyPairs {
  x25519: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    publicKeyBase64: string;
    privateKeyPkcs8: Uint8Array;
  };
  ed25519: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    publicKeyBase64: string;
    privateKeyPkcs8: Uint8Array;
  };
  publicKeyFingerprint: string;
}

export async function computePublicKeyFingerprint(
  x25519PublicKeyBase64: string,
  ed25519PublicKeyBase64: string,
): Promise<string> {
  const input = textEncoder.encode(
    `llm-vault/v1/key-fp:${x25519PublicKeyBase64}:${ed25519PublicKeyBase64}`,
  );
  const digest = await globalThis.crypto.subtle.digest("SHA-256", toBuffer(input));
  return bytesToHex(new Uint8Array(digest));
}

export async function generateUserKeyPairs(): Promise<UserKeyPairs> {
  const x25519Pair = (await globalThis.crypto.subtle.generateKey({ name: "X25519" }, true, [
    "deriveBits",
    "deriveKey",
  ])) as CryptoKeyPair;

  const ed25519Pair = (await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const x25519PublicRaw = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("raw", x25519Pair.publicKey),
  );
  const x25519PrivatePkcs8 = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("pkcs8", x25519Pair.privateKey),
  );

  const ed25519PublicRaw = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("raw", ed25519Pair.publicKey),
  );
  const ed25519PrivatePkcs8 = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("pkcs8", ed25519Pair.privateKey),
  );

  const x25519PublicKeyBase64 = bytesToBase64(x25519PublicRaw);
  const ed25519PublicKeyBase64 = bytesToBase64(ed25519PublicRaw);
  const publicKeyFingerprint = await computePublicKeyFingerprint(
    x25519PublicKeyBase64,
    ed25519PublicKeyBase64,
  );

  return {
    x25519: {
      publicKey: x25519Pair.publicKey,
      privateKey: x25519Pair.privateKey,
      publicKeyBase64: x25519PublicKeyBase64,
      privateKeyPkcs8: x25519PrivatePkcs8,
    },
    ed25519: {
      publicKey: ed25519Pair.publicKey,
      privateKey: ed25519Pair.privateKey,
      publicKeyBase64: ed25519PublicKeyBase64,
      privateKeyPkcs8: ed25519PrivatePkcs8,
    },
    publicKeyFingerprint,
  };
}

export interface WrappedKeyBlob {
  ciphertext: string;
  iv: string;
  authTag: string;
  aad: string;
}

export async function wrapUserPrivateKey(
  privateKeyBytes: Uint8Array,
  masterEncryptionKey: CryptoKey,
  aadLabel: string = "llm-vault/v1/user-private-key",
): Promise<WrappedKeyBlob> {
  const iv = new Uint8Array(AES_GCM_IV_BYTES);
  globalThis.crypto.getRandomValues(iv);
  const aadBytes = textEncoder.encode(aadLabel);

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(aadBytes),
      tagLength: AES_GCM_TAG_BITS,
    },
    masterEncryptionKey,
    toBuffer(privateKeyBytes),
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const ciphertextLength = encryptedBytes.byteLength - AES_GCM_TAG_BYTES;
  return {
    ciphertext: bytesToBase64(encryptedBytes.subarray(0, ciphertextLength)),
    iv: bytesToBase64(iv),
    authTag: bytesToBase64(encryptedBytes.subarray(ciphertextLength)),
    aad: aadLabel,
  };
}

export async function unwrapUserPrivateKey(
  wrappedBlob: WrappedKeyBlob,
  masterEncryptionKey: CryptoKey,
  expectedAadLabel: string = "llm-vault/v1/user-private-key",
): Promise<Uint8Array> {
  if (wrappedBlob.aad !== expectedAadLabel) {
    throw new Error(
      `Wrapped private key AAD mismatch: expected "${expectedAadLabel}", received "${wrappedBlob.aad}"`,
    );
  }
  const iv = base64ToBytes(wrappedBlob.iv);
  const ciphertext = base64ToBytes(wrappedBlob.ciphertext);
  const authTag = base64ToBytes(wrappedBlob.authTag);
  const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  combined.set(ciphertext, 0);
  combined.set(authTag, ciphertext.byteLength);

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(textEncoder.encode(expectedAadLabel)),
      tagLength: AES_GCM_TAG_BITS,
    },
    masterEncryptionKey,
    toBuffer(combined),
  );

  return new Uint8Array(decryptedBuffer);
}

async function resolveX25519PrivateKey(key: CryptoKey | Uint8Array): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    return globalThis.crypto.subtle.importKey("pkcs8", toBuffer(key), { name: "X25519" }, false, [
      "deriveBits",
      "deriveKey",
    ]);
  }
  return key;
}

async function resolveX25519PublicKey(key: CryptoKey | Uint8Array | string): Promise<CryptoKey> {
  if (typeof key === "string") {
    const raw = base64ToBytes(key);
    return globalThis.crypto.subtle.importKey("raw", toBuffer(raw), { name: "X25519" }, true, []);
  }
  if (key instanceof Uint8Array) {
    return globalThis.crypto.subtle.importKey("raw", toBuffer(key), { name: "X25519" }, true, []);
  }
  return key;
}

export interface RecipientWrappedVaultKey {
  encryptedVaultKey: string;
  iv: string;
  authTag: string;
  aad: string;
  keyVersion: number;
}

async function deriveSharedVaultWrappingKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  vaultId: string,
  keyVersion: number,
): Promise<CryptoKey> {
  const sharedBits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: publicKey,
    },
    privateKey,
    256,
  );
  const sharedBytes = new Uint8Array(sharedBits);
  try {
    const hkdfKey = await globalThis.crypto.subtle.importKey(
      "raw",
      toBuffer(sharedBytes),
      "HKDF",
      false,
      ["deriveKey"],
    );
    const infoBytes = textEncoder.encode(`llm-vault/v1/vault-share:${vaultId}:${keyVersion}`);
    return await globalThis.crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new ArrayBuffer(32),
        info: toBuffer(infoBytes),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    zeroizeBuffer(sharedBytes);
  }
}

export async function wrapVaultKeyForRecipient(
  vaultKeyBytes: Uint8Array,
  senderX25519PrivateKey: CryptoKey | Uint8Array,
  recipientX25519PublicKey: CryptoKey | Uint8Array | string,
  vaultId: string,
  keyVersion: number,
): Promise<RecipientWrappedVaultKey> {
  if (vaultKeyBytes.byteLength !== AES_GCM_KEY_BYTES) {
    throw new RangeError(
      `VaultKey must be ${AES_GCM_KEY_BYTES} bytes, received ${vaultKeyBytes.byteLength}`,
    );
  }
  const privKey = await resolveX25519PrivateKey(senderX25519PrivateKey);
  const pubKey = await resolveX25519PublicKey(recipientX25519PublicKey);
  const wrappingKey = await deriveSharedVaultWrappingKey(privKey, pubKey, vaultId, keyVersion);

  const aad = `vault-share:${vaultId}:${keyVersion}`;
  const iv = new Uint8Array(AES_GCM_IV_BYTES);
  globalThis.crypto.getRandomValues(iv);

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(textEncoder.encode(aad)),
      tagLength: AES_GCM_TAG_BITS,
    },
    wrappingKey,
    toBuffer(vaultKeyBytes),
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const ciphertextLength = encryptedBytes.byteLength - AES_GCM_TAG_BYTES;

  return {
    encryptedVaultKey: bytesToBase64(encryptedBytes.subarray(0, ciphertextLength)),
    iv: bytesToBase64(iv),
    authTag: bytesToBase64(encryptedBytes.subarray(ciphertextLength)),
    aad,
    keyVersion,
  };
}

export async function unwrapVaultKeyFromSender(
  wrappedRecord: RecipientWrappedVaultKey,
  recipientX25519PrivateKey: CryptoKey | Uint8Array,
  senderX25519PublicKey: CryptoKey | Uint8Array | string,
  vaultId: string,
  keyVersion: number,
): Promise<Uint8Array> {
  const expectedAad = `vault-share:${vaultId}:${keyVersion}`;
  if (wrappedRecord.aad !== expectedAad || wrappedRecord.keyVersion !== keyVersion) {
    throw new Error("Wrapped VaultKey AAD or keyVersion mismatch");
  }

  const privKey = await resolveX25519PrivateKey(recipientX25519PrivateKey);
  const pubKey = await resolveX25519PublicKey(senderX25519PublicKey);
  const wrappingKey = await deriveSharedVaultWrappingKey(privKey, pubKey, vaultId, keyVersion);

  const iv = base64ToBytes(wrappedRecord.iv);
  const ciphertext = base64ToBytes(wrappedRecord.encryptedVaultKey);
  const authTag = base64ToBytes(wrappedRecord.authTag);
  const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  combined.set(ciphertext, 0);
  combined.set(authTag, ciphertext.byteLength);

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(textEncoder.encode(expectedAad)),
      tagLength: AES_GCM_TAG_BITS,
    },
    wrappingKey,
    toBuffer(combined),
  );

  return new Uint8Array(decryptedBuffer);
}

export async function signAuditOrKeyPayload(
  ed25519PrivateKey: CryptoKey | Uint8Array,
  payloadBytes: Uint8Array,
): Promise<Uint8Array> {
  const privKey =
    ed25519PrivateKey instanceof Uint8Array
      ? await globalThis.crypto.subtle.importKey(
          "pkcs8",
          toBuffer(ed25519PrivateKey),
          { name: "Ed25519" },
          false,
          ["sign"],
        )
      : ed25519PrivateKey;

  const sig = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    privKey,
    toBuffer(payloadBytes),
  );
  return new Uint8Array(sig);
}

export async function verifyPayloadSignature(
  ed25519PublicKey: CryptoKey | Uint8Array | string,
  payloadBytes: Uint8Array,
  signatureBytes: Uint8Array,
): Promise<boolean> {
  const pubKey =
    typeof ed25519PublicKey === "string"
      ? await globalThis.crypto.subtle.importKey(
          "raw",
          toBuffer(base64ToBytes(ed25519PublicKey)),
          { name: "Ed25519" },
          false,
          ["verify"],
        )
      : ed25519PublicKey instanceof Uint8Array
        ? await globalThis.crypto.subtle.importKey(
            "raw",
            toBuffer(ed25519PublicKey),
            { name: "Ed25519" },
            false,
            ["verify"],
          )
        : ed25519PublicKey;

  return globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    pubKey,
    toBuffer(signatureBytes),
    toBuffer(payloadBytes),
  );
}

export function generateAgentDecryptionKey(): Uint8Array {
  const key = new Uint8Array(AES_GCM_KEY_BYTES);
  globalThis.crypto.getRandomValues(key);
  return key;
}

async function deriveAgentWrappingKey(
  agentDecryptionKey: Uint8Array,
  agentId: string,
  vaultId: string,
  keyVersion: number,
): Promise<CryptoKey> {
  if (agentDecryptionKey.byteLength !== AES_GCM_KEY_BYTES) {
    throw new RangeError(
      `AgentDecryptionKey must be ${AES_GCM_KEY_BYTES} bytes, received ${agentDecryptionKey.byteLength}`,
    );
  }
  const hkdfKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toBuffer(agentDecryptionKey),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const info = textEncoder.encode(
    `llm-vault/v1/agent-vault-key:${agentId}:${vaultId}:${keyVersion}`,
  );
  return globalThis.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(32),
      info: toBuffer(info),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export interface AgentWrappedVaultKey {
  agentEncryptedVaultKey: string;
  iv: string;
  authTag: string;
  aad: string;
  agentId: string;
  vaultId: string;
  keyVersion: number;
}

export async function wrapVaultKeyForAgent(
  vaultKeyBytes: Uint8Array,
  agentDecryptionKey: Uint8Array,
  agentId: string,
  vaultId: string,
  keyVersion: number,
): Promise<AgentWrappedVaultKey> {
  if (vaultKeyBytes.byteLength !== AES_GCM_KEY_BYTES) {
    throw new RangeError(
      `VaultKey must be ${AES_GCM_KEY_BYTES} bytes, received ${vaultKeyBytes.byteLength}`,
    );
  }
  const wrappingKey = await deriveAgentWrappingKey(
    agentDecryptionKey,
    agentId,
    vaultId,
    keyVersion,
  );
  const aad = `agent:${agentId}:${vaultId}:${keyVersion}`;
  const iv = new Uint8Array(AES_GCM_IV_BYTES);
  globalThis.crypto.getRandomValues(iv);

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(textEncoder.encode(aad)),
      tagLength: AES_GCM_TAG_BITS,
    },
    wrappingKey,
    toBuffer(vaultKeyBytes),
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const ciphertextLength = encryptedBytes.byteLength - AES_GCM_TAG_BYTES;

  return {
    agentEncryptedVaultKey: bytesToBase64(encryptedBytes.subarray(0, ciphertextLength)),
    iv: bytesToBase64(iv),
    authTag: bytesToBase64(encryptedBytes.subarray(ciphertextLength)),
    aad,
    agentId,
    vaultId,
    keyVersion,
  };
}

export async function unwrapVaultKeyForAgent(
  wrappedRecord: AgentWrappedVaultKey,
  agentDecryptionKey: Uint8Array,
  agentId: string,
  vaultId: string,
  keyVersion: number,
): Promise<Uint8Array> {
  const expectedAad = `agent:${agentId}:${vaultId}:${keyVersion}`;
  if (
    wrappedRecord.aad !== expectedAad ||
    wrappedRecord.agentId !== agentId ||
    wrappedRecord.vaultId !== vaultId ||
    wrappedRecord.keyVersion !== keyVersion
  ) {
    throw new Error("AgentEncryptedVaultKey metadata or AAD mismatch");
  }

  const wrappingKey = await deriveAgentWrappingKey(
    agentDecryptionKey,
    agentId,
    vaultId,
    keyVersion,
  );

  const iv = base64ToBytes(wrappedRecord.iv);
  const ciphertext = base64ToBytes(wrappedRecord.agentEncryptedVaultKey);
  const authTag = base64ToBytes(wrappedRecord.authTag);
  const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  combined.set(ciphertext, 0);
  combined.set(authTag, ciphertext.byteLength);

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(textEncoder.encode(expectedAad)),
      tagLength: AES_GCM_TAG_BITS,
    },
    wrappingKey,
    toBuffer(combined),
  );

  return new Uint8Array(decryptedBuffer);
}

export async function deriveVaultSearchKey(vaultKeyBytes: Uint8Array): Promise<CryptoKey> {
  if (vaultKeyBytes.byteLength !== AES_GCM_KEY_BYTES) {
    throw new RangeError(
      `VaultKey must be ${AES_GCM_KEY_BYTES} bytes, received ${vaultKeyBytes.byteLength}`,
    );
  }
  const hkdfKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toBuffer(vaultKeyBytes),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return globalThis.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(32),
      info: toBuffer(textEncoder.encode(HKDF_INFO_VAULT_SEARCH_KEY)),
    },
    hkdfKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"],
  );
}

export async function computeTagBlindIndex(
  vaultSearchKey: CryptoKey,
  tag: string,
): Promise<string> {
  const normalizedTag = tag.trim().toLowerCase();
  if (normalizedTag.length === 0) {
    throw new Error("Tag for blind indexing must not be empty");
  }
  const payload = textEncoder.encode(`llm-vault/v1/tag-index:${normalizedTag}`);
  const mac = await globalThis.crypto.subtle.sign("HMAC", vaultSearchKey, toBuffer(payload));
  return bytesToHex(new Uint8Array(mac));
}

async function resolveHmacKey(key: CryptoKey | Uint8Array): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    return globalThis.crypto.subtle.importKey(
      "raw",
      toBuffer(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
  }
  return key;
}

export const GENESIS_AUDIT_EVENT_HASH = "GENESIS";

export async function computeAuditEventHash(
  auditHmacKey: CryptoKey | Uint8Array,
  prevEventHash: string,
  canonicalEventJson: string,
): Promise<string> {
  const hmacKey = await resolveHmacKey(auditHmacKey);
  const data = textEncoder.encode(`${prevEventHash}:${canonicalEventJson}`);
  const signature = await globalThis.crypto.subtle.sign("HMAC", hmacKey, toBuffer(data));
  return bytesToHex(new Uint8Array(signature));
}

export interface HashChainedAuditRecord {
  id: string;
  prevEventHash: string;
  eventHash: string;
  canonicalEventJson: string;
}

export async function verifyAuditHashChain(
  events: readonly HashChainedAuditRecord[],
  auditHmacKey: CryptoKey | Uint8Array,
  expectedInitialPrevHash: string = GENESIS_AUDIT_EVENT_HASH,
): Promise<{ valid: boolean; failedEventId?: string; reason?: string }> {
  let expectedPrevHash = expectedInitialPrevHash;
  const hmacKey = await resolveHmacKey(auditHmacKey);

  for (const event of events) {
    if (event.prevEventHash !== expectedPrevHash) {
      return {
        valid: false,
        failedEventId: event.id,
        reason: `Broken prevEventHash link on ${event.id}: expected "${expectedPrevHash}", found "${event.prevEventHash}"`,
      };
    }

    const computed = await computeAuditEventHash(
      hmacKey,
      event.prevEventHash,
      event.canonicalEventJson,
    );
    if (computed !== event.eventHash) {
      return {
        valid: false,
        failedEventId: event.id,
        reason: `Event hash mismatch on ${event.id}: expected "${computed}", found "${event.eventHash}"`,
      };
    }

    expectedPrevHash = event.eventHash;
  }

  return { valid: true };
}
