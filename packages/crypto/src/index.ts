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

export function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
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

export async function deriveMasterSubkeysFromPrf(
  prfBytes: Uint8Array,
  salt: Uint8Array,
): Promise<DerivedMasterSubkeys> {
  if (prfBytes.byteLength < 32) {
    throw new RangeError(
      `WebAuthn PRF output must be at least 32 bytes, received ${prfBytes.byteLength}`,
    );
  }
  assertSalt(salt);

  const hkdfKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toBuffer(prfBytes),
    "HKDF",
    false,
    ["deriveKey", "deriveBits"],
  );

  const masterEncryptionKey = await globalThis.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toBuffer(salt),
      info: toBuffer(textEncoder.encode(HKDF_INFO_MASTER_ENCRYPTION_KEY)),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
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

const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

async function resolveX25519PrivateKey(key: CryptoKey | Uint8Array): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    let pkcs8Bytes = key;
    if (key.byteLength === 32) {
      const prefixed = new Uint8Array(48);
      prefixed.set(X25519_PKCS8_PREFIX, 0);
      prefixed.set(key, 16);
      pkcs8Bytes = prefixed;
    }
    return globalThis.crypto.subtle.importKey(
      "pkcs8",
      toBuffer(pkcs8Bytes),
      { name: "X25519" },
      false,
      ["deriveBits", "deriveKey"],
    );
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

export interface OrgRecoveryWrappedVaultKey {
  encryptedVaultKey: string;
  iv: string;
  authTag: string;
  aad: string;
  ephemeralPublicKey: string;
  keyVersion: number;
}

export function splitRecoveryKey(recoveryKeyBytes: Uint8Array): { share1: string; share2: string } {
  if (recoveryKeyBytes.byteLength !== 32) {
    throw new RangeError(
      `Recovery key must be exactly 32 bytes, received ${recoveryKeyBytes.byteLength}`,
    );
  }
  const share1Bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(share1Bytes);
  const share2Bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    share2Bytes[i] = recoveryKeyBytes[i]! ^ share1Bytes[i]!;
  }
  return {
    share1: bytesToHex(share1Bytes),
    share2: bytesToHex(share2Bytes),
  };
}

export function combineRecoveryKey(
  share1: string | Uint8Array,
  share2: string | Uint8Array,
): Uint8Array {
  const s1 = typeof share1 === "string" ? hexToBytes(share1) : share1;
  const s2 = typeof share2 === "string" ? hexToBytes(share2) : share2;
  if (s1.byteLength !== 32 || s2.byteLength !== 32) {
    throw new RangeError("Both recovery key shares must be exactly 32 bytes");
  }
  const combined = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    combined[i] = s1[i]! ^ s2[i]!;
  }
  return combined;
}

export async function generateOrgRecoveryKeyPair(): Promise<{
  publicKey: string;
  privateKeyBytes: Uint8Array;
}> {
  const pair = (await globalThis.crypto.subtle.generateKey({ name: "X25519" }, true, [
    "deriveKey",
    "deriveBits",
  ])) as CryptoKeyPair;

  const rawPub = await globalThis.crypto.subtle.exportKey("raw", pair.publicKey);
  const pkcs8Priv = await globalThis.crypto.subtle.exportKey("pkcs8", pair.privateKey);

  const privBytes = new Uint8Array(pkcs8Priv);
  const rawPriv = privBytes.subarray(privBytes.byteLength - 32);
  const outPriv = new Uint8Array(32);
  outPriv.set(rawPriv);

  return {
    publicKey: bytesToBase64(new Uint8Array(rawPub)),
    privateKeyBytes: outPriv,
  };
}

export async function wrapVaultKeyWithOrgRecoveryKey(
  vaultKeyBytes: Uint8Array,
  orgRecoveryPublicKey: CryptoKey | Uint8Array | string,
  vaultId: string,
  keyVersion: number,
): Promise<OrgRecoveryWrappedVaultKey> {
  if (vaultKeyBytes.byteLength !== AES_GCM_KEY_BYTES) {
    throw new RangeError(
      `VaultKey must be ${AES_GCM_KEY_BYTES} bytes, received ${vaultKeyBytes.byteLength}`,
    );
  }
  const pubKey = await resolveX25519PublicKey(orgRecoveryPublicKey);
  const ephemeralPair = (await globalThis.crypto.subtle.generateKey({ name: "X25519" }, true, [
    "deriveKey",
    "deriveBits",
  ])) as CryptoKeyPair;

  const sharedBits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: pubKey,
    },
    ephemeralPair.privateKey,
    256,
  );
  const sharedBytes = new Uint8Array(sharedBits);
  let wrappingKey: CryptoKey;
  try {
    const hkdfKey = await globalThis.crypto.subtle.importKey(
      "raw",
      toBuffer(sharedBytes),
      "HKDF",
      false,
      ["deriveKey"],
    );
    const infoBytes = textEncoder.encode(`llm-vault/v1/org-recovery-key:${vaultId}:${keyVersion}`);
    wrappingKey = await globalThis.crypto.subtle.deriveKey(
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

  const aad = `org-recovery:${vaultId}:${keyVersion}`;
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
  const rawEphemeralPub = await globalThis.crypto.subtle.exportKey("raw", ephemeralPair.publicKey);

  return {
    encryptedVaultKey: bytesToBase64(encryptedBytes.subarray(0, ciphertextLength)),
    iv: bytesToBase64(iv),
    authTag: bytesToBase64(encryptedBytes.subarray(ciphertextLength)),
    aad,
    ephemeralPublicKey: bytesToBase64(new Uint8Array(rawEphemeralPub)),
    keyVersion,
  };
}

export async function unwrapVaultKeyWithOrgRecoveryKey(
  wrappedRecord: OrgRecoveryWrappedVaultKey,
  orgRecoveryPrivateKey: CryptoKey | Uint8Array,
  vaultId: string,
): Promise<Uint8Array> {
  const expectedAad = `org-recovery:${vaultId}:${wrappedRecord.keyVersion}`;
  if (wrappedRecord.aad !== expectedAad) {
    throw new Error("OrgRecoveryWrappedVaultKey AAD mismatch");
  }

  const privKey = await resolveX25519PrivateKey(orgRecoveryPrivateKey);
  const ephemeralPubKey = await resolveX25519PublicKey(wrappedRecord.ephemeralPublicKey);

  const sharedBits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: ephemeralPubKey,
    },
    privKey,
    256,
  );
  const sharedBytes = new Uint8Array(sharedBits);
  let wrappingKey: CryptoKey;
  try {
    const hkdfKey = await globalThis.crypto.subtle.importKey(
      "raw",
      toBuffer(sharedBytes),
      "HKDF",
      false,
      ["deriveKey"],
    );
    const infoBytes = textEncoder.encode(
      `llm-vault/v1/org-recovery-key:${vaultId}:${wrappedRecord.keyVersion}`,
    );
    wrappingKey = await globalThis.crypto.subtle.deriveKey(
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

const RFC4648_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function bytesToBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]!;
    bits += 8;
    while (bits >= 5) {
      output += RFC4648_BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += RFC4648_BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

export function base32ToBytes(b32: string): Uint8Array {
  const cleaned = b32.toUpperCase().replace(/[=\s]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = RFC4648_BASE32_ALPHABET.indexOf(cleaned[i]!);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: ${cleaned[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(out);
}

export function generateTotpSecret(byteLength: number = 20): {
  secretBytes: Uint8Array;
  secretBase32: string;
} {
  const secretBytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(secretBytes);
  const secretBase32 = bytesToBase32(secretBytes);
  return { secretBytes, secretBase32 };
}

export async function generateTotpCode(
  secret: string | Uint8Array,
  timestampMs: number = Date.now(),
  stepSeconds: number = 30,
  digits: number = 6,
): Promise<string> {
  const secretBytes = typeof secret === "string" ? base32ToBytes(secret) : secret;
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);

  const counterBuffer = new ArrayBuffer(8);
  const view = new DataView(counterBuffer);
  view.setBigUint64(0, BigInt(counter));

  const hmacKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toBuffer(secretBytes),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );

  const signature = new Uint8Array(
    await globalThis.crypto.subtle.sign("HMAC", hmacKey, counterBuffer),
  );
  const offset = signature[signature.length - 1]! & 0x0f;
  const binary =
    ((signature[offset]! & 0x7f) << 24) |
    ((signature[offset + 1]! & 0xff) << 16) |
    ((signature[offset + 2]! & 0xff) << 8) |
    (signature[offset + 3]! & 0xff);

  const otp = binary % 10 ** digits;
  return otp.toString().padStart(digits, "0");
}

function cryptoTimingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function verifyTotpCode(
  code: string,
  secret: string | Uint8Array,
  options?: {
    window?: number;
    timestampMs?: number;
    stepSeconds?: number;
    digits?: number;
  },
): Promise<boolean> {
  const trimmed = code.trim();
  const digits = options?.digits ?? 6;
  if (trimmed.length !== digits || !/^\d+$/.test(trimmed)) {
    return false;
  }

  const window = options?.window ?? 1;
  const timestampMs = options?.timestampMs ?? Date.now();
  const stepSeconds = options?.stepSeconds ?? 30;

  for (let i = -window; i <= window; i++) {
    const checkTime = timestampMs + i * stepSeconds * 1000;
    const generated = await generateTotpCode(secret, checkTime, stepSeconds, digits);
    if (cryptoTimingSafeEqual(trimmed, generated)) {
      return true;
    }
  }

  return false;
}

export function sanitizeImportString(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  // Strip control characters (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F) while preserving \t, \n, \r
  let cleaned = "";
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (
      (code >= 0x00 && code <= 0x08) ||
      code === 0x0b ||
      code === 0x0c ||
      (code >= 0x0e && code <= 0x1f) ||
      code === 0x7f
    ) {
      continue;
    }
    cleaned += input[i];
  }
  // Iteratively strip script/style tags and HTML markup until fixpoint without regexes
  let prev = "";
  while (cleaned !== prev) {
    prev = cleaned;
    let result = "";
    let i = 0;
    while (i < cleaned.length) {
      if (cleaned[i] === "<") {
        const rest = cleaned.slice(i).toLowerCase();
        if (rest.startsWith("<script")) {
          const closeIdx = rest.indexOf("</script");
          if (closeIdx !== -1) {
            const endTagClose = cleaned.indexOf(">", i + closeIdx);
            if (endTagClose !== -1) {
              i = endTagClose + 1;
              continue;
            }
          }
        } else if (rest.startsWith("<style")) {
          const closeIdx = rest.indexOf("</style");
          if (closeIdx !== -1) {
            const endTagClose = cleaned.indexOf(">", i + closeIdx);
            if (endTagClose !== -1) {
              i = endTagClose + 1;
              continue;
            }
          }
        }
        const tagEnd = cleaned.indexOf(">", i);
        if (tagEnd !== -1) {
          i = tagEnd + 1;
          continue;
        }
        // Stray '<' without '>'
        i++;
        continue;
      }
      if (cleaned[i] === ">") {
        // Stray '>'
        i++;
        continue;
      }
      result += cleaned[i];
      i++;
    }
    cleaned = result;
  }

  return cleaned.trim();
}

export interface EncryptedBackupContainerData {
  format: "llm-vault-backup";
  version: 1;
  kdf: {
    provider: "pbkdf2" | "argon2id";
    salt: string;
    iterations: number;
  };
  iv: string;
  ciphertext: string;
  authTag: string;
  tenantId: string;
  vaultId: string;
  exportedAt: string;
  itemCount: number;
}

export async function createEncryptedBackup(params: {
  passphrase: string;
  tenantId: string;
  vaultId: string;
  items: unknown[];
  iterations?: number;
  exportedAt?: string;
}): Promise<EncryptedBackupContainerData> {
  const iterations = params.iterations ?? MIN_PBKDF2_ITERATIONS;
  if (iterations < 100_000) {
    throw new RangeError("Backup PBKDF2 iterations must be at least 100,000");
  }

  const salt = new Uint8Array(MASTER_SALT_BYTES);
  globalThis.crypto.getRandomValues(salt);

  const derivedBytes = await deriveMasterKeyMaterial(params.passphrase, salt, iterations);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toBuffer(derivedBytes),
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );

  const iv = new Uint8Array(AES_GCM_IV_BYTES);
  globalThis.crypto.getRandomValues(iv);

  const aad = textEncoder.encode(`llm-vault:backup:v1:${params.tenantId}:${params.vaultId}`);
  const plaintextBytes = textEncoder.encode(JSON.stringify(params.items));

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(aad),
      tagLength: AES_GCM_TAG_BITS,
    },
    cryptoKey,
    toBuffer(plaintextBytes),
  );

  const fullBytes = new Uint8Array(encryptedBuffer);
  const ciphertextLength = fullBytes.length - AES_GCM_TAG_BYTES;
  const ciphertextBytes = fullBytes.subarray(0, ciphertextLength);
  const authTagBytes = fullBytes.subarray(ciphertextLength);

  zeroizeBuffer(derivedBytes);
  zeroizeBuffer(plaintextBytes);

  return {
    format: "llm-vault-backup",
    version: 1,
    kdf: {
      provider: "pbkdf2",
      salt: bytesToBase64(salt),
      iterations,
    },
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertextBytes),
    authTag: bytesToBase64(authTagBytes),
    tenantId: params.tenantId,
    vaultId: params.vaultId,
    exportedAt: params.exportedAt ?? new Date().toISOString(),
    itemCount: params.items.length,
  };
}

export async function restoreEncryptedBackup<T = unknown>(params: {
  container: EncryptedBackupContainerData;
  passphrase: string;
}): Promise<T[]> {
  const { container, passphrase } = params;
  if (container.format !== "llm-vault-backup" || container.version !== 1) {
    throw new Error(`Unsupported backup format: ${container.format} v${container.version}`);
  }
  if (container.kdf.iterations < 100_000) {
    throw new Error("Rejected backup container: KDF iterations below security minimum (100,000)");
  }

  const salt = base64ToBytes(container.kdf.salt);
  const derivedBytes = await deriveMasterKeyMaterial(passphrase, salt, container.kdf.iterations);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toBuffer(derivedBytes),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const iv = base64ToBytes(container.iv);
  const ciphertextBytes = base64ToBytes(container.ciphertext);
  const authTagBytes = base64ToBytes(container.authTag);
  const combinedBuffer = new Uint8Array(ciphertextBytes.length + authTagBytes.length);
  combinedBuffer.set(ciphertextBytes, 0);
  combinedBuffer.set(authTagBytes, ciphertextBytes.length);

  const aad = textEncoder.encode(`llm-vault:backup:v1:${container.tenantId}:${container.vaultId}`);

  try {
    const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toBuffer(iv),
        additionalData: toBuffer(aad),
        tagLength: AES_GCM_TAG_BITS,
      },
      cryptoKey,
      toBuffer(combinedBuffer),
    );

    const decryptedBytes = new Uint8Array(decryptedBuffer);
    const parsed = JSON.parse(textDecoder.decode(decryptedBytes)) as T[];
    zeroizeBuffer(decryptedBytes);
    return parsed;
  } catch (err) {
    throw new Error(
      `Failed to restore encrypted backup (decryption or MAC verification failed): ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    zeroizeBuffer(derivedBytes);
  }
}

export interface ParsedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array;
  signedData: Uint8Array;
}

export function parseJwt(token: string): ParsedJwt {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(
      "Invalid JWT format: token must have exactly three parts (header.payload.signature).",
    );
  }

  const [headerB64, payloadB64, sigB64] = parts;
  if (!headerB64 || !payloadB64 || sigB64 === undefined) {
    throw new Error("Invalid JWT: empty token segment.");
  }

  try {
    const headerJson = textDecoder.decode(base64ToBytes(headerB64));
    const payloadJson = textDecoder.decode(base64ToBytes(payloadB64));
    const header = JSON.parse(headerJson) as Record<string, unknown>;
    const payload = JSON.parse(payloadJson) as Record<string, unknown>;
    const signature = base64ToBytes(sigB64);
    const signedData = textEncoder.encode(`${headerB64}.${payloadB64}`);

    return {
      header,
      payload,
      signature,
      signedData,
    };
  } catch (err) {
    throw new Error(
      `Failed to decode JWT segments: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export function matchClaimPattern(
  actualValue: unknown,
  expectedPattern: string | string[],
): boolean {
  if (Array.isArray(expectedPattern)) {
    return expectedPattern.some((pat) => matchClaimPattern(actualValue, pat));
  }

  if (Array.isArray(actualValue)) {
    return actualValue.some((val) => matchClaimPattern(val, expectedPattern));
  }

  const actualStr = String(actualValue ?? "");

  // Wildcard "*" matches anything
  if (expectedPattern === "*") {
    return true;
  }

  // Single wildcard pattern (e.g. "refs/heads/*", "repo:my-org/*")
  if (expectedPattern.includes("*")) {
    const starIdx = expectedPattern.indexOf("*");
    const prefix = expectedPattern.slice(0, starIdx);
    const suffix = expectedPattern.slice(starIdx + 1);

    if (suffix === "") {
      return actualStr.startsWith(prefix);
    }
    if (prefix === "") {
      return actualStr.endsWith(suffix);
    }
    return (
      actualStr.startsWith(prefix) &&
      actualStr.endsWith(suffix) &&
      actualStr.length >= prefix.length + suffix.length
    );
  }

  return actualStr === expectedPattern;
}

export function evaluateClaimFilters(
  claims: Record<string, unknown>,
  filters: Record<string, string | string[]>,
): boolean {
  for (const [key, expectedPattern] of Object.entries(filters)) {
    if (!(key in claims)) {
      return false;
    }
    const claimVal = claims[key];
    if (!matchClaimPattern(claimVal, expectedPattern)) {
      return false;
    }
  }
  return true;
}

export function verifyJwtClaims(
  token: string,
  options: {
    expectedIssuer: string;
    expectedAudience: string;
    clockToleranceSeconds?: number;
  },
): Record<string, unknown> {
  const { payload } = parseJwt(token);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const tolerance = options.clockToleranceSeconds ?? 60;

  // Validate exp (Expiration Time)
  if (typeof payload.exp === "number") {
    if (nowSeconds > payload.exp + tolerance) {
      throw new Error(
        `JWT expired at ${new Date(payload.exp * 1000).toISOString()} (current time: ${new Date(nowSeconds * 1000).toISOString()}).`,
      );
    }
  }

  // Validate nbf (Not Before)
  if (typeof payload.nbf === "number") {
    if (nowSeconds < payload.nbf - tolerance) {
      throw new Error(`JWT not valid before ${new Date(payload.nbf * 1000).toISOString()}.`);
    }
  }

  // Validate iss (Issuer)
  if (payload.iss !== options.expectedIssuer) {
    throw new Error(
      `JWT issuer mismatch: expected "${options.expectedIssuer}", got "${String(payload.iss)}".`,
    );
  }

  // Validate aud (Audience)
  const actualAud = payload.aud;
  let audMatches = false;
  if (typeof actualAud === "string") {
    audMatches = actualAud === options.expectedAudience;
  } else if (Array.isArray(actualAud)) {
    audMatches = actualAud.includes(options.expectedAudience);
  }
  if (!audMatches) {
    throw new Error(
      `JWT audience mismatch: expected "${options.expectedAudience}", got ${JSON.stringify(actualAud)}.`,
    );
  }

  return payload;
}

export async function createTestWorkloadJwt(
  payload: Record<string, unknown>,
  header: Record<string, unknown> = { alg: "HS256", typ: "JWT" },
  secret = "test-workload-jwt-signing-secret",
): Promise<string> {
  const encHeader = bytesToBase64Url(textEncoder.encode(JSON.stringify(header)));
  const encPayload = bytesToBase64Url(textEncoder.encode(JSON.stringify(payload)));
  const unsigned = `${encHeader}.${encPayload}`;

  const hmacKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toBuffer(textEncoder.encode(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sigBuffer = await globalThis.crypto.subtle.sign(
    "HMAC",
    hmacKey,
    toBuffer(textEncoder.encode(unsigned)),
  );
  const encSig = bytesToBase64Url(new Uint8Array(sigBuffer));

  return `${unsigned}.${encSig}`;
}
