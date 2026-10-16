const CROCKFORD_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
const CROCKFORD_DECODE_MAP = new Map<string, number>();

for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
  const char = CROCKFORD_ALPHABET[i]!;
  CROCKFORD_DECODE_MAP.set(char, i);
  CROCKFORD_DECODE_MAP.set(char.toUpperCase(), i);
}

const MAX_ULID_TIME_MS = 281_474_976_710_655; // 2^48 - 1
const TIME_LEN = 10;
const RANDOM_LEN = 16;
const ULID_LEN = 26;

export const ENTITY_PREFIX_NAMES = [
  "sec",
  "vlt",
  "fld",
  "usr",
  "agt",
  "lease",
  "aud",
  "wkb",
] as const;

export const ENTITY_PREFIXES = [
  "sec_",
  "vlt_",
  "fld_",
  "usr_",
  "agt_",
  "lease_",
  "aud_",
  "wkb_",
] as const;

export type EntityPrefixName = (typeof ENTITY_PREFIX_NAMES)[number];
export type EntityPrefix = (typeof ENTITY_PREFIXES)[number];
export type EntityPrefixInput = EntityPrefix | EntityPrefixName;

export type EntityId<P extends EntityPrefixName = EntityPrefixName> = `${P}_${string}`;
export type SecretId = EntityId<"sec">;
export type VaultId = EntityId<"vlt">;
export type FolderId = EntityId<"fld">;
export type UserId = EntityId<"usr">;
export type AgentId = EntityId<"agt">;
export type LeaseId = EntityId<"lease">;
export type AuditId = EntityId<"aud">;
export type WorkloadBindingId = EntityId<"wkb">;

export type SecretHandle = `{{vault:sec_${string}}}`;
export type LeaseHandle = `{{vault:lease_${string}}}`;
export type VaultHandle = SecretHandle | LeaseHandle;

export interface ParsedEntityId {
  id: string;
  prefix: EntityPrefix;
  prefixName: EntityPrefixName;
  ulid: string;
  timestampMs: number;
  timestamp: Date;
}

const PREFIX_NAME_SET = new Set<string>(ENTITY_PREFIX_NAMES);
const ULID_REGEX = /^[0-7][0-9a-hjkmnp-tv-z]{25}$/i;
const ENTITY_ID_REGEX = /^(sec|vlt|fld|usr|agt|lease|aud|wkb)_([0-7][0-9a-hjkmnp-tv-z]{25})$/i;
const SECRET_HANDLE_REGEX = /^\{\{vault:(sec_[0-7][0-9a-hjkmnp-tv-z]{25})\}\}$/i;
export const VAULT_HANDLE_REGEX = /^\{\{vault:((?:sec|lease)_[0-7][0-9a-hjkmnp-tv-z]{25})\}\}$/i;

export function normalizePrefix(prefix: EntityPrefixInput): {
  prefix: EntityPrefix;
  prefixName: EntityPrefixName;
} {
  const trimmed = prefix.endsWith("_") ? prefix.slice(0, -1) : prefix;
  if (!PREFIX_NAME_SET.has(trimmed)) {
    throw new Error(`Invalid entity prefix: "${prefix}"`);
  }
  const prefixName = trimmed as EntityPrefixName;
  return {
    prefix: `${prefixName}_`,
    prefixName,
  };
}

export function encodeUlidTime(timestampMs: number): string {
  if (!Number.isInteger(timestampMs) || timestampMs < 0 || timestampMs > MAX_ULID_TIME_MS) {
    throw new RangeError(
      `Invalid ULID timestampMs: ${timestampMs}. Expected integer in [0, ${MAX_ULID_TIME_MS}].`,
    );
  }

  let remaining = timestampMs;
  const chars = new Array<string>(TIME_LEN);
  for (let i = TIME_LEN - 1; i >= 0; i--) {
    const mod = remaining % 32;
    chars[i] = CROCKFORD_ALPHABET[mod]!;
    remaining = (remaining - mod) / 32;
  }
  return chars.join("");
}

export function decodeUlidTime(ulid: string): number {
  if (ulid.length !== ULID_LEN || !ULID_REGEX.test(ulid)) {
    throw new Error(`Invalid 26-character ULID: "${ulid}"`);
  }

  let timestampMs = 0;
  for (let i = 0; i < TIME_LEN; i++) {
    const ch = ulid[i]!;
    const val = CROCKFORD_DECODE_MAP.get(ch);
    if (val === undefined) {
      throw new Error(`Invalid Crockford Base32 character "${ch}" in ULID`);
    }
    timestampMs = timestampMs * 32 + val;
  }
  return timestampMs;
}

function generateRandomBase32(): number[] {
  const bytes = new Uint8Array(10); // 80 bits
  globalThis.crypto.getRandomValues(bytes);

  // Convert 10 bytes (80 bits) into 16 5-bit integers
  const digits = new Array<number>(RANDOM_LEN);
  digits[0] = (bytes[0]! & 0xf8) >> 3;
  digits[1] = ((bytes[0]! & 0x07) << 2) | ((bytes[1]! & 0xc0) >> 6);
  digits[2] = (bytes[1]! & 0x3e) >> 1;
  digits[3] = ((bytes[1]! & 0x01) << 4) | ((bytes[2]! & 0xf0) >> 4);
  digits[4] = ((bytes[2]! & 0x0f) << 1) | ((bytes[3]! & 0x80) >> 7);
  digits[5] = (bytes[3]! & 0x7c) >> 2;
  digits[6] = ((bytes[3]! & 0x03) << 3) | ((bytes[4]! & 0xe0) >> 5);
  digits[7] = bytes[4]! & 0x1f;

  digits[8] = (bytes[5]! & 0xf8) >> 3;
  digits[9] = ((bytes[5]! & 0x07) << 2) | ((bytes[6]! & 0xc0) >> 6);
  digits[10] = (bytes[6]! & 0x3e) >> 1;
  digits[11] = ((bytes[6]! & 0x01) << 4) | ((bytes[7]! & 0xf0) >> 4);
  digits[12] = ((bytes[7]! & 0x0f) << 1) | ((bytes[8]! & 0x80) >> 7);
  digits[13] = (bytes[8]! & 0x7c) >> 2;
  digits[14] = ((bytes[8]! & 0x03) << 3) | ((bytes[9]! & 0xe0) >> 5);
  digits[15] = bytes[9]! & 0x1f;

  return digits;
}

function incrementBase32Digits(digits: number[]): number[] {
  const next = digits.slice();
  for (let i = next.length - 1; i >= 0; i--) {
    const val = next[i]!;
    if (val < 31) {
      next[i] = val + 1;
      return next;
    }
    next[i] = 0;
  }
  throw new Error("ULID monotonic random component overflowed within the same millisecond");
}

function encodeBase32Digits(digits: number[]): string {
  return digits.map((d) => CROCKFORD_ALPHABET[d]!).join("");
}

export interface MonotonicUlidGenerator {
  (timestampMs?: number): string;
}

export function createMonotonicUlidGenerator(now: () => number = Date.now): MonotonicUlidGenerator {
  let lastTimestampMs = -1;
  let lastRandomDigits: number[] = [];

  return (timestampMs?: number): string => {
    const currentTimestampMs = timestampMs ?? now();
    const timePart = encodeUlidTime(currentTimestampMs);

    if (currentTimestampMs === lastTimestampMs) {
      lastRandomDigits = incrementBase32Digits(lastRandomDigits);
    } else {
      lastTimestampMs = currentTimestampMs;
      lastRandomDigits = generateRandomBase32();
    }

    return `${timePart}${encodeBase32Digits(lastRandomDigits)}`;
  };
}

const defaultUlidGenerator = createMonotonicUlidGenerator();

export function generateRawUlid(timestampMs?: number): string {
  return defaultUlidGenerator(timestampMs);
}

export function generateEntityId<P extends EntityPrefixInput>(
  prefix: P,
  timestampMs?: number,
): string {
  const { prefix: normalizedPrefix } = normalizePrefix(prefix);
  const ulid = defaultUlidGenerator(timestampMs);
  return `${normalizedPrefix}${ulid}`;
}

export function parseEntityId(id: string): ParsedEntityId {
  const match = ENTITY_ID_REGEX.exec(id.trim());
  if (!match) {
    throw new Error(`Invalid entity identifier: "${id}"`);
  }

  const rawPrefixName = match[1]!.toLowerCase() as EntityPrefixName;
  const ulid = match[2]!.toLowerCase();
  const timestampMs = decodeUlidTime(ulid);
  const prefix: EntityPrefix = `${rawPrefixName}_`;

  return {
    id: `${prefix}${ulid}`,
    prefix,
    prefixName: rawPrefixName,
    ulid,
    timestampMs,
    timestamp: new Date(timestampMs),
  };
}

export function isValidEntityId(id: unknown, expectedPrefix?: EntityPrefixInput): id is string {
  if (typeof id !== "string") {
    return false;
  }
  const match = ENTITY_ID_REGEX.exec(id.trim());
  if (!match) {
    return false;
  }
  if (expectedPrefix !== undefined) {
    try {
      const { prefixName } = normalizePrefix(expectedPrefix);
      return match[1]!.toLowerCase() === prefixName;
    } catch {
      return false;
    }
  }
  return true;
}

export function extractUlidTimestamp(id: string): number {
  return parseEntityId(id).timestampMs;
}

export function formatSecretHandle(secId: string): SecretHandle {
  const parsed = parseEntityId(secId);
  if (parsed.prefixName !== "sec") {
    throw new Error(`Expected secret identifier with prefix "sec_", received "${parsed.prefix}"`);
  }
  return `{{vault:${parsed.id}}}` as SecretHandle;
}

export function parseSecretHandle(handle: string): {
  handle: SecretHandle;
  secretId: SecretId;
  ulid: string;
  timestampMs: number;
} {
  const match = SECRET_HANDLE_REGEX.exec(handle.trim());
  if (!match) {
    throw new Error(`Invalid opaque secret handle: "${handle}"`);
  }
  const parsed = parseEntityId(match[1]!);
  return {
    handle: `{{vault:${parsed.id}}}` as SecretHandle,
    secretId: parsed.id as SecretId,
    ulid: parsed.ulid,
    timestampMs: parsed.timestampMs,
  };
}

export function isValidSecretHandle(handle: unknown): handle is SecretHandle {
  if (typeof handle !== "string") {
    return false;
  }
  return SECRET_HANDLE_REGEX.test(handle.trim());
}

export function formatLeaseHandle(leaseId: string): LeaseHandle {
  const parsed = parseEntityId(leaseId);
  if (parsed.prefixName !== "lease") {
    throw new Error(`Expected lease identifier with prefix "lease_", received "${parsed.prefix}"`);
  }
  return `{{vault:${parsed.id}}}` as LeaseHandle;
}

export function formatVaultHandle(id: string): VaultHandle {
  const parsed = parseEntityId(id);
  if (parsed.prefixName !== "sec" && parsed.prefixName !== "lease") {
    throw new Error(`Expected "sec_" or "lease_" identifier, received "${parsed.prefix}"`);
  }
  return `{{vault:${parsed.id}}}` as VaultHandle;
}

export function parseVaultHandle(handle: string): {
  handle: VaultHandle;
  id: string;
  prefixName: "sec" | "lease";
  ulid: string;
  timestampMs: number;
} {
  const match = VAULT_HANDLE_REGEX.exec(handle.trim());
  if (!match) {
    throw new Error(`Invalid opaque vault handle: "${handle}"`);
  }
  const parsed = parseEntityId(match[1]!);
  return {
    handle: `{{vault:${parsed.id}}}` as VaultHandle,
    id: parsed.id,
    prefixName: parsed.prefixName as "sec" | "lease",
    ulid: parsed.ulid,
    timestampMs: parsed.timestampMs,
  };
}

export function isValidVaultHandle(handle: unknown): handle is VaultHandle {
  if (typeof handle !== "string") {
    return false;
  }
  return VAULT_HANDLE_REGEX.test(handle.trim());
}
