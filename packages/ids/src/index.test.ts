import { describe, expect, it } from "vitest";

import {
  ENTITY_PREFIXES,
  ENTITY_PREFIX_NAMES,
  createMonotonicUlidGenerator,
  decodeUlidTime,
  encodeUlidTime,
  extractUlidTimestamp,
  formatSecretHandle,
  generateEntityId,
  isValidEntityId,
  isValidSecretHandle,
  parseEntityId,
  parseSecretHandle,
} from "./index.js";

describe("@llm-vault/ids", () => {
  it("generates and parses valid ULIDs across all 7 entity prefixes", () => {
    const fixedTime = 1_728_900_000_000;

    for (const prefix of ENTITY_PREFIXES) {
      const id = generateEntityId(prefix, fixedTime);
      expect(id.startsWith(prefix)).toBe(true);
      expect(isValidEntityId(id)).toBe(true);
      expect(isValidEntityId(id, prefix)).toBe(true);

      const parsed = parseEntityId(id);
      expect(parsed.id).toBe(id);
      expect(parsed.prefix).toBe(prefix);
      expect(parsed.ulid).toHaveLength(26);
      expect(parsed.timestampMs).toBe(fixedTime);
      expect(parsed.timestamp.getTime()).toBe(fixedTime);
      expect(extractUlidTimestamp(id)).toBe(fixedTime);
    }

    for (const prefixName of ENTITY_PREFIX_NAMES) {
      const id = generateEntityId(prefixName, fixedTime);
      expect(id.startsWith(`${prefixName}_`)).toBe(true);
      expect(isValidEntityId(id, prefixName)).toBe(true);
    }
  });

  it("maintains strict lexicographical monotonicity within the same millisecond and across timestamps", () => {
    const gen = createMonotonicUlidGenerator(() => 1_728_900_123_456);
    const ulids: string[] = [];
    for (let i = 0; i < 50; i++) {
      ulids.push(gen());
    }
    const sorted = [...ulids].sort();
    expect(ulids).toEqual(sorted);
    expect(new Set(ulids).size).toBe(50);

    const earlier = generateEntityId("sec_", 1_700_000_000_000);
    const later = generateEntityId("sec_", 1_750_000_000_000);
    expect(earlier < later).toBe(true);
  });

  it("round-trips ULID timestamps and rejects out-of-range values", () => {
    const zero = encodeUlidTime(0);
    expect(zero).toBe("0000000000");
    expect(decodeUlidTime(`${zero}0000000000000000`)).toBe(0);

    const maxTime = 281_474_976_710_655;
    const maxEncoded = encodeUlidTime(maxTime);
    expect(maxEncoded).toBe("7zzzzzzzzz");
    expect(decodeUlidTime(`${maxEncoded}zzzzzzzzzzzzzzzz`)).toBe(maxTime);

    expect(() => encodeUlidTime(-1)).toThrow(RangeError);
    expect(() => encodeUlidTime(maxTime + 1)).toThrow(RangeError);
    expect(() => decodeUlidTime("80000000000000000000000000")).toThrow();
  });

  it("rejects malformed identifiers and mismatched expected prefixes", () => {
    const secId = generateEntityId("sec_");
    expect(isValidEntityId(secId, "vlt_")).toBe(false);
    expect(isValidEntityId("unknown_01jk7a89b2c3d4e5f6g7h8j9k0")).toBe(false);
    expect(isValidEntityId("sec_short")).toBe(false);
    expect(isValidEntityId(null)).toBe(false);
    expect(() => parseEntityId("invalid")).toThrow();
  });

  it("formats and parses opaque zero-context secret handles", () => {
    const secId = generateEntityId("sec_", 1_728_900_555_000);
    const handle = formatSecretHandle(secId);

    expect(handle).toBe(`{{vault:${secId}}}`);
    expect(isValidSecretHandle(handle)).toBe(true);

    const parsed = parseSecretHandle(handle);
    expect(parsed.handle).toBe(handle);
    expect(parsed.secretId).toBe(secId);
    expect(parsed.timestampMs).toBe(1_728_900_555_000);

    const vaultId = generateEntityId("vlt_");
    expect(() => formatSecretHandle(vaultId)).toThrow();
    expect(() => parseSecretHandle("{{vault:vlt_01jk7a89b2c3d4e5f6g7h8j9k1}}")).toThrow();
    expect(isValidSecretHandle("plaintext-secret")).toBe(false);
  });
});
