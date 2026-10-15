import { describe, expect, it } from "vitest";
import { estimateEntropyBits, generatePassphrase, generatePassword } from "./generator.js";

describe("generator", () => {
  describe("generatePassword", () => {
    it("generates passwords of requested length within bounds [8, 128]", () => {
      const p1 = generatePassword({
        length: 16,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
        excludeAmbiguous: false,
      });
      expect(p1.length).toBe(16);

      // Clamp low
      const pLow = generatePassword({
        length: 4,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: false,
        excludeAmbiguous: false,
      });
      expect(pLow.length).toBe(8);

      // Clamp high
      const pHigh = generatePassword({
        length: 200,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: false,
        excludeAmbiguous: false,
      });
      expect(pHigh.length).toBe(128);
    });

    it("guarantees inclusion of enabled character sets", () => {
      const pwd = generatePassword({
        length: 32,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
        excludeAmbiguous: false,
      });

      expect(/[A-Z]/.test(pwd)).toBe(true);
      expect(/[a-z]/.test(pwd)).toBe(true);
      expect(/[0-9]/.test(pwd)).toBe(true);
      expect(/[!@#$%^&*()_\-=[\]{}|;:,.<>?]/.test(pwd)).toBe(true);
    });

    it("excludes ambiguous characters when excludeAmbiguous is true", () => {
      for (let i = 0; i < 20; i++) {
        const pwd = generatePassword({
          length: 32,
          includeUppercase: true,
          includeLowercase: true,
          includeNumbers: true,
          includeSymbols: false,
          excludeAmbiguous: true,
        });

        // Should not contain I, O, l, o, 1, 0
        expect(/[IOlo10]/.test(pwd)).toBe(false);
      }
    });

    it("falls back gracefully if all character sets are disabled", () => {
      const pwd = generatePassword({
        length: 12,
        includeUppercase: false,
        includeLowercase: false,
        includeNumbers: false,
        includeSymbols: false,
        excludeAmbiguous: false,
      });
      expect(pwd.length).toBe(12);
      expect(pwd.length).toBeGreaterThanOrEqual(8);
    });
  });

  describe("generatePassphrase", () => {
    it("generates diceware passphrases with specified word count and delimiter", () => {
      const phrase = generatePassphrase({
        wordCount: 5,
        delimiter: "-",
        capitalize: true,
        includeNumber: false,
      });

      const parts = phrase.split("-");
      expect(parts.length).toBe(5);
      for (const part of parts) {
        expect(part.length).toBeGreaterThan(0);
        expect(part[0]).toBe(part[0]?.toUpperCase());
      }
    });

    it("embeds a random digit when includeNumber is true", () => {
      const phrase = generatePassphrase({
        wordCount: 4,
        delimiter: ".",
        capitalize: false,
        includeNumber: true,
      });

      expect(/\d/.test(phrase)).toBe(true);
      const parts = phrase.split(".");
      expect(parts.length).toBe(4);
    });
  });

  describe("estimateEntropyBits", () => {
    it("returns 0 for empty string", () => {
      expect(estimateEntropyBits("")).toBe(0);
    });

    it("calculates proportional entropy based on character sets and length", () => {
      const lowEntropy = estimateEntropyBits("aaaaaa");
      const highEntropy = estimateEntropyBits("A1#bC9$xZ@2!");

      expect(lowEntropy).toBeGreaterThan(0);
      expect(highEntropy).toBeGreaterThan(lowEntropy);
      expect(highEntropy).toBeGreaterThanOrEqual(60);
    });
  });
});
