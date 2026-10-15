import React, { useState } from "react";
import { Check, Copy, RefreshCw, X } from "lucide-react";
import { estimateEntropyBits, generatePassphrase, generatePassword } from "../lib/generator.js";
import type { PassphraseGeneratorOptions, PasswordGeneratorOptions } from "../types.js";

interface PasswordGeneratorModalProps {
  onClose: () => void;
  onSelectPassword?: (password: string) => void;
  onCopyClipboard: (val: string) => void;
}

export const PasswordGeneratorModal: React.FC<PasswordGeneratorModalProps> = ({
  onClose,
  onSelectPassword,
  onCopyClipboard,
}) => {
  const [mode, setMode] = useState<"password" | "passphrase">("password");

  const [pwOptions, setPwOptions] = useState<PasswordGeneratorOptions>({
    length: 24,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeAmbiguous: true,
  });

  const [phraseOptions, setPhraseOptions] = useState<PassphraseGeneratorOptions>({
    wordCount: 5,
    delimiter: "-",
    capitalize: true,
    includeNumber: true,
  });

  const [generated, setGenerated] = useState<string>(() => generatePassword(pwOptions));
  const [copied, setCopied] = useState(false);

  const handleRegenerate = () => {
    if (mode === "password") {
      setGenerated(generatePassword(pwOptions));
    } else {
      setGenerated(generatePassphrase(phraseOptions));
    }
  };

  const handleModeChange = (newMode: "password" | "passphrase") => {
    setMode(newMode);
    if (newMode === "password") {
      setGenerated(generatePassword(pwOptions));
    } else {
      setGenerated(generatePassphrase(phraseOptions));
    }
  };

  const handleCopy = () => {
    onCopyClipboard(generated);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const entropy = estimateEntropyBits(generated);

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-5 py-4 border-b border-neutral-800 flex items-center justify-between">
          <span className="font-semibold text-sm text-neutral-100">
            Cryptographic Password Generator
          </span>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg text-neutral-400 hover:text-neutral-100 hover:bg-neutral-800 transition"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4">
          {/* Mode Switcher */}
          <div className="flex rounded-xl bg-neutral-950 p-1 border border-neutral-800 text-xs font-medium">
            <button
              type="button"
              onClick={() => handleModeChange("password")}
              className={`flex-1 py-1.5 rounded-lg text-center transition ${
                mode === "password"
                  ? "bg-neutral-800 text-neutral-100 shadow"
                  : "text-neutral-400 hover:text-neutral-200"
              }`}
            >
              Random Password
            </button>
            <button
              type="button"
              onClick={() => handleModeChange("passphrase")}
              className={`flex-1 py-1.5 rounded-lg text-center transition ${
                mode === "passphrase"
                  ? "bg-neutral-800 text-neutral-100 shadow"
                  : "text-neutral-400 hover:text-neutral-200"
              }`}
            >
              Memorable Passphrase
            </button>
          </div>

          {/* Generated Result Box */}
          <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 flex items-center justify-between gap-2">
            <span className="font-mono text-xs text-emerald-400 break-all select-all flex-1">
              {generated}
            </span>
            <div className="flex items-center gap-1.5 shrink-0">
              <button
                type="button"
                onClick={handleRegenerate}
                className="p-1.5 rounded-lg text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800 transition"
                title="Generate new"
              >
                <RefreshCw className="h-4 w-4" />
              </button>
              <button
                type="button"
                onClick={handleCopy}
                className="p-1.5 rounded-lg text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800 transition"
                title="Copy value"
              >
                {copied ? (
                  <Check className="h-4 w-4 text-emerald-400" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>

          {/* Entropy Indicator */}
          <div className="flex items-center justify-between text-xs px-1">
            <span className="text-neutral-400">Estimated Strength:</span>
            <span className="font-mono text-emerald-400">
              ~{entropy} bits (
              {entropy >= 80 ? "Very Strong" : entropy >= 60 ? "Strong" : "Moderate"})
            </span>
          </div>

          {/* Config Controls */}
          {mode === "password" ? (
            <div className="space-y-3 pt-2 border-t border-neutral-800/80">
              <div>
                <div className="flex justify-between text-xs text-neutral-300 mb-1">
                  <span>Length:</span>
                  <span className="font-mono text-emerald-400">{pwOptions.length}</span>
                </div>
                <input
                  type="range"
                  min={8}
                  max={64}
                  value={pwOptions.length}
                  onChange={(e) => {
                    const length = Number(e.target.value);
                    const updated = { ...pwOptions, length };
                    setPwOptions(updated);
                    setGenerated(generatePassword(updated));
                  }}
                  className="w-full accent-emerald-500 cursor-pointer"
                />
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs text-neutral-300">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={pwOptions.includeUppercase}
                    onChange={(e) => {
                      const updated = { ...pwOptions, includeUppercase: e.target.checked };
                      setPwOptions(updated);
                      setGenerated(generatePassword(updated));
                    }}
                    className="rounded accent-emerald-500"
                  />
                  Uppercase (A-Z)
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={pwOptions.includeLowercase}
                    onChange={(e) => {
                      const updated = { ...pwOptions, includeLowercase: e.target.checked };
                      setPwOptions(updated);
                      setGenerated(generatePassword(updated));
                    }}
                    className="rounded accent-emerald-500"
                  />
                  Lowercase (a-z)
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={pwOptions.includeNumbers}
                    onChange={(e) => {
                      const updated = { ...pwOptions, includeNumbers: e.target.checked };
                      setPwOptions(updated);
                      setGenerated(generatePassword(updated));
                    }}
                    className="rounded accent-emerald-500"
                  />
                  Numbers (0-9)
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={pwOptions.includeSymbols}
                    onChange={(e) => {
                      const updated = { ...pwOptions, includeSymbols: e.target.checked };
                      setPwOptions(updated);
                      setGenerated(generatePassword(updated));
                    }}
                    className="rounded accent-emerald-500"
                  />
                  Symbols (!@#$)
                </label>
              </div>

              <label className="flex items-center gap-2 text-xs text-neutral-300 cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={pwOptions.excludeAmbiguous}
                  onChange={(e) => {
                    const updated = { ...pwOptions, excludeAmbiguous: e.target.checked };
                    setPwOptions(updated);
                    setGenerated(generatePassword(updated));
                  }}
                  className="rounded accent-emerald-500"
                />
                Exclude Ambiguous Characters (1, l, I, 0, O, o)
              </label>
            </div>
          ) : (
            <div className="space-y-3 pt-2 border-t border-neutral-800/80">
              <div>
                <div className="flex justify-between text-xs text-neutral-300 mb-1">
                  <span>Words:</span>
                  <span className="font-mono text-emerald-400">{phraseOptions.wordCount}</span>
                </div>
                <input
                  type="range"
                  min={3}
                  max={8}
                  value={phraseOptions.wordCount}
                  onChange={(e) => {
                    const wordCount = Number(e.target.value);
                    const updated = { ...phraseOptions, wordCount };
                    setPhraseOptions(updated);
                    setGenerated(generatePassphrase(updated));
                  }}
                  className="w-full accent-emerald-500 cursor-pointer"
                />
              </div>

              <div className="flex items-center gap-2 text-xs text-neutral-300">
                <label className="shrink-0">Delimiter:</label>
                <input
                  type="text"
                  maxLength={2}
                  value={phraseOptions.delimiter}
                  onChange={(e) => {
                    const updated = { ...phraseOptions, delimiter: e.target.value };
                    setPhraseOptions(updated);
                    setGenerated(generatePassphrase(updated));
                  }}
                  className="w-12 px-2 py-1 rounded bg-neutral-950 border border-neutral-800 text-center font-mono text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex items-center gap-4 text-xs text-neutral-300">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={phraseOptions.capitalize}
                    onChange={(e) => {
                      const updated = { ...phraseOptions, capitalize: e.target.checked };
                      setPhraseOptions(updated);
                      setGenerated(generatePassphrase(updated));
                    }}
                    className="rounded accent-emerald-500"
                  />
                  Capitalize Words
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={phraseOptions.includeNumber}
                    onChange={(e) => {
                      const updated = { ...phraseOptions, includeNumber: e.target.checked };
                      setPhraseOptions(updated);
                      setGenerated(generatePassphrase(updated));
                    }}
                    className="rounded accent-emerald-500"
                  />
                  Append Number
                </label>
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="pt-3 border-t border-neutral-800 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg text-xs font-medium text-neutral-400 hover:text-neutral-200 transition"
            >
              Close
            </button>
            {onSelectPassword && (
              <button
                type="button"
                onClick={() => {
                  onSelectPassword(generated);
                  onClose();
                }}
                className="px-4 py-2 rounded-xl text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition"
              >
                Use Password
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
