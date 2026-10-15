import React, { useState } from "react";
import { KeyRound, Lock, Plus, ShieldAlert, ShieldCheck } from "lucide-react";
import type { EncryptedVaultRecord } from "../types.js";

interface VaultLockViewProps {
  vaults: EncryptedVaultRecord[];
  selectedVaultId: string | null;
  onSelectVaultId: (id: string) => void;
  onUnlock: (vaultId: string, passphrase: string) => Promise<void>;
  onCreateVault: (name: string, passphrase: string, iterations: number) => Promise<void>;
}

export const VaultLockView: React.FC<VaultLockViewProps> = ({
  vaults,
  selectedVaultId,
  onSelectVaultId,
  onUnlock,
  onCreateVault,
}) => {
  const [activeTab, setActiveTab] = useState<"unlock" | "create">("unlock");
  const [passphrase, setPassphrase] = useState("");
  const [createName, setCreateName] = useState("");
  const [createPassphrase, setCreatePassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [iterations, setIterations] = useState(600_000);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const selectedVault = vaults.find((v) => v.id === selectedVaultId) ?? vaults[0] ?? null;

  const handleUnlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedVault) {
      setError("Please select or create a vault.");
      return;
    }
    if (!passphrase) {
      setError("Master passphrase is required.");
      return;
    }

    setError(null);
    setLoading(true);
    try {
      await onUnlock(selectedVault.id, passphrase);
      setPassphrase("");
    } catch (err) {
      setError((err as Error).message || "Failed to unlock vault.");
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createName.trim()) {
      setError("Vault name is required.");
      return;
    }
    if (createPassphrase.length < 8) {
      setError("Passphrase must be at least 8 characters.");
      return;
    }
    if (createPassphrase !== confirmPassphrase) {
      setError("Passphrases do not match.");
      return;
    }

    setError(null);
    setLoading(true);
    try {
      await onCreateVault(createName.trim(), createPassphrase, iterations);
      setCreateName("");
      setCreatePassphrase("");
      setConfirmPassphrase("");
      setActiveTab("unlock");
    } catch (err) {
      setError((err as Error).message || "Failed to create vault.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto my-12 p-6 rounded-2xl bg-neutral-900 border border-neutral-800 shadow-2xl">
      <div className="text-center mb-6">
        <div className="inline-flex h-12 w-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 items-center justify-center text-emerald-400 mb-3">
          <Lock className="h-6 w-6" />
        </div>
        <h1 className="text-xl font-bold text-neutral-100 tracking-tight">Zero-Knowledge Vault</h1>
        <p className="text-xs text-neutral-400 mt-1">
          Keys are derived client-side via PBKDF2-HMAC-SHA256 (600,000+ iter) & AES-256-GCM.
        </p>
      </div>

      <div className="flex border-b border-neutral-800 mb-5">
        <button
          type="button"
          onClick={() => {
            setActiveTab("unlock");
            setError(null);
          }}
          className={`flex-1 py-2 text-xs font-semibold text-center border-b-2 transition ${
            activeTab === "unlock"
              ? "border-emerald-500 text-emerald-400"
              : "border-transparent text-neutral-400 hover:text-neutral-200"
          }`}
        >
          Unlock Existing Vault
        </button>
        <button
          type="button"
          onClick={() => {
            setActiveTab("create");
            setError(null);
          }}
          className={`flex-1 py-2 text-xs font-semibold text-center border-b-2 transition ${
            activeTab === "create"
              ? "border-emerald-500 text-emerald-400"
              : "border-transparent text-neutral-400 hover:text-neutral-200"
          }`}
        >
          Create New Vault
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 flex items-start gap-2">
          <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {activeTab === "unlock" ? (
        vaults.length === 0 ? (
          <div className="text-center py-6">
            <p className="text-xs text-neutral-400 mb-4">No vaults found in local storage.</p>
            <button
              type="button"
              onClick={() => setActiveTab("create")}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition"
            >
              <Plus className="h-3.5 w-3.5" />
              Create Your First Vault
            </button>
          </div>
        ) : (
          <form onSubmit={handleUnlockSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="vault-select"
                className="block text-xs font-medium text-neutral-300 mb-1.5"
              >
                Select Vault
              </label>
              <select
                id="vault-select"
                aria-label="Select Vault"
                value={selectedVault?.id ?? ""}
                onChange={(e) => onSelectVaultId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-neutral-950 border border-neutral-800 text-xs text-neutral-200 focus:outline-none focus:border-emerald-500"
              >
                {vaults.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name} ({v.id})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="vault-passphrase"
                className="block text-xs font-medium text-neutral-300 mb-1.5"
              >
                Master Passphrase
              </label>
              <input
                id="vault-passphrase"
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter master passphrase to unlock..."
                className="w-full px-3 py-2 rounded-lg bg-neutral-950 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
                autoFocus
              />
            </div>

            <div className="flex items-center justify-between text-xs text-neutral-500 pt-1">
              <span>PBKDF2 Iterations:</span>
              <span className="font-mono text-neutral-300">
                {selectedVault?.iterations.toLocaleString() ?? "600,000"}
              </span>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white transition flex items-center justify-center gap-1.5"
            >
              {loading ? (
                <>
                  <KeyRound className="h-3.5 w-3.5 animate-spin" />
                  Stretching & Deriving Keys...
                </>
              ) : (
                <>
                  <ShieldCheck className="h-3.5 w-3.5" />
                  Unlock Vault
                </>
              )}
            </button>
          </form>
        )
      ) : (
        <form onSubmit={handleCreateSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="create-vault-name"
              className="block text-xs font-medium text-neutral-300 mb-1.5"
            >
              Vault Name
            </label>
            <input
              id="create-vault-name"
              type="text"
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              placeholder="e.g. Work Secrets, Personal"
              className="w-full px-3 py-2 rounded-lg bg-neutral-950 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
              required
            />
          </div>

          <div>
            <label
              htmlFor="create-vault-passphrase"
              className="block text-xs font-medium text-neutral-300 mb-1.5"
            >
              Master Passphrase
            </label>
            <input
              id="create-vault-passphrase"
              type="password"
              value={createPassphrase}
              onChange={(e) => setCreatePassphrase(e.target.value)}
              placeholder="Choose a strong master passphrase..."
              className="w-full px-3 py-2 rounded-lg bg-neutral-950 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
              required
            />
          </div>

          <div>
            <label
              htmlFor="create-vault-confirm-passphrase"
              className="block text-xs font-medium text-neutral-300 mb-1.5"
            >
              Confirm Master Passphrase
            </label>
            <input
              id="create-vault-confirm-passphrase"
              type="password"
              value={confirmPassphrase}
              onChange={(e) => setConfirmPassphrase(e.target.value)}
              placeholder="Re-enter master passphrase..."
              className="w-full px-3 py-2 rounded-lg bg-neutral-950 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
              required
            />
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-neutral-300 mb-1.5">
              <label htmlFor="create-vault-iterations">PBKDF2 Iteration Baseline</label>
              <span className="font-mono text-emerald-400">{iterations.toLocaleString()}</span>
            </div>
            <select
              id="create-vault-iterations"
              aria-label="PBKDF2 Iteration Baseline"
              value={iterations}
              onChange={(e) => setIterations(Number(e.target.value))}
              className="w-full px-3 py-2 rounded-lg bg-neutral-950 border border-neutral-800 text-xs text-neutral-200 focus:outline-none focus:border-emerald-500"
            >
              <option value={600000}>600,000 (NIST / OWASP Recommended Standard)</option>
              <option value={1000000}>1,000,000 (Maximum GPU Hardening)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white transition flex items-center justify-center gap-1.5"
          >
            {loading ? (
              <>
                <KeyRound className="h-3.5 w-3.5 animate-spin" />
                Generating Keys & Encrypting...
              </>
            ) : (
              <>
                <Plus className="h-3.5 w-3.5" />
                Create Zero-Knowledge Vault
              </>
            )}
          </button>
        </form>
      )}
    </div>
  );
};
