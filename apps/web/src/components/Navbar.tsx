import React from "react";
import { KeyRound, Lock, ShieldCheck, Sparkles } from "lucide-react";
import type { VaultSessionState } from "../lib/session.js";

interface NavbarProps {
  session: VaultSessionState | null;
  onLock: () => void;
  onOpenGenerator: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ session, onLock, onOpenGenerator }) => {
  return (
    <header className="border-b border-neutral-800 bg-neutral-900/90 backdrop-blur px-4 py-3 sticky top-0 z-30">
      <div className="max-w-6xl mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-emerald-600/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <KeyRound className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-neutral-100 tracking-tight">llm-vault</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-neutral-800 text-neutral-400 border border-neutral-700">
                WebCrypto Zero-Knowledge
              </span>
            </div>
            {session && (
              <p className="text-xs text-neutral-400">
                Vault: <span className="text-neutral-200 font-medium">{session.vaultName}</span>
                <span className="text-neutral-500 ml-1.5 font-mono">({session.vaultId})</span>
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={onOpenGenerator}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-200 border border-neutral-700 transition"
          >
            <Sparkles className="h-3.5 w-3.5 text-amber-400" />
            Password Generator
          </button>

          {session ? (
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <ShieldCheck className="h-3.5 w-3.5" />
                Unlocked
              </span>
              <button
                type="button"
                onClick={onLock}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/50 transition"
              >
                <Lock className="h-3.5 w-3.5" />
                Lock Vault
              </button>
            </div>
          ) : (
            <span className="flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-neutral-800 text-neutral-400 border border-neutral-700">
              <Lock className="h-3.5 w-3.5" />
              Locked
            </span>
          )}
        </div>
      </div>
    </header>
  );
};
