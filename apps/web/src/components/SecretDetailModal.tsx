import React, { useEffect, useState } from "react";
import { Copy, Eye, History, RotateCcw, Trash2, X } from "lucide-react";
import type { StoredSecretVersion } from "../types.js";
import { listSecretVersions } from "../lib/storage.js";

interface SecretDetailModalProps {
  secretId: string;
  onClose: () => void;
  onEdit: (secretId: string) => void;
  onDelete: (secretId: string) => Promise<void>;
  onRollback: (secretId: string, targetVersion: number) => Promise<void>;
  onRevealSingle: (
    secretId: string,
  ) => Promise<{ value: string; notes?: string | undefined; cleanup: () => void }>;
  onCopySecret: (secretId: string) => Promise<void>;
}

export const SecretDetailModal: React.FC<SecretDetailModalProps> = ({
  secretId,
  onClose,
  onEdit,
  onDelete,
  onRollback,
  onRevealSingle,
  onCopySecret,
}) => {
  const [versions, setVersions] = useState<StoredSecretVersion[]>([]);
  const [revealedValue, setRevealedValue] = useState<string | null>(null);
  const [revealedNotes, setRevealedNotes] = useState<string | undefined>(undefined);
  const [cleanupFn, setCleanupFn] = useState<(() => void) | null>(null);
  const [rollbackLoading, setRollbackLoading] = useState(false);

  useEffect(() => {
    let mounted = true;
    listSecretVersions(secretId).then((v) => {
      if (mounted) setVersions(v);
    });
    return () => {
      mounted = false;
    };
  }, [secretId]);

  const handlePointerDown = async () => {
    try {
      const res = await onRevealSingle(secretId);
      setRevealedValue(res.value);
      setRevealedNotes(res.notes);
      setCleanupFn(() => res.cleanup);
    } catch {
      // Ignored
    }
  };

  const handlePointerUp = () => {
    if (cleanupFn) {
      cleanupFn();
      setCleanupFn(null);
    }
    setRevealedValue(null);
    setRevealedNotes(undefined);
  };

  const handleRollback = async (version: number) => {
    if (
      !window.confirm(
        `Rollback secret to version v${version}? This will commit a new version with those contents.`,
      )
    ) {
      return;
    }
    setRollbackLoading(true);
    try {
      await onRollback(secretId, version);
      const updatedVersions = await listSecretVersions(secretId);
      setVersions(updatedVersions);
    } finally {
      setRollbackLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-neutral-900 border border-neutral-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-5 py-4 border-b border-neutral-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-sm text-neutral-100">Secret Details</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-neutral-800 text-neutral-400 border border-neutral-700">
              {secretId}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg text-neutral-400 hover:text-neutral-100 hover:bg-neutral-800 transition"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-5 overflow-y-auto flex-1">
          {/* Secret Value Hold-to-Reveal Box */}
          <div>
            <label className="block text-xs font-medium text-neutral-400 mb-1.5">
              Secret Value (Hold to Reveal)
            </label>
            <div className="flex gap-2 items-center">
              <div
                onPointerDown={handlePointerDown}
                onPointerUp={handlePointerUp}
                onPointerLeave={handlePointerUp}
                onPointerCancel={handlePointerUp}
                className="flex-1 px-3 py-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-xs font-mono text-neutral-200 select-none cursor-pointer flex items-center justify-between"
                title="Hold pointer down to unmask; releasing immediately wipes buffer"
              >
                <span className="truncate">
                  {revealedValue !== null
                    ? revealedValue || "(empty string)"
                    : "••••••••••••••••••••••••"}
                </span>
                <Eye className="h-4 w-4 text-neutral-500 shrink-0 ml-2" />
              </div>

              <button
                type="button"
                onClick={() => onCopySecret(secretId)}
                className="px-3 py-2.5 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-neutral-200 border border-neutral-700 text-xs font-medium transition flex items-center gap-1.5 shrink-0"
              >
                <Copy className="h-3.5 w-3.5" />
                Copy
              </button>
            </div>
            {revealedNotes && (
              <div className="mt-2 p-2.5 rounded-lg bg-neutral-950 border border-neutral-800 text-xs text-neutral-300">
                <span className="font-semibold text-neutral-400">Notes:</span> {revealedNotes}
              </div>
            )}
          </div>

          {/* Version History */}
          <div>
            <div className="flex items-center gap-1.5 text-xs font-medium text-neutral-300 mb-2">
              <History className="h-3.5 w-3.5 text-emerald-400" />
              <span>Version History & Rollback</span>
            </div>
            <div className="border border-neutral-800 rounded-xl divide-y divide-neutral-800 overflow-hidden bg-neutral-950/60">
              {versions.length === 0 ? (
                <div className="p-3 text-xs text-neutral-500">No version records</div>
              ) : (
                versions.map((ver, idx) => (
                  <div
                    key={ver.version}
                    className="p-3 flex items-center justify-between text-xs hover:bg-neutral-900/60 transition"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-semibold text-neutral-200">
                          v{ver.version}
                        </span>
                        {idx === 0 && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                            Active
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-neutral-500 mt-0.5">
                        {new Date(ver.createdAt).toLocaleString()}
                      </p>
                    </div>

                    {idx > 0 && (
                      <button
                        type="button"
                        disabled={rollbackLoading}
                        onClick={() => handleRollback(ver.version)}
                        className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-200 border border-neutral-700 transition"
                      >
                        <RotateCcw className="h-3 w-3" />
                        Rollback
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="px-5 py-3 border-t border-neutral-800 bg-neutral-950 flex items-center justify-between">
          <button
            type="button"
            onClick={async () => {
              if (window.confirm("Permanently delete this secret and its history?")) {
                await onDelete(secretId);
                onClose();
              }
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-rose-400 hover:bg-rose-950/40 border border-rose-900/40 transition"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete Secret
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg text-xs font-medium text-neutral-400 hover:text-neutral-200 transition"
            >
              Close
            </button>
            <button
              type="button"
              onClick={() => {
                onClose();
                onEdit(secretId);
              }}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition"
            >
              Edit Secret
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
