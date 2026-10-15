import React, { useState } from "react";
import { Copy, Eye, Plus, Search, Tag } from "lucide-react";
import type { DecryptedSecretItem } from "../types.js";

interface SecretListViewProps {
  secrets: DecryptedSecretItem[];
  selectedTag: string | null;
  onSelectTag: (tag: string | null) => void;
  onOpenCreate: () => void;
  onSelectSecret: (secretId: string) => void;
  onRevealSingle: (secretId: string) => Promise<{ value: string; cleanup: () => void }>;
  onCopySecret: (secretId: string) => Promise<void>;
}

export const SecretListView: React.FC<SecretListViewProps> = ({
  secrets,
  selectedTag,
  onSelectTag,
  onOpenCreate,
  onSelectSecret,
  onRevealSingle,
  onCopySecret,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [revealedSecretId, setRevealedSecretId] = useState<string | null>(null);
  const [revealedValue, setRevealedValue] = useState<string>("");
  const [cleanupFn, setCleanupFn] = useState<(() => void) | null>(null);

  // Extract unique tags across all secrets
  const allTags = Array.from(new Set(secrets.flatMap((s) => s.metadata.tags))).sort();

  // Filter secrets by search query and active tag filter
  const filteredSecrets = secrets.filter((s) => {
    if (selectedTag && !s.metadata.tags.includes(selectedTag)) {
      return false;
    }
    if (!searchQuery.trim()) {
      return true;
    }
    const q = searchQuery.toLowerCase();
    return (
      s.metadata.name.toLowerCase().includes(q) ||
      (s.metadata.description && s.metadata.description.toLowerCase().includes(q)) ||
      s.id.toLowerCase().includes(q) ||
      s.metadata.tags.some((t) => t.toLowerCase().includes(q))
    );
  });

  const handlePointerDownReveal = async (secretId: string) => {
    try {
      const res = await onRevealSingle(secretId);
      setRevealedSecretId(secretId);
      setRevealedValue(res.value);
      setCleanupFn(() => res.cleanup);
    } catch {
      // Ignored if unable to reveal
    }
  };

  const handlePointerUpReveal = () => {
    if (cleanupFn) {
      cleanupFn();
      setCleanupFn(null);
    }
    setRevealedSecretId(null);
    setRevealedValue("");
  };

  return (
    <div className="max-w-6xl mx-auto py-6 px-4">
      {/* Search & Actions Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between mb-6">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-neutral-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search secrets by name, tag, or ULID..."
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-neutral-900 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <button
          type="button"
          onClick={onOpenCreate}
          className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition shrink-0"
        >
          <Plus className="h-4 w-4" />
          New Secret
        </button>
      </div>

      {/* Tag Filters */}
      {allTags.length > 0 && (
        <div className="flex items-center gap-1.5 overflow-x-auto pb-3 mb-4 scrollbar-none">
          <button
            type="button"
            onClick={() => onSelectTag(null)}
            className={`px-2.5 py-1 rounded-full text-xs font-medium transition shrink-0 ${
              selectedTag === null
                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                : "bg-neutral-900 text-neutral-400 border border-neutral-800 hover:text-neutral-200"
            }`}
          >
            All Items ({secrets.length})
          </button>
          {allTags.map((tag) => (
            <button
              key={tag}
              type="button"
              onClick={() => onSelectTag(selectedTag === tag ? null : tag)}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium transition shrink-0 ${
                selectedTag === tag
                  ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                  : "bg-neutral-900 text-neutral-400 border border-neutral-800 hover:text-neutral-200"
              }`}
            >
              <Tag className="h-3 w-3" />
              {tag}
            </button>
          ))}
        </div>
      )}

      {/* Secret Cards List */}
      {filteredSecrets.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-neutral-800 rounded-2xl bg-neutral-900/50">
          <p className="text-sm font-medium text-neutral-300">No secrets found</p>
          <p className="text-xs text-neutral-500 mt-1">
            {searchQuery || selectedTag
              ? "Try clearing your search or filter tags."
              : "Store your first credential with zero-knowledge envelope encryption."}
          </p>
          {!searchQuery && !selectedTag && (
            <button
              type="button"
              onClick={onOpenCreate}
              className="mt-4 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition"
            >
              <Plus className="h-3.5 w-3.5" />
              Add Secret
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {filteredSecrets.map((secret) => {
            const isRevealed = revealedSecretId === secret.id;

            return (
              <div
                key={secret.id}
                className="p-4 rounded-xl bg-neutral-900 border border-neutral-800 hover:border-neutral-700 transition flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <button
                      type="button"
                      onClick={() => onSelectSecret(secret.id)}
                      className="text-left font-semibold text-sm text-neutral-100 hover:text-emerald-400 transition truncate"
                    >
                      {secret.metadata.name}
                    </button>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-400 border border-neutral-700 shrink-0">
                      v{secret.version}
                    </span>
                  </div>

                  <p className="font-mono text-[11px] text-neutral-500 mb-2 truncate">
                    {secret.id}
                  </p>

                  {secret.metadata.description && (
                    <p className="text-xs text-neutral-400 line-clamp-2 mb-3">
                      {secret.metadata.description}
                    </p>
                  )}

                  {secret.metadata.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-4">
                      {secret.metadata.tags.map((t) => (
                        <span
                          key={t}
                          className="px-2 py-0.5 rounded text-[10px] font-medium bg-neutral-800 text-neutral-300"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-neutral-800/80 flex items-center justify-between gap-2">
                  {/* Hold to reveal interaction */}
                  <button
                    type="button"
                    onPointerDown={() => handlePointerDownReveal(secret.id)}
                    onPointerUp={handlePointerUpReveal}
                    onPointerLeave={handlePointerUpReveal}
                    onPointerCancel={handlePointerUpReveal}
                    className="flex-1 flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-mono font-medium bg-neutral-800 hover:bg-neutral-700 active:bg-emerald-950/60 active:border-emerald-600 text-neutral-300 select-none border border-neutral-700 transition truncate"
                    title="Press and hold to reveal value; releasing zeroes memory and re-masks"
                  >
                    <Eye className="h-3 w-3 shrink-0" />
                    <span className="truncate">
                      {isRevealed ? revealedValue || "(empty)" : "••••••••••••"}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => onCopySecret(secret.id)}
                    className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-200 border border-neutral-700 transition flex items-center gap-1"
                    title="Copy to clipboard with 30s auto-wipe timer"
                  >
                    <Copy className="h-3.5 w-3.5" />
                    Copy
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
