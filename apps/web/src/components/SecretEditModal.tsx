import React, { useEffect, useState } from "react";
import { Sparkles, X } from "lucide-react";
import type { DecryptedSecretItem } from "../types.js";

interface SecretEditModalProps {
  existingSecret?: DecryptedSecretItem | null | undefined;
  onClose: () => void;
  onSave: (data: {
    name: string;
    value: string;
    description?: string | undefined;
    notes?: string | undefined;
    tags: string[];
  }) => Promise<void>;
  onOpenGenerator: (onSelectPassword: (pass: string) => void) => void;
  onGetInitialValue?:
    ((secretId: string) => Promise<{ value: string; notes?: string | undefined }>) | undefined;
}

export const SecretEditModal: React.FC<SecretEditModalProps> = ({
  existingSecret,
  onClose,
  onSave,
  onOpenGenerator,
  onGetInitialValue,
}) => {
  const [name, setName] = useState(existingSecret?.metadata.name ?? "");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState(existingSecret?.metadata.description ?? "");
  const [notes, setNotes] = useState("");
  const [tagsStr, setTagsStr] = useState(existingSecret?.metadata.tags.join(", ") ?? "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (existingSecret && onGetInitialValue) {
      onGetInitialValue(existingSecret.id).then((val) => {
        setValue(val.value);
        if (val.notes) setNotes(val.notes);
      });
    }
  }, [existingSecret, onGetInitialValue]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    if (!value) {
      setError("Secret value is required.");
      return;
    }

    const tags = tagsStr
      .split(",")
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);

    setLoading(true);
    setError(null);
    try {
      await onSave({
        name: name.trim(),
        value,
        description: description.trim() || undefined,
        notes: notes.trim() || undefined,
        tags,
      });
      onClose();
    } catch (err) {
      setError((err as Error).message || "Failed to save secret.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-neutral-900 border border-neutral-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-5 py-4 border-b border-neutral-800 flex items-center justify-between">
          <span className="font-semibold text-sm text-neutral-100">
            {existingSecret ? `Edit Secret: ${existingSecret.metadata.name}` : "Create New Secret"}
          </span>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg text-neutral-400 hover:text-neutral-100 hover:bg-neutral-800 transition"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 overflow-y-auto flex-1">
          {error && (
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300">
              {error}
            </div>
          )}

          <div>
            <label
              htmlFor="secret-name-input"
              className="block text-xs font-medium text-neutral-300 mb-1.5"
            >
              Secret Name *
            </label>
            <input
              id="secret-name-input"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. AWS Production Access Key"
              className="w-full px-3 py-2 rounded-xl bg-neutral-950 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
              required
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label
                htmlFor="secret-value-input"
                className="block text-xs font-medium text-neutral-300"
              >
                Secret Value *
              </label>
              <button
                type="button"
                onClick={() => onOpenGenerator((generated) => setValue(generated))}
                className="inline-flex items-center gap-1 text-[11px] text-amber-400 hover:text-amber-300 transition"
              >
                <Sparkles className="h-3 w-3" />
                Generate Secure Value
              </button>
            </div>
            <textarea
              id="secret-value-input"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="Paste or generate secret value..."
              rows={3}
              className="w-full px-3 py-2 rounded-xl bg-neutral-950 border border-neutral-800 text-xs font-mono text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
              required
            />
          </div>

          <div>
            <label
              htmlFor="secret-desc-input"
              className="block text-xs font-medium text-neutral-300 mb-1.5"
            >
              Description (Optional)
            </label>
            <input
              id="secret-desc-input"
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description or purpose..."
              className="w-full px-3 py-2 rounded-xl bg-neutral-950 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label
              htmlFor="secret-tags-input"
              className="block text-xs font-medium text-neutral-300 mb-1.5"
            >
              Tags (Comma separated)
            </label>
            <input
              id="secret-tags-input"
              type="text"
              value={tagsStr}
              onChange={(e) => setTagsStr(e.target.value)}
              placeholder="e.g. aws, prod, database"
              className="w-full px-3 py-2 rounded-xl bg-neutral-950 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
            />
            <p className="text-[11px] text-neutral-500 mt-1">
              Tags are indexed on the server via keyed HMAC-SHA256 blind indexes.
            </p>
          </div>

          <div>
            <label
              htmlFor="secret-notes-input"
              className="block text-xs font-medium text-neutral-300 mb-1.5"
            >
              Encrypted Notes (Optional)
            </label>
            <textarea
              id="secret-notes-input"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Additional operational instructions or metadata..."
              rows={2}
              className="w-full px-3 py-2 rounded-xl bg-neutral-950 border border-neutral-800 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="pt-3 border-t border-neutral-800 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg text-xs font-medium text-neutral-400 hover:text-neutral-200 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 rounded-xl text-xs font-medium bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white transition"
            >
              {loading
                ? "Encrypting & Storing..."
                : existingSecret
                  ? "Save New Version"
                  : "Save Secret"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
