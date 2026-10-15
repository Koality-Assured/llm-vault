import React, { useEffect, useState } from "react";
import { ClipboardTimerBar } from "./components/ClipboardTimerBar.js";
import { Navbar } from "./components/Navbar.js";
import { PasswordGeneratorModal } from "./components/PasswordGeneratorModal.js";
import { SecretDetailModal } from "./components/SecretDetailModal.js";
import { SecretEditModal } from "./components/SecretEditModal.js";
import { SecretListView } from "./components/SecretListView.js";
import { VaultLockView } from "./components/VaultLockView.js";
import { copySecretToClipboard } from "./lib/clipboard.js";
import {
  createNewVault,
  createSecretItem,
  deleteSecret,
  loadDecryptedSecretList,
  lockVaultSession,
  revealSecretPayload,
  rollbackSecretItem,
  subscribeVaultSession,
  unlockVault,
  updateSecretItem,
  type VaultSessionState,
} from "./lib/session.js";
import { getUserPreferences, listVaultRecords, saveUserPreferences } from "./lib/storage.js";
import type { DecryptedSecretItem, EncryptedVaultRecord } from "./types.js";

export const App: React.FC = () => {
  const [session, setSession] = useState<VaultSessionState | null>(null);
  const [vaults, setVaults] = useState<EncryptedVaultRecord[]>([]);
  const [selectedVaultId, setSelectedVaultId] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<DecryptedSecretItem[]>([]);
  const [selectedTag, setSelectedTag] = useState<string | null>(null);

  // Modals
  const [isGeneratorOpen, setIsGeneratorOpen] = useState(false);
  const [generatorCallback, setGeneratorCallback] = useState<((p: string) => void) | null>(null);
  const [detailSecretId, setDetailSecretId] = useState<string | null>(null);
  const [editingSecret, setEditingSecret] = useState<DecryptedSecretItem | null>(null);
  const [isCreatingSecret, setIsCreatingSecret] = useState(false);

  // Initial load
  useEffect(() => {
    listVaultRecords().then((list) => {
      setVaults(list);
      const prefs = getUserPreferences();
      if (prefs.lastVaultId && list.some((v) => v.id === prefs.lastVaultId)) {
        setSelectedVaultId(prefs.lastVaultId);
      } else if (list.length > 0) {
        setSelectedVaultId(list[0]!.id);
      }
    });

    return subscribeVaultSession(setSession);
  }, []);

  // When session unlocks or updates, refresh secret catalog
  useEffect(() => {
    if (session) {
      loadDecryptedSecretList(session).then(setSecrets);
    } else {
      setSecrets([]);
      setDetailSecretId(null);
      setEditingSecret(null);
      setIsCreatingSecret(false);
    }
  }, [session]);

  const handleUnlock = async (vaultId: string, passphrase: string) => {
    const prefs = getUserPreferences();
    await unlockVault(vaultId, passphrase, prefs.autoLockTimeoutMinutes);
    saveUserPreferences({ ...prefs, lastVaultId: vaultId });
  };

  const handleCreateVault = async (name: string, passphrase: string, iterations: number) => {
    const prefs = getUserPreferences();
    const newRecord = await createNewVault(
      name,
      passphrase,
      iterations,
      prefs.autoLockTimeoutMinutes,
    );
    const updatedVaults = await listVaultRecords();
    setVaults(updatedVaults);
    setSelectedVaultId(newRecord.id);
    saveUserPreferences({ ...prefs, lastVaultId: newRecord.id });
  };

  const handleRevealSingle = async (secretId: string) => {
    if (!session) {
      throw new Error("Vault is locked.");
    }
    const { payload, cleanup } = await revealSecretPayload(session, secretId);
    return {
      value: payload.value,
      notes: payload.notes,
      cleanup,
    };
  };

  const handleCopySecret = async (secretId: string) => {
    if (!session) return;
    const { payload, cleanup } = await revealSecretPayload(session, secretId);
    try {
      await copySecretToClipboard(payload.value, secretId, 30);
    } finally {
      cleanup();
    }
  };

  const handleSaveSecret = async (data: {
    name: string;
    value: string;
    description?: string | undefined;
    notes?: string | undefined;
    tags: string[];
  }) => {
    if (!session) return;
    if (editingSecret) {
      await updateSecretItem(session, editingSecret.id, data);
    } else {
      await createSecretItem(session, data);
    }
    const refreshed = await loadDecryptedSecretList(session);
    setSecrets(refreshed);
  };

  const handleDeleteSecret = async (secretId: string) => {
    await deleteSecret(secretId);
    if (session) {
      const refreshed = await loadDecryptedSecretList(session);
      setSecrets(refreshed);
    }
  };

  const handleRollbackSecret = async (secretId: string, targetVersion: number) => {
    if (!session) return;
    await rollbackSecretItem(session, secretId, targetVersion);
    const refreshed = await loadDecryptedSecretList(session);
    setSecrets(refreshed);
  };

  return (
    <div className="min-h-screen flex flex-col bg-neutral-950 text-neutral-100">
      <Navbar
        session={session}
        onLock={lockVaultSession}
        onOpenGenerator={() => {
          setGeneratorCallback(null);
          setIsGeneratorOpen(true);
        }}
      />

      <main className="flex-1">
        {!session ? (
          <VaultLockView
            vaults={vaults}
            selectedVaultId={selectedVaultId}
            onSelectVaultId={setSelectedVaultId}
            onUnlock={handleUnlock}
            onCreateVault={handleCreateVault}
          />
        ) : (
          <SecretListView
            secrets={secrets}
            selectedTag={selectedTag}
            onSelectTag={setSelectedTag}
            onOpenCreate={() => {
              setEditingSecret(null);
              setIsCreatingSecret(true);
            }}
            onSelectSecret={(id) => setDetailSecretId(id)}
            onRevealSingle={handleRevealSingle}
            onCopySecret={handleCopySecret}
          />
        )}
      </main>

      {/* Secret Detail & History Modal */}
      {session && detailSecretId && (
        <SecretDetailModal
          secretId={detailSecretId}
          onClose={() => setDetailSecretId(null)}
          onEdit={(id) => {
            const found = secrets.find((s) => s.id === id);
            if (found) setEditingSecret(found);
          }}
          onDelete={handleDeleteSecret}
          onRollback={handleRollbackSecret}
          onRevealSingle={handleRevealSingle}
          onCopySecret={handleCopySecret}
        />
      )}

      {/* Secret Create / Edit Modal */}
      {session && (isCreatingSecret || editingSecret) && (
        <SecretEditModal
          existingSecret={editingSecret}
          onClose={() => {
            setIsCreatingSecret(false);
            setEditingSecret(null);
          }}
          onSave={handleSaveSecret}
          onOpenGenerator={(callback) => {
            setGeneratorCallback(() => callback);
            setIsGeneratorOpen(true);
          }}
          onGetInitialValue={async (id) => {
            if (!session) return { value: "" };
            const { payload, cleanup } = await revealSecretPayload(session, id);
            const copy = { value: payload.value, notes: payload.notes };
            cleanup();
            return copy;
          }}
        />
      )}

      {/* Standalone Password Generator Modal */}
      {isGeneratorOpen && (
        <PasswordGeneratorModal
          onClose={() => setIsGeneratorOpen(false)}
          onSelectPassword={(generated) => {
            if (generatorCallback) {
              generatorCallback(generated);
            }
          }}
          onCopyClipboard={async (val) => {
            await copySecretToClipboard(val, "generated_pass", 30);
          }}
        />
      )}

      {/* Persistent Clipboard Auto-Wipe Bar */}
      <ClipboardTimerBar />
    </div>
  );
};
