# @llm-vault/web

Zero-knowledge client-side web vault and browser security foundation for `llm-vault`.

## Overview

`@llm-vault/web` provides a standalone zero-knowledge browser vault interface for creating, managing, revealing, and rotating encrypted secrets. All cryptographic operations occur exclusively in the browser via W3C WebCrypto (`SubtleCrypto`). Master passphrases and plaintext secrets never touch persistent server storage or unencrypted browser storage.

## Security Architecture

- **Zero-Knowledge Encryption**: Master key material is derived client-side via PBKDF2-HMAC-SHA256 (600,000+ iterations) and expanded via HKDF-SHA256 into non-extractable `MasterEncryptionKey` and `ClientAuthKey`.
- **Envelope Encryption**: Secrets are encrypted using AES-256-GCM with canonical Additional Authenticated Data (AAD) binding `tenant_id`, `vault_id`, `secret_id`, `version`, and `key_version`.
- **In-Memory Hygiene**: Raw symmetric key buffers (`Uint8Array`) are zeroized in-place via `zeroizeBuffer()` upon vault lock, tab backgrounding (`visibilityState === "hidden"`), or window teardown (`beforeunload`).
- **Single-Secret On-Demand Decryption**: Secret values are decrypted into memory only on user request and return an explicit `cleanup()` callback that zeroizes buffer memory.
- **Clipboard Auto-Purge**: 30-second countdown with automatic clipboard clearing. If browser tab focus is lost, a queued purge clears the clipboard upon window focus restoration.
- **Strict Storage Boundaries**: Encrypted vault envelopes and secret records are persisted in IndexedDB (`llm_vault_client_db`). `localStorage` is restricted strictly to non-sensitive UI preferences (theme, auto-lock interval) and asserts against secret, password, or ciphertext fragments.
- **Content-Security-Policy**: Enforces `default-src 'self'`, `script-src 'self'`, `style-src 'self' 'unsafe-inline'`, and disallows inline scripts and external object loading.

## Development

```bash
# Run web vault dev server
npm run dev -w @llm-vault/web

# Build production bundle
npm run build -w @llm-vault/web

# Run test suite
npm test apps/web
```
