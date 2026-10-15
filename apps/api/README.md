# @llm-vault/api

Lightweight standalone Fastify REST API backend for `llm-vault`.

## Overview

`@llm-vault/api` provides the server-side persistence layer and zero-knowledge synchronization plane for both the web vault (`@llm-vault/web`) and the Model Context Protocol server (`llm-vault-mcp`). In `DEPLOYMENT_MODE=standalone`, the API operates locally using embedded SQLite storage (`~/.llm-vault/vault.db`), requiring no external database or cloud dependencies.

## Security Architecture

- **Zero Plaintext Invariant**: Plaintext secret values and unencrypted `VaultKey` bytes never touch the server. All secret metadata and payloads are stored as AES-256-GCM encrypted envelopes with canonical Additional Authenticated Data (AAD).
- **Zero-Knowledge `/reveal`**: `POST /api/v1/secrets/:id/reveal` verifies caller RBAC, records a tamper-evident audit entry, and returns only the encrypted secret payload and the caller's wrapped `EncryptedVaultKey`. Client applications decrypt the envelope locally in process memory.
- **ClientAuthKey Separation**: Client passwords are never sent to the server. Master passphrases are stretched client-side and split via HKDF-SHA256; only the separate `ClientAuthKey` hex token is sent to the API, where it is hashed with a per-user server salt before comparison or persistence.
- **Agent Delegation & Admin Isolation**: Agent identities (`agt_<ulid>`) receive scoped `AgentEncryptedVaultKey` grants created client-side by a human administrator. Administrative user, role, and IdP mutation scopes are strictly blocked from agent tokens.
- **Cryptographic Audit Hash Chain**: Every secret access, revelation, modification, and agent grant is appended to an immutable SHA-256 hash-chained log (`aud_<ulid>`).

## API Endpoints

- **Health & Status**: `GET /api/v1/health`, `GET /api/v1/status`
- **Auth**: `POST /api/v1/auth/bootstrap`, `POST /api/v1/auth/login`, `GET /api/v1/auth/me`
- **Vaults**: `POST /api/v1/vaults`, `GET /api/v1/vaults`, `GET /api/v1/vaults/:id`
- **Secrets**: `POST /api/v1/vaults/:vaultId/secrets`, `GET /api/v1/vaults/:vaultId/secrets` (supports `?tagBlindIndex=`), `GET /api/v1/secrets/:id`, `POST /api/v1/secrets/:id/reveal`, `PUT /api/v1/secrets/:id`, `DELETE /api/v1/secrets/:id`, `GET /api/v1/secrets/:id/versions`
- **Agents**: `POST /api/v1/agents`, `GET /api/v1/agents/:id/vault-key`
- **Audit**: `GET /api/v1/audit/logs`

## Development

```bash
# Run server in development mode
npm run dev -w @llm-vault/api

# Run integration tests
npm test apps/api
```
