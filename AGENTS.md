# Repository AGENTS

Canonical instructions for AI coding agents working in `Koality-Assured/llm-vault`.

## Purpose

`llm-vault` is an open-source, zero-knowledge secrets management platform built for autonomous AI agents (via Model Context Protocol and REST APIs) and human operators (via a browser web vault).

## Critical Architectural Invariants

1. **Zero-Knowledge Boundary**:
   - The backend server and database MUST NEVER receive or persist plaintext master passphrases, unwrapped private keys, unwrapped `VaultKey` material, or plaintext secret payloads.
   - All envelope encryption and decryption runs client-side in the browser or locally inside `llm-vault-mcp` via W3C WebCrypto (`globalThis.crypto.subtle`).
2. **Domain-Separated Key Derivation**:
   - Master key stretching uses `PBKDF2-HMAC-SHA256` (minimum 600,000 iterations, 32-byte random salt) or WASM `Argon2id` (64 MiB memory, 3 iterations, 4 lanes).
   - `HKDF-SHA256` expands master key material into domain-separated subkeys:
     - `MasterEncryptionKey` (`info = "llm-vault/v1/master-encryption-key"`): non-extractable 256-bit `AES-GCM` `CryptoKey`.
     - `ClientAuthKey` (`info = "llm-vault/v1/client-auth-key"`): 256-bit authentication material for `DEPLOYMENT_MODE=standalone`.
3. **Canonical AAD Binding**:
   - Every `AES-256-GCM` encryption and decryption call MUST bind canonical Additional Authenticated Data:
     `UTF8("${tenantId}:${vaultId}:${secretId}:${version}:${keyVersion}")`
   - Every encryption operation MUST generate a fresh 96-bit (12-byte) IV via `crypto.getRandomValues()` and verify a 128-bit (16-byte) authentication tag.
4. **Type-Prefixed Sortable ULIDs**:
   - All entity identifiers use lowercase Crockford Base32 ULIDs prefixed by entity type: `sec_`, `vlt_`, `fld_`, `usr_`, `agt_`, `lease_`, `aud_`.
5. **Memory Hygiene**:
   - Transient plaintext buffers (`Uint8Array` / `ArrayBuffer`) MUST be zeroized via `zeroizeBuffer()` immediately after use or lock transitions.

## Workspace Layout

- `packages/ids` (`@llm-vault/ids`): Type-prefixed sortable ULID generator, validator, and opaque secret handle formatter (`{{vault:sec_<ulid>}}`).
- `packages/crypto` (`@llm-vault/crypto`): Zero-knowledge W3C WebCrypto engine (`PBKDF2` / `Argon2id`, `HKDF-SHA256`, `AES-256-GCM` with canonical AAD, `X25519` / `Ed25519` key hierarchy, agent key wrapping, blind indexing, and hash-chained audit verification).
- `packages/schema` (`@llm-vault/schema`): Shared Zod validation schemas, RBAC permission types, and dual-dialect Drizzle ORM schemas (`PostgreSQL` for `enterprise` mode, `SQLite` for `standalone` mode).

## Verification Gates

Before committing or opening a pull request, run:

```bash
npm run lint
npm run format:check
npm run typecheck
npm test
```

All commits and pull request titles MUST follow Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `test:`).
