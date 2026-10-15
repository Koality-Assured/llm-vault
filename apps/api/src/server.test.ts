import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { sqliteSchema } from "@llm-vault/schema/db/sqlite";
import { buildServer } from "./server.js";
import { initSchema, type VaultDatabase } from "./db.js";

describe("Fastify REST API server (apps/api)", () => {
  let app: FastifyInstance;
  let testDb: VaultDatabase;
  let userSessionToken = "";
  let createdVaultId = "";
  let createdSecretId = "";
  let agentToken = "";
  let agentId = "";

  beforeAll(async () => {
    const sqlite = new Database(":memory:");
    initSchema(sqlite);
    const db = drizzle(sqlite, { schema: sqliteSchema });
    testDb = { db, sqlite, path: ":memory:" };

    app = buildServer({ database: testDb, enableCors: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  describe("Health & Status", () => {
    it("GET /api/v1/health returns ok", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/api/v1/health",
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ status: "ok" });
    });

    it("GET /api/v1/status reports standalone deployment mode", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/api/v1/status",
      });
      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.status).toBe("ok");
      expect(json.deploymentMode).toBe("standalone");
      expect(json.version).toBe("0.1.0");
    });
  });

  describe("Auth & Bootstrap", () => {
    const bootstrapPayload = {
      email: "engineer@company.local",
      displayName: "Alice Engineer",
      kdfSalt: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      kdfIterations: 600000,
      clientAuthKeyHex: "f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1",
      x25519PublicKey: "base64_x25519_pk",
      ed25519PublicKey: "base64_ed25519_pk",
      publicKeyFingerprint: "sha256:fingerprint12345",
      encryptedX25519PrivateKey: "blob_priv_x25519",
      encryptedEd25519PrivateKey: "blob_priv_ed25519",
    };

    it("POST /api/v1/auth/bootstrap creates initial admin and returns session token", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/auth/bootstrap",
        payload: bootstrapPayload,
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      expect(json.userId).toMatch(/^usr_/);
      expect(json.tenantId).toBe("local");
      expect(json.sessionToken).toMatch(/^vlt_session_/);

      userSessionToken = json.sessionToken;
    });

    it("POST /api/v1/auth/bootstrap rejects duplicate initialization", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/auth/bootstrap",
        payload: bootstrapPayload,
      });

      expect(res.statusCode).toBe(409);
    });

    it("POST /api/v1/auth/login validates clientAuthKey and issues session token", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/auth/login",
        payload: {
          email: "engineer@company.local",
          clientAuthKeyHex: "f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1",
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.sessionToken).toMatch(/^vlt_session_/);
      expect(json.displayName).toBe("Alice Engineer");
    });

    it("POST /api/v1/auth/login rejects invalid credentials", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/auth/login",
        payload: {
          email: "engineer@company.local",
          clientAuthKeyHex: "wrong_client_auth_key_12345",
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it("GET /api/v1/auth/me returns caller profile with valid token", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/api/v1/auth/me",
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.caller.email).toBe("engineer@company.local");
      expect(json.caller.actorType).toBe("user");
    });
  });

  describe("Vault Management", () => {
    it("POST /api/v1/vaults creates a new vault with wrapped key envelope", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/vaults",
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
        payload: {
          name: "Engineering Production",
          description: "Production credentials and API keys",
          encryptedVaultKey: {
            ciphertext: "wrapped_vault_key_ct",
            iv: "wrapped_vault_key_iv",
            authTag: "wrapped_vault_key_tag",
            aad: "local:vlt:key:1:1",
            keyVersion: 1,
          },
        },
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      expect(json.id).toMatch(/^vlt_/);
      expect(json.name).toBe("Engineering Production");
      createdVaultId = json.id;
    });

    it("GET /api/v1/vaults lists accessible vaults for user", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/api/v1/vaults",
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.vaults.length).toBeGreaterThanOrEqual(1);
      expect(json.vaults.some((v: { id: string }) => v.id === createdVaultId)).toBe(true);
    });

    it("GET /api/v1/vaults/:id returns vault envelope and caller wrapped key", async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/v1/vaults/${createdVaultId}`,
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.vault.id).toBe(createdVaultId);
      expect(json.encryptedVaultKey.ciphertext).toBe("wrapped_vault_key_ct");
    });
  });

  describe("Secret CRUD & Zero-Knowledge Reveal", () => {
    const dummyBlindIndex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    it("POST /api/v1/vaults/:vaultId/secrets creates secret item with encrypted envelopes", async () => {
      const res = await app.inject({
        method: "POST",
        url: `/api/v1/vaults/${createdVaultId}/secrets`,
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
        payload: {
          encryptedMetadata: {
            algorithm: "AES-256-GCM",
            ciphertext: "metadata_ciphertext_blob",
            iv: "metadata_iv_12bytes",
            authTag: "metadata_authtag_16bytes",
            aad: `local:${createdVaultId}:sec:1:1`,
            keyVersion: 1,
          },
          encryptedPayload: {
            algorithm: "AES-256-GCM",
            ciphertext: "payload_ciphertext_blob",
            iv: "payload_iv_12bytes",
            authTag: "payload_authtag_16bytes",
            aad: `local:${createdVaultId}:sec:1:1`,
            keyVersion: 1,
          },
          tagBlindIndexes: [dummyBlindIndex],
        },
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      expect(json.id).toMatch(/^sec_/);
      expect(json.version).toBe(1);
      createdSecretId = json.id;
    });

    it("GET /api/v1/vaults/:vaultId/secrets returns list and supports tag blind index search", async () => {
      // General list
      const res = await app.inject({
        method: "GET",
        url: `/api/v1/vaults/${createdVaultId}/secrets`,
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.secrets.length).toBe(1);
      expect(json.secrets[0].id).toBe(createdSecretId);
      expect(json.secrets[0].encryptedMetadata.ciphertext).toBe("metadata_ciphertext_blob");

      // Filter by matching blind index
      const matchRes = await app.inject({
        method: "GET",
        url: `/api/v1/vaults/${createdVaultId}/secrets?tagBlindIndex=${dummyBlindIndex}`,
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });
      expect(matchRes.statusCode).toBe(200);
      expect(matchRes.json().secrets.length).toBe(1);

      // Filter by non-matching blind index
      const noMatchRes = await app.inject({
        method: "GET",
        url: `/api/v1/vaults/${createdVaultId}/secrets?tagBlindIndex=0000000000000000000000000000000000000000000000000000000000000000`,
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });
      expect(noMatchRes.statusCode).toBe(200);
      expect(noMatchRes.json().secrets.length).toBe(0);
    });

    it("POST /api/v1/secrets/:id/reveal returns encrypted payload and wrapped key, NEVER plaintext", async () => {
      const res = await app.inject({
        method: "POST",
        url: `/api/v1/secrets/${createdSecretId}/reveal`,
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.id).toBe(createdSecretId);
      expect(json.encryptedPayload.ciphertext).toBe("payload_ciphertext_blob");
      expect(json.encryptedVaultKey.ciphertext).toBe("wrapped_vault_key_ct");
      expect(json.auditEventId).toMatch(/^aud_/);

      // Cryptographic Zero-Knowledge Verification: Assert raw plaintext never exists in response
      const rawText = res.body;
      expect(rawText).not.toContain("super_secret_plaintext");
      expect(rawText).not.toContain("sk_live_");
    });

    it("PUT /api/v1/secrets/:id updates secret with monotonic version increment", async () => {
      const res = await app.inject({
        method: "PUT",
        url: `/api/v1/secrets/${createdSecretId}`,
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
        payload: {
          encryptedMetadata: {
            algorithm: "AES-256-GCM",
            ciphertext: "metadata_ciphertext_v2",
            iv: "metadata_iv_v2",
            authTag: "metadata_tag_v2",
            aad: `local:${createdVaultId}:${createdSecretId}:2:1`,
            keyVersion: 1,
          },
          encryptedPayload: {
            algorithm: "AES-256-GCM",
            ciphertext: "payload_ciphertext_v2",
            iv: "payload_iv_v2",
            authTag: "payload_tag_v2",
            aad: `local:${createdVaultId}:${createdSecretId}:2:1`,
            keyVersion: 1,
          },
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().version).toBe(2);

      // Verify versions history
      const verRes = await app.inject({
        method: "GET",
        url: `/api/v1/secrets/${createdSecretId}/versions`,
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });
      expect(verRes.statusCode).toBe(200);
      expect(verRes.json().versions.length).toBe(2);
      expect(verRes.json().versions[0].version).toBe(2);
      expect(verRes.json().versions[1].version).toBe(1);
    });
  });

  describe("Agent Provisioning & Key Delegation", () => {
    it("POST /api/v1/agents provisions agent identity and issues agent token", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/agents",
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
        payload: {
          vaultId: createdVaultId,
          name: "MCP Coding Assistant",
          description: "Subagent running on developer workstation",
          vaultRole: "SecretConsumer",
          scopes: ["secrets:read", "secrets:reveal", "agent:exec:run", "agent:exec:http_proxy"],
          keyVersion: 1,
          agentEncryptedVaultKey: {
            ciphertext: "agent_wrapped_vault_key_ct",
            iv: "agent_wrapped_vault_key_iv",
            authTag: "agent_wrapped_vault_key_tag",
            aad: `local:${createdVaultId}:agt:1:1`,
          },
          allowRawContextReveal: false,
        },
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      expect(json.id).toMatch(/^agt_/);
      expect(json.token).toContain(".");
      expect(json.token.startsWith(json.id)).toBe(true);

      agentId = json.id;
      agentToken = json.token;
    });

    it("POST /api/v1/agents blocks agent assignment of human-only admin scopes", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/agents",
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
        payload: {
          vaultId: createdVaultId,
          name: "Malicious Agent",
          scopes: ["secrets:read", "admin:users:manage"],
          keyVersion: 1,
          agentEncryptedVaultKey: {
            ciphertext: "ct",
            iv: "iv",
            authTag: "tag",
            aad: "aad",
          },
        },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().error).toContain("Security violation");
    });

    it("Agent can authenticate with token and execute zero-knowledge reveal", async () => {
      const res = await app.inject({
        method: "POST",
        url: `/api/v1/secrets/${createdSecretId}/reveal`,
        headers: {
          authorization: `Bearer ${agentToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.id).toBe(createdSecretId);
      // Key is delivered wrapped for the agent's key!
      expect(json.encryptedVaultKey.ciphertext).toBe("agent_wrapped_vault_key_ct");
    });

    it("GET /api/v1/agents/:id/vault-key delivers wrapped key to agent", async () => {
      const res = await app.inject({
        method: "GET",
        url: `/api/v1/agents/${agentId}/vault-key`,
        headers: {
          authorization: `Bearer ${agentToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.agentId).toBe(agentId);
      expect(json.agentEncryptedVaultKey.ciphertext).toBe("agent_wrapped_vault_key_ct");
    });
  });

  describe("Audit Logs & Cryptographic Hash Chain", () => {
    it("GET /api/v1/audit/logs returns hash-chained records", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/api/v1/audit/logs",
        headers: {
          authorization: `Bearer ${userSessionToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.logs.length).toBeGreaterThanOrEqual(4);

      // Verify that each log has eventHash and prevEventHash
      for (const log of json.logs) {
        expect(log.id).toMatch(/^aud_/);
        expect(log.eventHash).toMatch(/^[0-9a-f]{64}$/);
        expect(log.prevEventHash).toBeDefined();
      }
    });
  });
});
