import crypto from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { eq } from "drizzle-orm";
import { sqliteSchema } from "@llm-vault/schema/db/sqlite";
import { generateEntityId } from "@llm-vault/ids";
import {
  createTestWorkloadJwt,
  generateOrgRecoveryKeyPair,
  generateTotpCode,
  generateTotpSecret,
  generateVaultKeyBytes,
  splitRecoveryKey,
  wrapVaultKeyWithOrgRecoveryKey,
} from "@llm-vault/crypto";
import { buildServer } from "./server.js";
import { initSchema, type VaultDatabase } from "./db.js";
import { createMockSamlResponseXml, issueSessionToken } from "./auth.js";

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

  describe("Slice 3: Enterprise Backend, SSO Ceremony & Multi-Tenant Sharing", () => {
    let enterpriseApp: FastifyInstance;
    let enterpriseDb: VaultDatabase;
    let entAdminToken = "";
    let entAdminUserId = "";
    let entTenantId = "";
    let sharedVaultId = "";
    let memberUserId = "";
    let totpSecretBase32 = "";

    beforeAll(async () => {
      const sqlite = new Database(":memory:");
      initSchema(sqlite);
      const db = drizzle(sqlite, { schema: sqliteSchema });
      enterpriseDb = { db, sqlite, path: ":memory:" };

      enterpriseApp = buildServer({
        database: enterpriseDb,
        enableCors: false,
        deploymentMode: "enterprise",
      });
      await enterpriseApp.ready();

      const { secretBase32 } = generateTotpSecret(20);
      totpSecretBase32 = secretBase32;

      // Bootstrap enterprise break-glass admin
      const res = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/auth/bootstrap",
        payload: {
          email: "superadmin@corp.enterprise",
          displayName: "Enterprise Break-Glass Admin",
          kdfSalt: "1122334455661122334455661122334455661122334455661122334455661122",
          kdfIterations: 600000,
          clientAuthKeyHex: "aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb",
          x25519PublicKey: "pk_x25519_admin",
          ed25519PublicKey: "pk_ed25519_admin",
          publicKeyFingerprint: "sha256:adminfp123",
          encryptedX25519PrivateKey: "priv_x25519_enc",
          encryptedEd25519PrivateKey: "priv_ed25519_enc",
          isBreakGlassAdmin: true,
          totpSecret: totpSecretBase32,
        },
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      entAdminToken = json.sessionToken;
      entAdminUserId = json.userId;
      entTenantId = json.tenantId;
    });

    afterAll(async () => {
      await enterpriseApp.close();
    });

    it("GET /api/v1/status confirms enterprise mode", async () => {
      const res = await enterpriseApp.inject({
        method: "GET",
        url: "/api/v1/status",
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().deploymentMode).toBe("enterprise");
    });

    it("POST /api/v1/auth/login rejects password login in enterprise mode with HTTP 403", async () => {
      const res = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/auth/login",
        payload: {
          email: "superadmin@corp.enterprise",
          clientAuthKeyHex: "aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb",
        },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error).toContain("disabled in enterprise mode");
    });

    it("POST /api/v1/auth/oidc/authorize and /callback execute PKCE flow and require unlock ceremony", async () => {
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

      const authRes = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/auth/oidc/authorize",
        payload: {
          email: "saml_alice@corp.enterprise",
          name: "Alice Engineer",
          tenantId: entTenantId,
          codeChallenge,
        },
      });
      expect(authRes.statusCode).toBe(200);
      const { code } = authRes.json();
      expect(code).toMatch(/^oidc_code_/);

      const callbackRes = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/auth/oidc/callback",
        payload: {
          code,
          codeVerifier,
          tenantId: entTenantId,
        },
      });

      expect(callbackRes.statusCode).toBe(200);
      const json = callbackRes.json();
      expect(json.email).toBe("saml_alice@corp.enterprise");
      expect(json.sessionToken).toMatch(/^vlt_session_/);
      expect(json.unlockRequired).toBe(true);
      memberUserId = json.userId;
    });

    it("POST /api/v1/auth/saml/login and /callback execute SAML 2.0 assertion flow", async () => {
      const loginRes = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/auth/saml/login",
        payload: { tenantId: entTenantId },
      });
      expect(loginRes.statusCode).toBe(200);
      expect(loginRes.json().ssoUrl).toBe("/api/v1/auth/saml/callback");

      const samlXml = createMockSamlResponseXml({
        email: "saml_bob@corp.enterprise",
        name: "Bob Operator",
        sub: "usr_saml_bob_123",
      });
      const samlResponse = Buffer.from(samlXml).toString("base64");

      const callbackRes = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/auth/saml/callback",
        payload: {
          samlResponse,
          tenantId: entTenantId,
        },
      });

      expect(callbackRes.statusCode).toBe(200);
      const json = callbackRes.json();
      expect(json.email).toBe("saml_bob@corp.enterprise");
      expect(json.sessionToken).toMatch(/^vlt_session_/);
      expect(json.unlockRequired).toBe(true);
    });

    it("POST /api/v1/auth/break-glass/login validates TOTP code and logs critical audit event", async () => {
      // Reject invalid TOTP code
      const failRes = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/auth/break-glass/login",
        payload: {
          email: "superadmin@corp.enterprise",
          clientAuthKeyHex: "aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb",
          totpCode: "000000",
          reason: "Emergency recovery from IdP outage",
        },
      });
      expect(failRes.statusCode).toBe(401);

      // Successful break-glass login with valid TOTP
      const validCode = await generateTotpCode(totpSecretBase32);
      const successRes = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/auth/break-glass/login",
        payload: {
          email: "superadmin@corp.enterprise",
          clientAuthKeyHex: "aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb",
          totpCode: validCode,
          reason: "Emergency recovery from IdP outage",
        },
      });

      expect(successRes.statusCode).toBe(200);
      const json = successRes.json();
      expect(json.isBreakGlass).toBe(true);
      expect(json.sessionToken).toMatch(/^vlt_session_/);
    });

    it("Multi-Tenant Isolation: SuperAdmin can create and list independent tenants", async () => {
      const res = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/tenants",
        headers: { authorization: `Bearer ${entAdminToken}` },
        payload: {
          name: "Acme Healthcare Subsidiary",
          slug: "acme-health",
          deploymentMode: "enterprise",
        },
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      expect(json.slug).toBe("acme-health");
      expect(json.id).toMatch(/^tnt_/);

      const listRes = await enterpriseApp.inject({
        method: "GET",
        url: "/api/v1/tenants",
        headers: { authorization: `Bearer ${entAdminToken}` },
      });
      expect(listRes.statusCode).toBe(200);
      expect(listRes.json().tenants.length).toBeGreaterThanOrEqual(2);
    });

    it("Multi-User Vault Sharing: VaultAdmin shares vault with member using recipient-wrapped key", async () => {
      // 1. Create a vault
      const vltRes = await enterpriseApp.inject({
        method: "POST",
        url: "/api/v1/vaults",
        headers: { authorization: `Bearer ${entAdminToken}` },
        payload: {
          name: "Enterprise Shared Infrastructure",
          description: "Secrets shared with engineering members",
          encryptedVaultKey: {
            ciphertext: "admin_wrapped_vault_key_v1",
            iv: "iv_1234567890123456",
            authTag: "auth_tag_1234567890123456",
            aad: "vault-share:vlt_shared:1",
            keyVersion: 1,
          },
        },
      });
      expect(vltRes.statusCode).toBe(201);
      sharedVaultId = vltRes.json().id;

      // 2. Share vault with Alice (memberUserId)
      const shareRes = await enterpriseApp.inject({
        method: "POST",
        url: `/api/v1/vaults/${sharedVaultId}/members`,
        headers: { authorization: `Bearer ${entAdminToken}` },
        payload: {
          userId: memberUserId,
          vaultRole: "SecretEditor",
          encryptedVaultKey: {
            ciphertext: "alice_wrapped_vault_key_v1",
            iv: "iv_alice_12345678901234",
            authTag: "auth_tag_alice_1234567890",
            aad: `vault-share:${sharedVaultId}:1`,
            keyVersion: 1,
          },
        },
      });
      expect(shareRes.statusCode).toBe(201);
      expect(shareRes.json().userId).toBe(memberUserId);

      // 3. List members
      const listMemRes = await enterpriseApp.inject({
        method: "GET",
        url: `/api/v1/vaults/${sharedVaultId}/members`,
        headers: { authorization: `Bearer ${entAdminToken}` },
      });
      expect(listMemRes.statusCode).toBe(200);
      const members = listMemRes.json().members;
      expect(members.some((m: { userId: string }) => m.userId === memberUserId)).toBe(true);
    });

    it("Member revocation flags mandatory VaultKey rotation and POST /rotate-key commits key_version + 1", async () => {
      // 1. Revoke Alice from vault
      const revokeRes = await enterpriseApp.inject({
        method: "DELETE",
        url: `/api/v1/vaults/${sharedVaultId}/members/${memberUserId}`,
        headers: { authorization: `Bearer ${entAdminToken}` },
      });
      expect(revokeRes.statusCode).toBe(200);
      expect(revokeRes.json().rotationRequired).toBe(true);

      // Verify GET /api/v1/vaults/:id shows rotationRequired: true
      const getVaultRes = await enterpriseApp.inject({
        method: "GET",
        url: `/api/v1/vaults/${sharedVaultId}`,
        headers: { authorization: `Bearer ${entAdminToken}` },
      });
      expect(getVaultRes.statusCode).toBe(200);
      expect(getVaultRes.json().vault.rotationRequired).toBe(true);

      // 2. Perform mandatory key rotation to keyVersion 2
      const rotateRes = await enterpriseApp.inject({
        method: "POST",
        url: `/api/v1/vaults/${sharedVaultId}/rotate-key`,
        headers: { authorization: `Bearer ${entAdminToken}` },
        payload: {
          newKeyVersion: 2,
          memberKeys: [
            {
              userId: entAdminUserId, // remaining admin
              encryptedVaultKey: "admin_wrapped_vault_key_v2",
              iv: "iv_admin_v2_123456789012",
              authTag: "tag_admin_v2_123456789012",
              aad: `vault-share:${sharedVaultId}:2`,
            },
          ],
        },
      });
      expect(rotateRes.statusCode).toBe(200);
      const rotatedJson = rotateRes.json();
      expect(rotatedJson.status).toBe("rotated");
      expect(rotatedJson.keyVersion).toBe(2);
      expect(rotatedJson.rotationRequired).toBe(false);

      // Verify GET /api/v1/vaults/:id reflects keyVersion 2 and rotationRequired: false
      const verifyRes = await enterpriseApp.inject({
        method: "GET",
        url: `/api/v1/vaults/${sharedVaultId}`,
        headers: { authorization: `Bearer ${entAdminToken}` },
      });
      expect(verifyRes.statusCode).toBe(200);
      expect(verifyRes.json().vault.keyVersion).toBe(2);
      expect(verifyRes.json().vault.rotationRequired).toBe(false);
    });
  });

  describe("Slice 4: Enterprise RBAC, Dual-Control Escrow & Hash-Chained Audit Plane", () => {
    let slice4App: FastifyInstance;
    let slice4Db: VaultDatabase;
    let superAdminToken = "";
    let secAdminToken = "";
    let userAdminToken = "";
    let auditorToken = "";
    let readerToken = "";
    let slice4TenantId = "";
    let slice4VaultId = "";
    let recoveryShare1 = "";
    let recoveryShare2 = "";
    let orgRecoveryPubKey = "";

    beforeAll(async () => {
      const sqlite = new Database(":memory:");
      initSchema(sqlite);
      const db = drizzle(sqlite, { schema: sqliteSchema });
      slice4Db = { db, sqlite, path: ":memory:" };

      slice4App = buildServer({
        database: slice4Db,
        deploymentMode: "enterprise",
        enableCors: false,
      });
      await slice4App.ready();

      // Bootstrap SuperAdmin via Break-Glass
      const totp = generateTotpSecret(20);
      const now = new Date().toISOString();
      const bgSalt = crypto.randomBytes(32).toString("hex");
      const clientAuthKey = "super_admin_auth_key_12345";
      const serverHash = crypto.scryptSync(clientAuthKey, bgSalt, 32).toString("hex");

      const tList = slice4Db.db.select().from(sqliteSchema.tenants).all();
      slice4TenantId = tList[0]!.id;

      slice4Db.db
        .insert(sqliteSchema.users)
        .values({
          id: "usr_superadmin_01",
          tenantId: slice4TenantId,
          email: "superadmin@enterprise.local",
          displayName: "Super Administrator",
          systemRole: "SuperAdmin",
          kdfSalt: bgSalt,
          serverPasswordHash: serverHash,
          totpSecret: totp.secretBase32,
          isBreakGlassAdmin: true,
          x25519PublicKey: "placeholder_pub",
          ed25519PublicKey: "placeholder_pub",
          publicKeyFingerprint: "fingerprint_01",
          encryptedX25519PrivateKey: "placeholder_priv",
          encryptedEd25519PrivateKey: "placeholder_priv",
          createdAt: now,
          updatedAt: now,
        })
        .run();

      const bgCode = await generateTotpCode(totp.secretBase32, Date.now());
      const bgRes = await slice4App.inject({
        method: "POST",
        url: "/api/v1/auth/break-glass/login",
        payload: {
          email: "superadmin@enterprise.local",
          clientAuthKeyHex: clientAuthKey,
          totpCode: bgCode,
          reason: "Slice 4 bootstrap initialization",
        },
      });
      expect(bgRes.statusCode).toBe(200);
      superAdminToken = bgRes.json().sessionToken;

      slice4Db.db
        .insert(sqliteSchema.vaults)
        .values({
          id: "vlt_slice4_agent_vault_01",
          tenantId: slice4TenantId,
          name: "Agent Test Vault",
          description: "Vault for testing agent separation",
          keyVersion: 1,
          createdByUserId: "usr_superadmin_01",
          createdAt: now,
          updatedAt: now,
        })
        .run();

      // Create SecurityAdmin user via SuperAdmin
      const secUserRes = await slice4App.inject({
        method: "POST",
        url: "/api/v1/admin/users",
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          email: "secadmin@enterprise.local",
          displayName: "Security Administrator",
          systemRole: "SecurityAdmin",
        },
      });
      expect(secUserRes.statusCode).toBe(201);
      const secUserId = secUserRes.json().id;

      // Create UserAdmin user
      const uAdminRes = await slice4App.inject({
        method: "POST",
        url: "/api/v1/admin/users",
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          email: "useradmin@enterprise.local",
          displayName: "User Administrator",
          systemRole: "UserAdmin",
        },
      });
      expect(uAdminRes.statusCode).toBe(201);
      const uAdminId = uAdminRes.json().id;

      // Create ComplianceAuditor user
      const auditUserRes = await slice4App.inject({
        method: "POST",
        url: "/api/v1/admin/users",
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          email: "auditor@enterprise.local",
          displayName: "Compliance Auditor",
          systemRole: "ComplianceAuditor",
        },
      });
      expect(auditUserRes.statusCode).toBe(201);
      const auditorId = auditUserRes.json().id;

      // Create regular user for SecretReader
      const readerUserRes = await slice4App.inject({
        method: "POST",
        url: "/api/v1/admin/users",
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          email: "reader@enterprise.local",
          displayName: "Secret Reader",
        },
      });
      expect(readerUserRes.statusCode).toBe(201);
      const readerId = readerUserRes.json().id;

      // Issue mock session tokens for testing RBAC
      const { issueSessionToken } = await import("./auth.js");
      secAdminToken = issueSessionToken({
        actorId: secUserId,
        actorType: "user",
        tenantId: slice4TenantId,
        email: "secadmin@enterprise.local",
        displayName: "Security Administrator",
        systemRole: "SecurityAdmin",
        scopes: ["admin:audit:read", "admin:roles:manage", "agent:token:revoke", "secrets:read"],
      });

      userAdminToken = issueSessionToken({
        actorId: uAdminId,
        actorType: "user",
        tenantId: slice4TenantId,
        email: "useradmin@enterprise.local",
        displayName: "User Administrator",
        systemRole: "UserAdmin",
        scopes: ["admin:users:manage"],
      });

      auditorToken = issueSessionToken({
        actorId: auditorId,
        actorType: "user",
        tenantId: slice4TenantId,
        email: "auditor@enterprise.local",
        displayName: "Compliance Auditor",
        systemRole: "ComplianceAuditor",
        scopes: ["admin:audit:read"],
      });

      readerToken = issueSessionToken({
        actorId: readerId,
        actorType: "user",
        tenantId: slice4TenantId,
        email: "reader@enterprise.local",
        displayName: "Secret Reader",
        systemRole: "SecretConsumer",
        scopes: ["secrets:read", "secrets:reveal"],
      });

      // Generate Org Recovery Keypair and split into 2 shares
      const recPair = await generateOrgRecoveryKeyPair();
      orgRecoveryPubKey = recPair.publicKey;
      const shares = splitRecoveryKey(recPair.privateKeyBytes);
      recoveryShare1 = shares.share1;
      recoveryShare2 = shares.share2;
    });

    afterAll(async () => {
      await slice4App.close();
    });

    it("enforces human-only admin separation and rejects agent callers with HTTP 403", async () => {
      // Create agent token
      const agToken = "agt_slice4_agent_01.secret_12345";
      const agHash = crypto.createHash("sha256").update(agToken).digest("hex");
      slice4Db.db
        .insert(sqliteSchema.agents)
        .values({
          id: "agt_slice4_agent_01",
          tenantId: slice4TenantId,
          vaultId: "vlt_slice4_agent_vault_01",
          name: "Test Agent",
          vaultRole: "SecretConsumer",
          scopesJson: JSON.stringify(["secrets:read"]),
          keyVersion: 1,
          agentEncryptedVaultKey: "placeholder",
          iv: "placeholder_iv_12",
          authTag: "placeholder_tag_16",
          aad: "placeholder_aad",
          tokenHash: agHash,
          status: "active",
          createdByUserId: "usr_superadmin_01",
          createdAt: new Date().toISOString(),
        })
        .run();

      const res = await slice4App.inject({
        method: "POST",
        url: "/api/v1/admin/users",
        headers: { authorization: `Bearer ${agToken}` },
        payload: {
          email: "agent_created@enterprise.local",
          displayName: "Malicious Provisioning",
        },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error).toContain("restricted to human administrators");
    });

    it("enforces system role RBAC matrices across UserAdmin, SecurityAdmin, and ComplianceAuditor", async () => {
      // UserAdmin can manage users
      const listUsersRes = await slice4App.inject({
        method: "GET",
        url: "/api/v1/admin/users",
        headers: { authorization: `Bearer ${userAdminToken}` },
      });
      expect(listUsersRes.statusCode).toBe(200);

      // UserAdmin CANNOT access IdP or SIEM config
      const idpRes = await slice4App.inject({
        method: "GET",
        url: "/api/v1/admin/idp",
        headers: { authorization: `Bearer ${userAdminToken}` },
      });
      expect(idpRes.statusCode).toBe(403);

      // SecurityAdmin CANNOT manage users
      const secUsersRes = await slice4App.inject({
        method: "GET",
        url: "/api/v1/admin/users",
        headers: { authorization: `Bearer ${secAdminToken}` },
      });
      expect(secUsersRes.statusCode).toBe(403);

      // SecurityAdmin CAN manage roles and SIEM config
      const rolesRes = await slice4App.inject({
        method: "GET",
        url: "/api/v1/admin/roles",
        headers: { authorization: `Bearer ${secAdminToken}` },
      });
      expect(rolesRes.statusCode).toBe(200);

      // SecurityAdmin CAN configure SIEM
      const siemRes = await slice4App.inject({
        method: "POST",
        url: "/api/v1/admin/siem",
        headers: { authorization: `Bearer ${secAdminToken}` },
        payload: {
          webhookUrl: "https://siem.enterprise.local/webhook",
          sharedSecret: "super-secret-siem-token-12345",
          enabled: true,
        },
      });
      expect(siemRes.statusCode).toBe(200);

      // ComplianceAuditor can read audit logs and verify
      const auditRes = await slice4App.inject({
        method: "GET",
        url: "/api/v1/admin/audit-logs",
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(auditRes.statusCode).toBe(200);

      const verifyRes = await slice4App.inject({
        method: "GET",
        url: "/api/v1/admin/audit-logs/verify",
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(verifyRes.statusCode).toBe(200);
      expect(verifyRes.json().valid).toBe(true);

      // ComplianceAuditor CANNOT update IdP or users
      const auditorIdpRes = await slice4App.inject({
        method: "PUT",
        url: "/api/v1/admin/idp",
        headers: { authorization: `Bearer ${auditorToken}` },
        payload: { providerType: "oidc", issuer: "https://evil.local" },
      });
      expect(auditorIdpRes.statusCode).toBe(403);
    });

    it("cryptographically withholds EncryptedVaultKey and payload for SecretReader role", async () => {
      // 1. Create a vault with OrgRecoveryEncryptedVaultKey
      const vaultKey = generateVaultKeyBytes();
      slice4VaultId = generateEntityId("vlt_");
      const recoveryBlob = await wrapVaultKeyWithOrgRecoveryKey(
        vaultKey,
        orgRecoveryPubKey,
        slice4VaultId,
        1,
      );

      const createVaultRes = await slice4App.inject({
        method: "POST",
        url: "/api/v1/vaults",
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          id: slice4VaultId,
          name: "Escrowed Production Vault",
          description: "Dual-control recovery vault",
          encryptedVaultKey: {
            ciphertext: "admin_key_cipher",
            iv: "admin_iv_123456",
            authTag: "admin_tag_12345678",
            aad: `vault-share:${slice4VaultId}:1`,
            keyVersion: 1,
          },
          orgRecoveryEncryptedVaultKey: recoveryBlob,
        },
      });
      expect(createVaultRes.statusCode).toBe(201);
      const actualVaultId = createVaultRes.json().id;

      // 2. Share vault with user as SecretReader
      const uList = slice4Db.db
        .select()
        .from(sqliteSchema.users)
        .where(eq(sqliteSchema.users.email, "reader@enterprise.local"))
        .all();
      const readerUserId = uList[0]!.id;

      const shareRes = await slice4App.inject({
        method: "POST",
        url: `/api/v1/vaults/${actualVaultId}/members`,
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          userId: readerUserId,
          vaultRole: "SecretReader",
        },
      });
      expect(shareRes.statusCode).toBe(201);

      // 3. GET /api/v1/vaults/:id as SecretReader returns encryptedVaultKey: null
      const getVaultRes = await slice4App.inject({
        method: "GET",
        url: `/api/v1/vaults/${actualVaultId}`,
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(getVaultRes.statusCode).toBe(200);
      expect(getVaultRes.json().encryptedVaultKey).toBeNull();

      // 4. Create secret in the vault
      const secId = generateEntityId("sec_");
      const createSecRes = await slice4App.inject({
        method: "POST",
        url: `/api/v1/vaults/${actualVaultId}/secrets`,
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          id: secId,
          vaultId: actualVaultId,
          version: 1,
          keyVersion: 1,
          encryptedMetadata: {
            algorithm: "AES-256-GCM",
            ciphertext: "metadata_cipher",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: `${slice4TenantId}:${actualVaultId}:${secId}:1:1`,
            keyVersion: 1,
          },
          encryptedPayload: {
            algorithm: "AES-256-GCM",
            ciphertext: "payload_cipher",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: `${slice4TenantId}:${actualVaultId}:${secId}:1:1`,
            keyVersion: 1,
          },
        },
      });
      expect(createSecRes.statusCode).toBe(201);

      // 5. POST /api/v1/secrets/:id/reveal as SecretReader returns 403 Forbidden
      const revealRes = await slice4App.inject({
        method: "POST",
        url: `/api/v1/secrets/${secId}/reveal`,
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(revealRes.statusCode).toBe(403);
      expect(revealRes.json().error).toContain("SecretReader");
    });

    it("executes dual-control organization recovery escrow with quorum validation", async () => {
      // 1. SuperAdmin creates a vault with OrgRecoveryEncryptedVaultKey
      const vaultKey = generateVaultKeyBytes();
      const escrowVaultId = generateEntityId("vlt_");
      const recoveryBlob = await wrapVaultKeyWithOrgRecoveryKey(
        vaultKey,
        orgRecoveryPubKey,
        escrowVaultId,
        1,
      );

      const createVaultRes = await slice4App.inject({
        method: "POST",
        url: "/api/v1/vaults",
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          id: escrowVaultId,
          name: "Quorum Recovery Vault",
          description: "Dual-control recovery quorum test",
          encryptedVaultKey: {
            ciphertext: "admin_key_cipher",
            iv: "admin_iv_123456",
            authTag: "admin_tag_12345678",
            aad: `vault-share:${escrowVaultId}:1`,
            keyVersion: 1,
          },
          orgRecoveryEncryptedVaultKey: recoveryBlob,
        },
      });
      expect(createVaultRes.statusCode).toBe(201);
      const actualVaultId = createVaultRes.json().id;

      // 2. SuperAdmin initiates recovery with Share 1
      const initRes = await slice4App.inject({
        method: "POST",
        url: `/api/v1/vaults/${actualVaultId}/recovery/initiate`,
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          vaultId: actualVaultId,
          reason: "Employee offboarding recovery request",
          initiatorShare: recoveryShare1,
        },
      });
      expect(initRes.statusCode).toBe(201);
      const { recoveryId } = initRes.json();
      expect(recoveryId).toMatch(/^rec_/);

      // 3. SuperAdmin attempting to self-approve fails with 403 Forbidden (quorum violation)
      const selfApproveRes = await slice4App.inject({
        method: "POST",
        url: `/api/v1/vaults/${actualVaultId}/recovery/approve`,
        headers: { authorization: `Bearer ${superAdminToken}` },
        payload: {
          recoveryId,
          approverShare: recoveryShare2,
        },
      });
      expect(selfApproveRes.statusCode).toBe(403);
      expect(selfApproveRes.json().error).toContain("Dual-control quorum violation");

      // 4. SecurityAdmin approves with Share 2 -> Successful unescrow
      const approveRes = await slice4App.inject({
        method: "POST",
        url: `/api/v1/vaults/${actualVaultId}/recovery/approve`,
        headers: { authorization: `Bearer ${secAdminToken}` },
        payload: {
          recoveryId,
          approverShare: recoveryShare2,
        },
      });
      expect(approveRes.statusCode).toBe(200);
      expect(approveRes.json().status).toBe("completed");
      expect(approveRes.json().recovered).toBe(true);
    });

    it("verifies hash-chained audit plane and detects tampered records", async () => {
      // 1. Verify valid hash chain
      const verifyRes = await slice4App.inject({
        method: "GET",
        url: "/api/v1/admin/audit-logs/verify",
        headers: { authorization: `Bearer ${superAdminToken}` },
      });
      expect(verifyRes.statusCode).toBe(200);
      const verifyJson = verifyRes.json();
      expect(verifyJson.valid).toBe(true);
      expect(verifyJson.totalEvents).toBeGreaterThan(0);

      // 2. Tamper with an audit record in the database
      const records = slice4Db.db.select().from(sqliteSchema.auditLogs).all();
      expect(records.length).toBeGreaterThan(0);
      const targetRecord = records[records.length - 1]!;
      slice4Db.db
        .update(sqliteSchema.auditLogs)
        .set({ canonicalEventJson: JSON.stringify({ tampered: true }) })
        .where(eq(sqliteSchema.auditLogs.id, targetRecord.id))
        .run();

      // 3. Verify hash chain now detects tampering
      const tamperedVerifyRes = await slice4App.inject({
        method: "GET",
        url: "/api/v1/admin/audit-logs/verify",
        headers: { authorization: `Bearer ${superAdminToken}` },
      });
      expect(tamperedVerifyRes.statusCode).toBe(200);
      const tamperedJson = tamperedVerifyRes.json();
      expect(tamperedJson.valid).toBe(false);
      expect(tamperedJson.reason).toContain("Hash mismatch");
    });
  });

  describe("Slice 5: Hardened Migrations, Ephemeral Leasing & Backup Integration", () => {
    let s5Db: VaultDatabase;
    let s5App: FastifyInstance;
    let s5Token: string;
    let s5VaultId: string;

    beforeAll(async () => {
      const sqlite = new Database(":memory:");
      initSchema(sqlite);
      const db = drizzle(sqlite, { schema: sqliteSchema });
      s5Db = { db, sqlite, path: ":memory:" };
      s5App = buildServer({ database: s5Db, deploymentMode: "standalone", enableCors: false });
      await s5App.ready();

      // Register initial admin
      const regRes = await s5App.inject({
        method: "POST",
        url: "/api/v1/auth/bootstrap",
        payload: {
          email: "slice5_admin@standalone.local",
          displayName: "Slice 5 Admin",
          clientAuthKeyHex: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
          kdfSalt: "test_salt_32_bytes_long_value__",
          kdfIterations: 600000,
          x25519PublicKey: "base64_x25519_pk",
          ed25519PublicKey: "base64_ed25519_pk",
          publicKeyFingerprint: "fp_test_slice5",
          encryptedX25519PrivateKey: "enc_priv_key",
          encryptedEd25519PrivateKey: "enc_ed_priv_key",
        },
      });
      expect(regRes.statusCode).toBe(201);
      s5Token = regRes.json().sessionToken;

      // Create primary vault
      s5VaultId = generateEntityId("vlt_");
      const vltRes = await s5App.inject({
        method: "POST",
        url: "/api/v1/vaults",
        headers: { authorization: `Bearer ${s5Token}` },
        payload: {
          id: s5VaultId,
          name: "Slice 5 Source Vault",
          encryptedVaultKey: {
            ciphertext: "enc_key",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_context",
          },
        },
      });
      expect(vltRes.statusCode).toBe(201);

      // Create a secret in source vault
      const secRes = await s5App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s5VaultId}/secrets`,
        headers: { authorization: `Bearer ${s5Token}` },
        payload: {
          encryptedMetadata: {
            algorithm: "AES-256-GCM",
            ciphertext: "enc_meta_payload",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_context",
            keyVersion: 1,
          },
          encryptedPayload: {
            algorithm: "AES-256-GCM",
            ciphertext: "enc_secret_payload",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_context",
            keyVersion: 1,
          },
        },
      });
      expect(secRes.statusCode).toBe(201);
    });

    afterAll(async () => {
      await s5App.close();
    });

    it("exports encrypted backup and imports it into a second vault", async () => {
      const passphrase = "high-entropy-backup-passphrase-2026";

      // 1. Export backup from source vault
      const exportRes = await s5App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s5VaultId}/backup/export`,
        headers: { authorization: `Bearer ${s5Token}` },
        payload: { passphrase },
      });
      expect(exportRes.statusCode).toBe(200);
      const backupContainer = exportRes.json();
      expect(backupContainer.format).toBe("llm-vault-backup");
      expect(backupContainer.version).toBe(1);
      expect(backupContainer.itemCount).toBe(1);
      expect(backupContainer.ciphertext).toBeDefined();

      // 2. Create destination vault
      const destVaultId = generateEntityId("vlt_");
      const vltRes = await s5App.inject({
        method: "POST",
        url: "/api/v1/vaults",
        headers: { authorization: `Bearer ${s5Token}` },
        payload: {
          id: destVaultId,
          name: "Slice 5 Destination Vault",
          encryptedVaultKey: {
            ciphertext: "enc_key_dest",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_context",
          },
        },
      });
      expect(vltRes.statusCode).toBe(201);

      // 3. Import backup into destination vault
      const importRes = await s5App.inject({
        method: "POST",
        url: `/api/v1/vaults/${destVaultId}/backup/import`,
        headers: { authorization: `Bearer ${s5Token}` },
        payload: {
          container: backupContainer,
          passphrase,
        },
      });
      expect(importRes.statusCode).toBe(200);
      expect(importRes.json().status).toBe("imported");
      expect(importRes.json().importedCount).toBe(1);

      // 4. Import with wrong passphrase fails
      const badPassRes = await s5App.inject({
        method: "POST",
        url: `/api/v1/vaults/${destVaultId}/backup/import`,
        headers: { authorization: `Bearer ${s5Token}` },
        payload: {
          container: backupContainer,
          passphrase: "wrong-password",
        },
      });
      expect(badPassRes.statusCode).toBe(400);
      expect(badPassRes.json().error).toContain("failed");
    });

    it("rejects backup import payloads exceeding the 50MB size limit with HTTP 413", async () => {
      // Create a string that exceeds 50MB
      // Using a mock payload that is oversized
      const hugeContainer = {
        format: "llm-vault-backup",
        version: 1,
        kdf: { provider: "pbkdf2", salt: "salt", iterations: 600000 },
        iv: "iv",
        ciphertext: "X".repeat(52_428_801), // > 50MB
        authTag: "tag",
        tenantId: "tnt_default",
        vaultId: s5VaultId,
        exportedAt: new Date().toISOString(),
        itemCount: 1,
      };

      const res = await s5App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s5VaultId}/backup/import`,
        headers: { authorization: `Bearer ${s5Token}` },
        payload: {
          container: hugeContainer,
          passphrase: "some-passphrase",
        },
      });
      expect(res.statusCode).toBe(413);
      expect(res.json().error).toMatch(/Payload Too Large|50MB/);
    });

    it("imports Bitwarden exports with HTML/script sanitization and creates encrypted secret rows", async () => {
      const res = await s5App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s5VaultId}/import/bitwarden`,
        headers: { authorization: `Bearer ${s5Token}` },
        payload: {
          encrypted: false,
          folders: [],
          items: [
            {
              name: "Stripe API Key <script>alert('xss')</script>",
              notes: "<b>Production Key</b>\x00\x08",
              login: {
                username: "billing_user\x1F",
                password: "sk_live_1234567890",
              },
            },
          ],
        },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().status).toBe("imported");
      expect(res.json().importedCount).toBe(1);
    });

    it("imports CSV rows with schema validation and string sanitization", async () => {
      const res = await s5App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s5VaultId}/import/csv`,
        headers: { authorization: `Bearer ${s5Token}` },
        payload: {
          rows: [
            {
              name: "Postgres Connection <iframe>evil</iframe>",
              value: "postgres://user:pass@db.prod:5432/main",
              description: "Primary DB cluster",
              tags: ["database", "prod"],
            },
          ],
        },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().status).toBe("imported");
      expect(res.json().importedCount).toBe(1);
    });
  });

  describe("Slice 7: Workload Identity Federation (OIDC & SPIFFE for CI/CD & Cloud Workloads)", () => {
    let s7App: FastifyInstance;
    let s7Db: VaultDatabase;
    let s7Token: string;
    let s7VaultId: string;
    let s7SecretId: string;
    const s7TenantId = "tnt_workload_corp";
    const s7AdminId = "usr_workload_admin_01";

    beforeAll(async () => {
      const sqlite = new Database(":memory:");
      initSchema(sqlite);
      const db = drizzle(sqlite, { schema: sqliteSchema });
      s7Db = { db, sqlite, path: ":memory:" };

      s7App = buildServer({ database: s7Db, enableCors: false });
      await s7App.ready();

      // Seed tenant & admin user
      const now = new Date().toISOString();
      s7Db.db
        .insert(sqliteSchema.tenants)
        .values({
          id: s7TenantId,
          name: "Workload Federation Corp",
          slug: "workload-corp",
          deploymentMode: "enterprise",
          createdAt: now,
          updatedAt: now,
        })
        .run();

      s7Db.db
        .insert(sqliteSchema.users)
        .values({
          id: s7AdminId,
          tenantId: s7TenantId,
          email: "admin@workload-corp.local",
          displayName: "Workload Admin",
          systemRole: "SuperAdmin",
          kdfSalt: "0123456789abcdef0123456789abcdef",
          x25519PublicKey: "placeholder_x25519",
          ed25519PublicKey: "placeholder_ed25519",
          publicKeyFingerprint: "fingerprint_123",
          encryptedX25519PrivateKey: "priv_blob",
          encryptedEd25519PrivateKey: "priv_blob",
          createdAt: now,
          updatedAt: now,
        })
        .run();

      s7Token = issueSessionToken({
        actorId: s7AdminId,
        actorType: "user",
        tenantId: s7TenantId,
        email: "admin@workload-corp.local",
        displayName: "Workload Admin",
        systemRole: "SuperAdmin",
        scopes: [
          "secrets:read",
          "secrets:write",
          "secrets:reveal",
          "secrets:create",
          "vaults:create",
          "vaults:share",
          "vaults:admin",
          "users:admin",
        ],
      });

      // Create a vault
      const vRes = await s7App.inject({
        method: "POST",
        url: "/api/v1/vaults",
        headers: { authorization: `Bearer ${s7Token}` },
        payload: {
          name: "CI Production Vault",
          description: "Production secrets for automated deployments",
          encryptedVaultKey: {
            ciphertext: "enc_vault_key_ciphertext_blob_12345",
            iv: "iv_0123456789abcdef",
            authTag: "auth_tag_0123456789abcdef",
            aad: "aad_vlt_test",
          },
        },
      });
      expect(vRes.statusCode).toBe(201);
      s7VaultId = vRes.json().id;

      // Create a secret in the vault
      const sRes = await s7App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s7VaultId}/secrets`,
        headers: { authorization: `Bearer ${s7Token}` },
        payload: {
          id: generateEntityId("sec_"),
          vaultId: s7VaultId,
          version: 1,
          keyVersion: 1,
          encryptedMetadata: {
            ciphertext: "enc_meta",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_meta",
          },
          encryptedPayload: {
            ciphertext: "enc_payload_secret_val",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_payload",
          },
          tagBlindIndexes: [],
        },
      });
      expect(sRes.statusCode).toBe(201);
      s7SecretId = sRes.json().id;
    });

    afterAll(async () => {
      await s7App.close();
    });

    it("creates, lists, and manages workload bindings on a vault", async () => {
      // Create binding for GitHub Actions on main branch
      const res = await s7App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s7VaultId}/workload-bindings`,
        headers: { authorization: `Bearer ${s7Token}` },
        payload: {
          name: "GitHub Actions CI Pipeline",
          provider: "github-actions",
          issuer: "https://token.actions.githubusercontent.com",
          audience: "https://vault.workload-corp.internal",
          claimFilters: {
            repository: "Koality-Assured/llm-vault",
            ref: "refs/heads/main",
            environment: "production",
          },
          vaultRole: "SecretConsumer",
          tokenTtlSeconds: 300,
        },
      });
      expect(res.statusCode).toBe(201);
      const binding = res.json().binding;
      expect(binding.id.startsWith("wkb_")).toBe(true);
      expect(binding.provider).toBe("github-actions");
      expect(binding.claimFilters.repository).toBe("Koality-Assured/llm-vault");

      // List bindings
      const listRes = await s7App.inject({
        method: "GET",
        url: `/api/v1/vaults/${s7VaultId}/workload-bindings`,
        headers: { authorization: `Bearer ${s7Token}` },
      });
      expect(listRes.statusCode).toBe(200);
      expect(listRes.json().bindings.length).toBeGreaterThanOrEqual(1);
    });

    it("exchanges valid GitHub Actions OIDC token for ephemeral token and wrapped vault key", async () => {
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        iss: "https://token.actions.githubusercontent.com",
        aud: "https://vault.workload-corp.internal",
        sub: "repo:Koality-Assured/llm-vault:ref:refs/heads/main",
        repository: "Koality-Assured/llm-vault",
        ref: "refs/heads/main",
        environment: "production",
        exp: now + 300,
      };

      const idToken = await createTestWorkloadJwt(claims);

      const exchangeRes = await s7App.inject({
        method: "POST",
        url: "/api/v1/auth/workload-identity/exchange",
        payload: {
          token: idToken,
          provider: "github-actions",
        },
      });

      expect(exchangeRes.statusCode).toBe(200);
      const data = exchangeRes.json();
      expect(data.token).toBeDefined();
      expect(data.actorId.startsWith("agt_")).toBe(true);
      expect(data.vaultId).toBe(s7VaultId);
      expect(data.vaultRole).toBe("SecretConsumer");
      expect(data.encryptedVaultKey).toBeDefined();
      expect(data.encryptedVaultKey.ciphertext).toBe("enc_vault_key_ciphertext_blob_12345");

      // Verify the issued ephemeral token can reveal secrets from the vault
      const revealRes = await s7App.inject({
        method: "POST",
        url: `/api/v1/secrets/${s7SecretId}/reveal`,
        headers: { authorization: `Bearer ${data.token}` },
        payload: { reason: "ci-automated-deployment" },
      });
      expect(revealRes.statusCode).toBe(200);
      expect(revealRes.json().id).toBe(s7SecretId);
      expect(revealRes.json().encryptedPayload.ciphertext).toBe("enc_payload_secret_val");
    });

    it("rejects untrusted branch or unauthorized repository with HTTP 403", async () => {
      const now = Math.floor(Date.now() / 1000);
      // Untrusted PR branch
      const unauthClaims = {
        iss: "https://token.actions.githubusercontent.com",
        aud: "https://vault.workload-corp.internal",
        sub: "repo:Koality-Assured/llm-vault:ref:refs/pull/99/merge",
        repository: "Koality-Assured/llm-vault",
        ref: "refs/pull/99/merge",
        environment: "production",
        exp: now + 300,
      };

      const unauthJwt = await createTestWorkloadJwt(unauthClaims);

      const res = await s7App.inject({
        method: "POST",
        url: "/api/v1/auth/workload-identity/exchange",
        payload: {
          token: unauthJwt,
          provider: "github-actions",
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().error).toContain("do not match any active workload binding policy");
    });

    it("rejects expired workload token with HTTP 401", async () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredClaims = {
        iss: "https://token.actions.githubusercontent.com",
        aud: "https://vault.workload-corp.internal",
        repository: "Koality-Assured/llm-vault",
        ref: "refs/heads/main",
        environment: "production",
        exp: now - 120, // expired 2 minutes ago
      };

      const expiredJwt = await createTestWorkloadJwt(expiredClaims);

      const res = await s7App.inject({
        method: "POST",
        url: "/api/v1/auth/workload-identity/exchange",
        payload: {
          token: expiredJwt,
          provider: "github-actions",
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().error).toContain("expired");
    });

    it("supports SPIFFE / Kubernetes JWT SVID workload identity binding", async () => {
      // 1. Create SPIFFE binding
      const createRes = await s7App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s7VaultId}/workload-bindings`,
        headers: { authorization: `Bearer ${s7Token}` },
        payload: {
          name: "Kubernetes Payment Service Pods",
          provider: "spiffe-jwt",
          issuer: "https://spiffe.internal",
          audience: "llm-vault",
          claimFilters: {
            sub: "spiffe://example.org/ns/production/sa/payment-service",
          },
          vaultRole: "SecretReader",
          tokenTtlSeconds: 120,
        },
      });
      expect(createRes.statusCode).toBe(201);
      const bindingId = createRes.json().binding.id;

      // 2. Exchange SPIFFE JWT SVID
      const now = Math.floor(Date.now() / 1000);
      const spiffeClaims = {
        iss: "https://spiffe.internal",
        aud: "llm-vault",
        sub: "spiffe://example.org/ns/production/sa/payment-service",
        exp: now + 120,
      };

      const spiffeToken = await createTestWorkloadJwt(spiffeClaims);

      const exchRes = await s7App.inject({
        method: "POST",
        url: "/api/v1/auth/workload-identity/exchange",
        payload: {
          token: spiffeToken,
          provider: "spiffe-jwt",
        },
      });

      expect(exchRes.statusCode).toBe(200);
      expect(exchRes.json().vaultId).toBe(s7VaultId);
      expect(exchRes.json().token).toBeDefined();

      // 3. Delete binding
      const delRes = await s7App.inject({
        method: "DELETE",
        url: `/api/v1/vaults/${s7VaultId}/workload-bindings/${bindingId}`,
        headers: { authorization: `Bearer ${s7Token}` },
      });
      expect(delRes.statusCode).toBe(200);
      expect(delRes.json().success).toBe(true);
    });
  });

  describe("Slice 8: Automated Secret Rotation & Provider Integrations", () => {
    let s8App: FastifyInstance;
    let s8Db: VaultDatabase;
    let s8Token = "";
    let s8TenantId = "";
    let s8VaultId = "";
    let s8SecretId = "";

    beforeAll(async () => {
      const sqlite = new Database(":memory:");
      initSchema(sqlite);
      const db = drizzle(sqlite, { schema: sqliteSchema });
      s8Db = { db, sqlite, path: ":memory:" };
      s8App = buildServer({ database: s8Db, enableCors: false });
      await s8App.ready();

      s8TenantId = generateEntityId("vlt_");
      const now = new Date().toISOString();

      s8Db.db
        .insert(sqliteSchema.tenants)
        .values({
          id: s8TenantId,
          name: "Rotation Test Org",
          slug: "rotation-test-org",
          deploymentMode: "enterprise",
          createdAt: now,
          updatedAt: now,
        })
        .run();

      const adminId = generateEntityId("usr_");
      s8Db.db
        .insert(sqliteSchema.users)
        .values({
          id: adminId,
          tenantId: s8TenantId,
          email: "rot-admin@vault.test",
          displayName: "Rotation Admin",
          systemRole: "SuperAdmin",
          kdfSalt: "0123456789abcdef0123456789abcdef",
          x25519PublicKey: "placeholder_x25519",
          ed25519PublicKey: "placeholder_ed25519",
          publicKeyFingerprint: "fingerprint_rot",
          encryptedX25519PrivateKey: "priv_blob",
          encryptedEd25519PrivateKey: "priv_blob",
          createdAt: now,
          updatedAt: now,
        })
        .run();

      s8Token = issueSessionToken({
        actorId: adminId,
        actorType: "user",
        tenantId: s8TenantId,
        email: "rot-admin@vault.test",
        displayName: "Rotation Admin",
        systemRole: "SuperAdmin",
        scopes: [
          "secrets:read",
          "secrets:create",
          "secrets:update",
          "secrets:reveal",
          "vaults:create",
          "vaults:share",
          "vaults:admin",
          "users:admin",
        ],
      });

      // Create vault
      const vRes = await s8App.inject({
        method: "POST",
        url: "/api/v1/vaults",
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          name: "Production API Keys Vault",
          description: "Vault containing cloud and AI secrets",
          encryptedVaultKey: {
            ciphertext: "enc_vault_key_ciphertext_blob_s8",
            iv: "iv_0123456789abcdef",
            authTag: "auth_tag_0123456789abcdef",
            aad: "aad_vlt_s8",
          },
        },
      });
      expect(vRes.statusCode).toBe(201);
      s8VaultId = vRes.json().id;

      // Create an OpenAI secret
      const sRes = await s8App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s8VaultId}/secrets`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          id: generateEntityId("sec_"),
          vaultId: s8VaultId,
          version: 1,
          keyVersion: 1,
          encryptedMetadata: {
            ciphertext: "enc_meta_s8",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_meta_s8",
          },
          encryptedPayload: {
            ciphertext: "enc_payload_v1_openai",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_payload_s8",
          },
          tagBlindIndexes: [],
        },
      });
      expect(sRes.statusCode).toBe(201);
      s8SecretId = sRes.json().id;
    });

    afterAll(async () => {
      await s8App.close();
    });

    it("configures rotation policy on a secret and queries rotation status", async () => {
      const putRes = await s8App.inject({
        method: "PUT",
        url: `/api/v1/secrets/${s8SecretId}/rotation-config`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          providerType: "ai-openai",
          targetResourceId: "proj_openai_prod_123",
          intervalDays: 14,
          enabled: true,
        },
      });

      expect(putRes.statusCode).toBe(200);
      const data = putRes.json();
      expect(data.secretId).toBe(s8SecretId);
      expect(data.providerType).toBe("ai-openai");
      expect(data.intervalDays).toBe(14);
      expect(data.nextRotationDue).toBeDefined();
      expect(data.status).toBe("idle");
      expect(data.dueForRotation).toBe(false);

      // Verify GET rotation-status
      const getRes = await s8App.inject({
        method: "GET",
        url: `/api/v1/secrets/${s8SecretId}/rotation-status`,
        headers: { authorization: `Bearer ${s8Token}` },
      });
      expect(getRes.statusCode).toBe(200);
      expect(getRes.json().providerType).toBe("ai-openai");
      expect(getRes.json().targetResourceId).toBe("proj_openai_prod_123");
    });

    it("executes a dry-run rotation verifying provider generation without mutating version", async () => {
      const dryRunRes = await s8App.inject({
        method: "POST",
        url: `/api/v1/secrets/${s8SecretId}/rotate`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: { dryRun: true },
      });

      expect(dryRunRes.statusCode).toBe(200);
      const data = dryRunRes.json();
      expect(data.dryRun).toBe(true);
      expect(data.previousVersion).toBe(1);
      expect(data.newVersion).toBe(2);
      expect(data.providerType).toBe("ai-openai");

      // Verify secret was NOT mutated
      const checkRes = await s8App.inject({
        method: "GET",
        url: `/api/v1/secrets/${s8SecretId}`,
        headers: { authorization: `Bearer ${s8Token}` },
      });
      expect(checkRes.statusCode).toBe(200);
      expect(checkRes.json().version).toBe(1);
    });

    it("executes live 3-phase rotation, commits version + 1, and updates nextRotationDue", async () => {
      const rotateRes = await s8App.inject({
        method: "POST",
        url: `/api/v1/secrets/${s8SecretId}/rotate`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: { dryRun: false },
      });

      expect(rotateRes.statusCode).toBe(200);
      const data = rotateRes.json();
      expect(data.success).toBe(true);
      expect(data.previousVersion).toBe(1);
      expect(data.newVersion).toBe(2);
      expect(data.rotatedAt).toBeDefined();
      expect(data.nextRotationDue).toBeDefined();

      // Verify database state: currentVersion is now 2
      const checkRes = await s8App.inject({
        method: "GET",
        url: `/api/v1/secrets/${s8SecretId}`,
        headers: { authorization: `Bearer ${s8Token}` },
      });
      expect(checkRes.statusCode).toBe(200);
      expect(checkRes.json().version).toBe(2);

      // Verify versions endpoint reflects both version 1 and 2
      const verRes = await s8App.inject({
        method: "GET",
        url: `/api/v1/secrets/${s8SecretId}/versions`,
        headers: { authorization: `Bearer ${s8Token}` },
      });
      expect(verRes.statusCode).toBe(200);
      expect(verRes.json().versions.length).toBe(2);
      expect(verRes.json().versions[0].version).toBe(2);
    });

    it("supports cloud infrastructure and database rotations (AWS IAM, PostgreSQL with remediation commands)", async () => {
      // 1. Create AWS IAM secret
      const awsSecId = generateEntityId("sec_");
      const cRes = await s8App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s8VaultId}/secrets`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          id: awsSecId,
          vaultId: s8VaultId,
          version: 1,
          keyVersion: 1,
          encryptedMetadata: {
            ciphertext: "enc_meta_aws",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_aws",
          },
          encryptedPayload: {
            ciphertext: "enc_payload_aws",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_aws",
          },
          tagBlindIndexes: [],
        },
      });
      expect(cRes.statusCode).toBe(201);

      // Configure AWS IAM rotation
      await s8App.inject({
        method: "PUT",
        url: `/api/v1/secrets/${awsSecId}/rotation-config`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          providerType: "cloud-aws-iam",
          targetResourceId: "prod-ci-runner",
          intervalDays: 90,
          enabled: true,
        },
      });

      // Rotate AWS IAM
      const awsRot = await s8App.inject({
        method: "POST",
        url: `/api/v1/secrets/${awsSecId}/rotate`,
        headers: { authorization: `Bearer ${s8Token}` },
      });
      expect(awsRot.statusCode).toBe(200);
      expect(awsRot.json().newVersion).toBe(2);
      expect(awsRot.json().providerType).toBe("cloud-aws-iam");

      // 2. Create PostgreSQL database secret
      const pgSecId = generateEntityId("sec_");
      await s8App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s8VaultId}/secrets`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          id: pgSecId,
          vaultId: s8VaultId,
          version: 1,
          keyVersion: 1,
          encryptedMetadata: {
            ciphertext: "enc_meta_pg",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_pg",
          },
          encryptedPayload: {
            ciphertext: "enc_payload_pg",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_pg",
          },
          tagBlindIndexes: [],
        },
      });

      // Configure PostgreSQL rotation
      await s8App.inject({
        method: "PUT",
        url: `/api/v1/secrets/${pgSecId}/rotation-config`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          providerType: "db-postgres",
          targetResourceId: "billing_app_svc",
          intervalDays: 30,
          enabled: true,
        },
      });

      // Rotate PostgreSQL secret and verify SQL remediation command is returned
      const pgRot = await s8App.inject({
        method: "POST",
        url: `/api/v1/secrets/${pgSecId}/rotate`,
        headers: { authorization: `Bearer ${s8Token}` },
      });
      expect(pgRot.statusCode).toBe(200);
      expect(pgRot.json().remediationCommand).toContain(
        'ALTER ROLE "billing_app_svc" WITH PASSWORD',
      );
    });

    it("sweeps and rotates scheduled secrets via POST /api/v1/admin/secrets/check-rotations", async () => {
      // Create a secret and set nextRotationDue in the past (overdue for rotation)
      const overdueSecId = generateEntityId("sec_");
      await s8App.inject({
        method: "POST",
        url: `/api/v1/vaults/${s8VaultId}/secrets`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          id: overdueSecId,
          vaultId: s8VaultId,
          version: 1,
          keyVersion: 1,
          encryptedMetadata: {
            ciphertext: "enc_meta_overdue",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_overdue",
          },
          encryptedPayload: {
            ciphertext: "enc_payload_overdue",
            iv: "iv_123456789012",
            authTag: "tag_1234567890123456",
            aad: "aad_overdue",
          },
          tagBlindIndexes: [],
        },
      });

      // Set rotation config
      await s8App.inject({
        method: "PUT",
        url: `/api/v1/secrets/${overdueSecId}/rotation-config`,
        headers: { authorization: `Bearer ${s8Token}` },
        payload: {
          providerType: "generic-symmetric",
          intervalDays: 7,
          enabled: true,
        },
      });

      // Force nextRotationDue to past timestamp directly in sqlite
      const pastTime = new Date(Date.now() - 3600 * 1000).toISOString();
      s8Db.sqlite
        .prepare("UPDATE secrets SET next_rotation_due = ? WHERE id = ?")
        .run(pastTime, overdueSecId);

      // Verify status reports dueForRotation = true
      const statRes = await s8App.inject({
        method: "GET",
        url: `/api/v1/secrets/${overdueSecId}/rotation-status`,
        headers: { authorization: `Bearer ${s8Token}` },
      });
      expect(statRes.statusCode).toBe(200);
      expect(statRes.json().dueForRotation).toBe(true);

      // Execute batch sweep
      const sweepRes = await s8App.inject({
        method: "POST",
        url: "/api/v1/admin/secrets/check-rotations",
        headers: { authorization: `Bearer ${s8Token}` },
      });

      expect(sweepRes.statusCode).toBe(200);
      const sweepData = sweepRes.json();
      expect(sweepData.due).toBeGreaterThanOrEqual(1);
      expect(sweepData.rotated).toBeGreaterThanOrEqual(1);
      expect(sweepData.failed).toBe(0);

      // Verify overdue secret has been updated to version 2
      const updatedSec = await s8App.inject({
        method: "GET",
        url: `/api/v1/secrets/${overdueSecId}`,
        headers: { authorization: `Bearer ${s8Token}` },
      });
      expect(updatedSec.statusCode).toBe(200);
      expect(updatedSec.json().version).toBe(2);
    });
  });
});
