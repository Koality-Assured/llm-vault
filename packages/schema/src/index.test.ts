import { getTableName } from "drizzle-orm";
import { describe, expect, it } from "vitest";

import {
  GENESIS_AUDIT_EVENT_HASH,
  computeAuditEventHash,
  computeTagBlindIndex,
  deriveVaultSearchKey,
  encryptSecretMetadata,
  encryptSecretPayload,
  generateAgentDecryptionKey,
  generateVaultKeyBytes,
  wrapVaultKeyForAgent,
} from "@llm-vault/crypto";
import { formatSecretHandle, generateEntityId } from "@llm-vault/ids";

import {
  AgentIdentitySchema,
  AuditEventSchema,
  CreateSecretRequestSchema,
  DeploymentModeSchema,
  RevealSecretResponseSchema,
  SecretHandleSchema,
  SecretMetadataSchema,
  SecretPayloadSchema,
  SystemRoleSchema,
  SYSTEM_ROLE_PERMISSIONS,
  VAULT_ROLE_PERMISSIONS,
  VaultRoleSchema,
  InitiateRecoveryRequestSchema,
  AdminCreateUserRequestSchema,
  isMcpAllowedScope,
  postgresSchema,
  sqliteSchema,
} from "./index.js";

describe("@llm-vault/schema", () => {
  it("validates DeploymentMode, SystemRole, VaultRole, and RBAC permission boundaries", () => {
    expect(DeploymentModeSchema.parse("enterprise")).toBe("enterprise");
    expect(DeploymentModeSchema.parse("standalone")).toBe("standalone");
    expect(() => DeploymentModeSchema.parse("dev-bypass")).toThrow();

    expect(SystemRoleSchema.parse("SuperAdmin")).toBe("SuperAdmin");
    expect(VaultRoleSchema.parse("SecretReader")).toBe("SecretReader");

    // System role permissions
    expect(SYSTEM_ROLE_PERMISSIONS.SuperAdmin).toContain("admin:users:manage");
    expect(SYSTEM_ROLE_PERMISSIONS.SuperAdmin).toContain("admin:idp:manage");
    expect(SYSTEM_ROLE_PERMISSIONS.SecurityAdmin).toContain("admin:audit:read");
    expect(SYSTEM_ROLE_PERMISSIONS.SecurityAdmin).not.toContain("admin:users:manage");
    expect(SYSTEM_ROLE_PERMISSIONS.ComplianceAuditor).toEqual(["admin:audit:read"]);

    // SecretReader has metadata-only visibility (never secrets:reveal)
    expect(VAULT_ROLE_PERMISSIONS.SecretReader).toEqual(["secrets:read"]);
    expect(VAULT_ROLE_PERMISSIONS.SecretReader).not.toContain("secrets:reveal");

    // Admin plane separation from MCP
    expect(isMcpAllowedScope("admin:users:manage")).toBe(false);
    expect(isMcpAllowedScope("admin:roles:manage")).toBe(false);
    expect(isMcpAllowedScope("admin:idp:manage")).toBe(false);
    expect(isMcpAllowedScope("admin:audit:read")).toBe(true);
    expect(isMcpAllowedScope("agent:exec:run")).toBe(true);

    // Slice 4 Schemas
    const adminUser = AdminCreateUserRequestSchema.parse({
      email: "secadmin@example.com",
      displayName: "Security Admin",
      systemRole: "SecurityAdmin",
    });
    expect(adminUser.systemRole).toBe("SecurityAdmin");

    const recReq = InitiateRecoveryRequestSchema.parse({
      vaultId: generateEntityId("vlt_"),
      reason: "Emergency recovery test",
      initiatorShare: "share123",
    });
    expect(recReq.reason).toBe("Emergency recovery test");
  });

  it("validates CreateSecretRequestSchema and RevealSecretResponseSchema with real WebCrypto envelopes", async () => {
    const vaultKey = generateVaultKeyBytes();
    const searchKey = await deriveVaultSearchKey(vaultKey);
    const vaultId = generateEntityId("vlt_");
    const secretId = generateEntityId("sec_");
    const folderId = generateEntityId("fld_");

    const aadContext = {
      tenantId: "tnt_01",
      vaultId,
      secretId,
      version: 1,
      keyVersion: 1,
    };

    const metadata = SecretMetadataSchema.parse({
      name: "OPENAI_API_KEY",
      description: "Production agent key",
      tags: ["openai", "llm"],
    });
    const payload = SecretPayloadSchema.parse({
      value: "sk-proj-FAKE_KEY_FOR_TESTING_ONLY_123456",
      notes: "Zero-context consumption only",
    });

    const encryptedMetadata = await encryptSecretMetadata(vaultKey, metadata, aadContext);
    const encryptedPayload = await encryptSecretPayload(vaultKey, payload, aadContext);
    const tagIndex = await computeTagBlindIndex(searchKey, "openai");

    const createReq = CreateSecretRequestSchema.parse({
      id: secretId,
      vaultId,
      folderId,
      version: 1,
      keyVersion: 1,
      encryptedMetadata,
      encryptedPayload,
      tagBlindIndexes: [tagIndex],
    });

    expect(createReq.id).toBe(secretId);
    expect(createReq.tagBlindIndexes).toEqual([tagIndex]);

    const handle = formatSecretHandle(secretId);
    expect(SecretHandleSchema.parse(handle)).toBe(handle);

    const revealRes = RevealSecretResponseSchema.parse({
      id: secretId,
      vaultId,
      version: 1,
      keyVersion: 1,
      encryptedPayload,
      encryptedVaultKey: {
        ciphertext: encryptedPayload.ciphertext,
        iv: encryptedPayload.iv,
        authTag: encryptedPayload.authTag,
        aad: `vault-share:${vaultId}:1`,
        keyVersion: 1,
      },
      auditEventId: generateEntityId("aud_"),
    });
    expect(revealRes.id).toBe(secretId);
  });

  it("enforces MCP admin plane separation on AgentIdentitySchema and validates AuditEventSchema", async () => {
    const agentId = generateEntityId("agt_");
    const vaultId = generateEntityId("vlt_");
    const userId = generateEntityId("usr_");
    const vaultKey = generateVaultKeyBytes();
    const agentDecryptionKey = generateAgentDecryptionKey();

    const wrappedAgentKey = await wrapVaultKeyForAgent(
      vaultKey,
      agentDecryptionKey,
      agentId,
      vaultId,
      1,
    );

    const validAgent = AgentIdentitySchema.parse({
      id: agentId,
      tenantId: "tnt_01",
      vaultId,
      name: "ci-deploy-agent",
      vaultRole: "SecretConsumer",
      scopes: ["secrets:read", "secrets:reveal", "agent:exec:run"],
      keyVersion: 1,
      agentEncryptedVaultKey: wrappedAgentKey,
      createdByUserId: userId,
      createdAt: new Date().toISOString(),
    });
    expect(validAgent.allowRawContextReveal).toBe(false);

    // Reject agent identity requesting human-only admin:users:manage
    expect(() =>
      AgentIdentitySchema.parse({
        ...validAgent,
        scopes: ["secrets:read", "admin:users:manage"],
      }),
    ).toThrow();

    // Validate hash-chained AuditEventSchema
    const auditKey = generateVaultKeyBytes();
    const canonicalEventJson = JSON.stringify({
      action: "secrets:reveal",
      actorId: agentId,
      targetId: vaultId,
    });
    const eventHash = await computeAuditEventHash(
      auditKey,
      GENESIS_AUDIT_EVENT_HASH,
      canonicalEventJson,
    );

    const auditEvent = AuditEventSchema.parse({
      id: generateEntityId("aud_"),
      tenantId: "tnt_01",
      vaultId,
      actorId: agentId,
      actorType: "agent",
      action: "secrets:reveal",
      targetId: vaultId,
      ipAddress: "127.0.0.1",
      canonicalEventJson,
      prevEventHash: GENESIS_AUDIT_EVENT_HASH,
      eventHash,
      timestamp: new Date().toISOString(),
    });
    expect(auditEvent.eventHash).toBe(eventHash);
  });

  it("defines matching Drizzle ORM table structures across PostgreSQL and SQLite dialects", () => {
    const pgKeys = Object.keys(postgresSchema).sort();
    const sqliteKeys = Object.keys(sqliteSchema).sort();

    expect(pgKeys).toEqual([
      "agents",
      "auditLogs",
      "folders",
      "idpConfigs",
      "recoveryRequests",
      "secretTagIndexes",
      "secretVersions",
      "secrets",
      "siemConfigs",
      "tenants",
      "users",
      "vaultMemberKeys",
      "vaults",
    ]);
    expect(sqliteKeys).toEqual(pgKeys);

    for (const key of pgKeys) {
      const pgTableObj = postgresSchema[key as keyof typeof postgresSchema];
      const sqliteTableObj = sqliteSchema[key as keyof typeof sqliteSchema];
      expect(getTableName(pgTableObj)).toBe(getTableName(sqliteTableObj));
    }
  });
});
