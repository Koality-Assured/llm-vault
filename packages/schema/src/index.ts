import { z } from "zod";

import { type EntityPrefixInput, isValidEntityId, isValidSecretHandle } from "@llm-vault/ids";

export { postgresSchema } from "./db/postgres.js";
export { sqliteSchema } from "./db/sqlite.js";

export const DEPLOYMENT_MODES = ["enterprise", "standalone"] as const;
export const DeploymentModeSchema = z.enum(DEPLOYMENT_MODES);
export type DeploymentMode = z.infer<typeof DeploymentModeSchema>;

export const SYSTEM_ROLES = [
  "SuperAdmin",
  "SecurityAdmin",
  "UserAdmin",
  "ComplianceAuditor",
] as const;
export const SystemRoleSchema = z.enum(SYSTEM_ROLES);
export type SystemRole = z.infer<typeof SystemRoleSchema>;

export const VAULT_ROLES = [
  "WorkspaceOwner",
  "VaultAdmin",
  "SecretEditor",
  "SecretConsumer",
  "SecretReader",
] as const;
export const VaultRoleSchema = z.enum(VAULT_ROLES);
export type VaultRole = z.infer<typeof VaultRoleSchema>;

export const PERMISSION_SCOPES = [
  "secrets:create",
  "secrets:read",
  "secrets:reveal",
  "secrets:update",
  "secrets:delete",
  "secrets:rollback",
  "secrets:export",
  "vaults:create",
  "vaults:manage",
  "vaults:share",
  "vaults:rotate_key",
  "admin:users:manage",
  "admin:roles:manage",
  "admin:idp:manage",
  "admin:audit:read",
  "agent:token:create",
  "agent:token:revoke",
  "agent:lease:acquire",
  "agent:exec:run",
  "agent:exec:http_proxy",
] as const;

export const PermissionScopeSchema = z.enum(PERMISSION_SCOPES);
export type PermissionScope = z.infer<typeof PermissionScopeSchema>;

export const HUMAN_ADMIN_ONLY_SCOPES = [
  "admin:users:manage",
  "admin:roles:manage",
  "admin:idp:manage",
] as const satisfies readonly PermissionScope[];

const HUMAN_ADMIN_ONLY_SET = new Set<string>(HUMAN_ADMIN_ONLY_SCOPES);

export function isMcpAllowedScope(scope: PermissionScope): boolean {
  return !HUMAN_ADMIN_ONLY_SET.has(scope);
}

export const VAULT_ROLE_PERMISSIONS: Readonly<Record<VaultRole, readonly PermissionScope[]>> = {
  WorkspaceOwner: [
    "vaults:create",
    "vaults:manage",
    "vaults:share",
    "vaults:rotate_key",
    "agent:token:create",
    "agent:token:revoke",
    "agent:lease:acquire",
    "agent:exec:run",
    "agent:exec:http_proxy",
    "secrets:create",
    "secrets:read",
    "secrets:reveal",
    "secrets:update",
    "secrets:delete",
    "secrets:rollback",
    "secrets:export",
  ],
  VaultAdmin: [
    "vaults:manage",
    "vaults:share",
    "vaults:rotate_key",
    "agent:token:create",
    "agent:token:revoke",
    "agent:lease:acquire",
    "agent:exec:run",
    "agent:exec:http_proxy",
    "secrets:create",
    "secrets:read",
    "secrets:reveal",
    "secrets:update",
    "secrets:delete",
    "secrets:rollback",
    "secrets:export",
  ],
  SecretEditor: [
    "secrets:create",
    "secrets:read",
    "secrets:reveal",
    "secrets:update",
    "secrets:rollback",
    "agent:lease:acquire",
    "agent:exec:run",
    "agent:exec:http_proxy",
  ],
  SecretConsumer: [
    "secrets:read",
    "secrets:reveal",
    "agent:lease:acquire",
    "agent:exec:run",
    "agent:exec:http_proxy",
  ],
  SecretReader: ["secrets:read"],
};

function createEntityIdZodSchema(expectedPrefix: EntityPrefixInput) {
  return z.string().refine((val) => isValidEntityId(val, expectedPrefix), {
    message: `Invalid entity ID; expected prefix "${expectedPrefix}"`,
  });
}

export const SecretIdSchema = createEntityIdZodSchema("sec_");
export const VaultIdSchema = createEntityIdZodSchema("vlt_");
export const FolderIdSchema = createEntityIdZodSchema("fld_");
export const UserIdSchema = createEntityIdZodSchema("usr_");
export const AgentIdSchema = createEntityIdZodSchema("agt_");
export const LeaseIdSchema = createEntityIdZodSchema("lease_");
export const AuditIdSchema = createEntityIdZodSchema("aud_");

export const ActorIdSchema = z
  .string()
  .refine((val) => isValidEntityId(val, "usr_") || isValidEntityId(val, "agt_"), {
    message: 'Actor ID must have prefix "usr_" or "agt_"',
  });

export const SecretHandleSchema = z.string().refine((val) => isValidSecretHandle(val), {
  message: 'Secret handle must match format "{{vault:sec_<ulid>}}"',
});

export const EncryptedEnvelopeSchema = z.object({
  algorithm: z.literal("AES-256-GCM"),
  ciphertext: z.string().min(1),
  iv: z.string().min(16),
  authTag: z.string().min(20),
  aad: z.string().regex(/^[^:]+:[^:]+:[^:]+:[1-9]\d*:[1-9]\d*$/),
  keyVersion: z.number().int().min(1),
});
export type EncryptedEnvelopeDto = z.infer<typeof EncryptedEnvelopeSchema>;

export const CustomFieldMetadataSchema = z.object({
  key: z.string().min(1).max(128),
  label: z.string().min(1).max(128).optional(),
  kind: z.enum(["text", "secret", "url"]).optional(),
});

export const SecretMetadataSchema = z.object({
  name: z.string().min(1).max(256),
  description: z.string().max(2048).optional(),
  tags: z.array(z.string().min(1).max(64)).max(64).optional(),
  customFieldMetadata: z.array(CustomFieldMetadataSchema).max(64).optional(),
});
export type SecretMetadata = z.infer<typeof SecretMetadataSchema>;

export const SecretPayloadSchema = z.object({
  value: z.string().min(1),
  notes: z.string().max(16384).optional(),
  customFields: z.record(z.string().min(1), z.string()).optional(),
});
export type SecretPayload = z.infer<typeof SecretPayloadSchema>;

export const CreateSecretRequestSchema = z.object({
  id: SecretIdSchema,
  vaultId: VaultIdSchema,
  folderId: FolderIdSchema.nullable().optional(),
  version: z.literal(1),
  keyVersion: z.number().int().min(1),
  encryptedMetadata: EncryptedEnvelopeSchema,
  encryptedPayload: EncryptedEnvelopeSchema,
  tagBlindIndexes: z
    .array(z.string().regex(/^[0-9a-f]{64}$/))
    .max(64)
    .default([]),
});
export type CreateSecretRequest = z.infer<typeof CreateSecretRequestSchema>;

export const RevealSecretResponseSchema = z.object({
  id: SecretIdSchema,
  vaultId: VaultIdSchema,
  version: z.number().int().min(1),
  keyVersion: z.number().int().min(1),
  encryptedPayload: EncryptedEnvelopeSchema,
  encryptedVaultKey: z.object({
    ciphertext: z.string().min(1),
    iv: z.string().min(16),
    authTag: z.string().min(20),
    aad: z.string().min(1),
    keyVersion: z.number().int().min(1),
  }),
  auditEventId: AuditIdSchema,
});
export type RevealSecretResponse = z.infer<typeof RevealSecretResponseSchema>;

export const AgentIdentitySchema = z.object({
  id: AgentIdSchema,
  tenantId: z.string().min(1),
  vaultId: VaultIdSchema,
  name: z.string().min(1).max(128),
  description: z.string().max(1024).default(""),
  vaultRole: VaultRoleSchema,
  scopes: z
    .array(PermissionScopeSchema)
    .min(1)
    .refine((scopes) => scopes.every(isMcpAllowedScope), {
      message: "Agent identity cannot be granted human-only administrative mutation scopes",
    }),
  keyVersion: z.number().int().min(1),
  agentEncryptedVaultKey: z.object({
    agentEncryptedVaultKey: z.string().min(1),
    iv: z.string().min(16),
    authTag: z.string().min(20),
    aad: z.string().min(1),
    keyVersion: z.number().int().min(1),
  }),
  allowRawContextReveal: z.boolean().default(false),
  status: z.enum(["active", "revoked"]).default("active"),
  createdByUserId: UserIdSchema,
  createdAt: z.string().datetime(),
  revokedAt: z.string().datetime().nullable().optional(),
});
export type AgentIdentity = z.infer<typeof AgentIdentitySchema>;

export const AuditEventSchema = z.object({
  id: AuditIdSchema,
  tenantId: z.string().min(1),
  vaultId: VaultIdSchema.nullable().optional(),
  actorId: ActorIdSchema,
  actorType: z.enum(["user", "agent"]),
  action: PermissionScopeSchema,
  targetId: z.string().min(1),
  ipAddress: z.string().min(1),
  canonicalEventJson: z.string().min(2),
  prevEventHash: z.string().min(1),
  eventHash: z.string().regex(/^[0-9a-f]{64}$/),
  signature: z.string().min(1).nullable().optional(),
  timestamp: z.string().datetime(),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;
