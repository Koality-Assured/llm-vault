import { boolean, index, integer, pgTable, text, uniqueIndex } from "drizzle-orm/pg-core";

export const tenants = pgTable(
  "tenants",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    slug: text("slug").notNull(),
    deploymentMode: text("deployment_mode").notNull().default("enterprise"),
    orgRecoveryPublicKey: text("org_recovery_public_key"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [uniqueIndex("tenants_slug_unique").on(table.slug)],
);

export const users = pgTable(
  "users",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    email: text("email").notNull(),
    displayName: text("display_name").notNull(),
    systemRole: text("system_role").notNull().default("SecretConsumer"),
    kdfAlgorithm: text("kdf_algorithm").notNull().default("PBKDF2-HMAC-SHA256"),
    kdfSalt: text("kdf_salt").notNull(),
    kdfIterations: integer("kdf_iterations").notNull().default(600000),
    serverPasswordHash: text("server_password_hash"),
    x25519PublicKey: text("x25519_public_key").notNull(),
    ed25519PublicKey: text("ed25519_public_key").notNull(),
    publicKeyFingerprint: text("public_key_fingerprint").notNull(),
    encryptedX25519PrivateKey: text("encrypted_x25519_private_key").notNull(),
    encryptedEd25519PrivateKey: text("encrypted_ed25519_private_key").notNull(),
    totpSecret: text("totp_secret"),
    isBreakGlassAdmin: boolean("is_break_glass_admin").notNull().default(false),
    status: text("status").notNull().default("active"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("users_tenant_email_unique").on(table.tenantId, table.email),
    index("idx_users_tenant").on(table.tenantId),
  ],
);

export const vaults = pgTable(
  "vaults",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    name: text("name").notNull(),
    description: text("description").notNull().default(""),
    keyVersion: integer("key_version").notNull().default(1),
    rotationRequired: boolean("rotation_required").notNull().default(false),
    orgRecoveryEncryptedVaultKey: text("org_recovery_encrypted_vault_key"),
    createdByUserId: text("created_by_user_id")
      .notNull()
      .references(() => users.id),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [index("idx_vaults_tenant").on(table.tenantId)],
);

export const vaultMemberKeys = pgTable(
  "vault_member_keys",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    vaultId: text("vault_id")
      .notNull()
      .references(() => vaults.id),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    vaultRole: text("vault_role").notNull(),
    keyVersion: integer("key_version").notNull(),
    encryptedVaultKey: text("encrypted_vault_key"),
    iv: text("iv"),
    authTag: text("auth_tag"),
    aad: text("aad"),
    grantedByUserId: text("granted_by_user_id")
      .notNull()
      .references(() => users.id),
    createdAt: text("created_at").notNull(),
    revokedAt: text("revoked_at"),
  },
  (table) => [
    uniqueIndex("vault_member_keys_vault_user_unique").on(table.vaultId, table.userId),
    index("idx_vault_member_keys_vault").on(table.vaultId),
    index("idx_vault_member_keys_user").on(table.userId),
  ],
);

export const agents = pgTable(
  "agents",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    vaultId: text("vault_id")
      .notNull()
      .references(() => vaults.id),
    name: text("name").notNull(),
    description: text("description").notNull().default(""),
    vaultRole: text("vault_role").notNull().default("SecretConsumer"),
    scopesJson: text("scopes_json").notNull().default("[]"),
    keyVersion: integer("key_version").notNull(),
    agentEncryptedVaultKey: text("agent_encrypted_vault_key").notNull(),
    iv: text("iv").notNull(),
    authTag: text("auth_tag").notNull(),
    aad: text("aad").notNull(),
    allowRawContextReveal: boolean("allow_raw_context_reveal").notNull().default(false),
    tokenHash: text("token_hash").notNull(),
    status: text("status").notNull().default("active"),
    createdByUserId: text("created_by_user_id")
      .notNull()
      .references(() => users.id),
    createdAt: text("created_at").notNull(),
    revokedAt: text("revoked_at"),
  },
  (table) => [
    index("idx_agents_tenant").on(table.tenantId),
    index("idx_agents_vault").on(table.vaultId),
  ],
);

export const folders = pgTable(
  "folders",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    vaultId: text("vault_id")
      .notNull()
      .references(() => vaults.id),
    parentFolderId: text("parent_folder_id"),
    name: text("name").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    index("idx_folders_vault").on(table.vaultId),
    index("idx_folders_parent").on(table.parentFolderId),
  ],
);

export const secrets = pgTable(
  "secrets",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    vaultId: text("vault_id")
      .notNull()
      .references(() => vaults.id),
    folderId: text("folder_id").references(() => folders.id),
    currentVersion: integer("current_version").notNull().default(1),
    keyVersion: integer("key_version").notNull().default(1),
    encryptedMetadata: text("encrypted_metadata").notNull(),
    metadataIv: text("metadata_iv").notNull(),
    metadataAuthTag: text("metadata_auth_tag").notNull(),
    metadataAad: text("metadata_aad").notNull(),
    status: text("status").notNull().default("active"),
    createdByActorId: text("created_by_actor_id").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    index("idx_secrets_tenant").on(table.tenantId),
    index("idx_secrets_vault").on(table.vaultId),
    index("idx_secrets_folder").on(table.folderId),
  ],
);

export const secretVersions = pgTable(
  "secret_versions",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    vaultId: text("vault_id")
      .notNull()
      .references(() => vaults.id),
    secretId: text("secret_id")
      .notNull()
      .references(() => secrets.id),
    version: integer("version").notNull(),
    keyVersion: integer("key_version").notNull(),
    encryptedPayload: text("encrypted_payload").notNull(),
    payloadIv: text("payload_iv").notNull(),
    payloadAuthTag: text("payload_auth_tag").notNull(),
    payloadAad: text("payload_aad").notNull(),
    createdByActorId: text("created_by_actor_id").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("secret_versions_secret_version_unique").on(table.secretId, table.version),
    index("idx_secret_versions_secret").on(table.secretId),
  ],
);

export const secretTagIndexes = pgTable(
  "secret_tag_indexes",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    vaultId: text("vault_id")
      .notNull()
      .references(() => vaults.id),
    secretId: text("secret_id")
      .notNull()
      .references(() => secrets.id),
    tagBlindIndex: text("tag_blind_index").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("secret_tag_indexes_secret_tag_unique").on(table.secretId, table.tagBlindIndex),
    index("idx_secret_tag_indexes_vault_tag").on(table.vaultId, table.tagBlindIndex),
  ],
);

export const auditLogs = pgTable(
  "audit_logs",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id")
      .notNull()
      .references(() => tenants.id),
    vaultId: text("vault_id"),
    actorId: text("actor_id").notNull(),
    actorType: text("actor_type").notNull(),
    action: text("action").notNull(),
    targetId: text("target_id").notNull(),
    ipAddress: text("ip_address").notNull(),
    canonicalEventJson: text("canonical_event_json").notNull(),
    prevEventHash: text("prev_event_hash").notNull(),
    eventHash: text("event_hash").notNull(),
    signature: text("signature"),
    timestamp: text("timestamp").notNull(),
  },
  (table) => [
    index("idx_audit_logs_tenant_time").on(table.tenantId, table.timestamp),
    index("idx_audit_logs_actor").on(table.actorId),
    index("idx_audit_logs_target").on(table.targetId),
  ],
);

export const postgresSchema = {
  tenants,
  users,
  vaults,
  vaultMemberKeys,
  agents,
  folders,
  secrets,
  secretVersions,
  secretTagIndexes,
  auditLogs,
};
