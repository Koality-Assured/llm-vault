import Database from "better-sqlite3";
import type { Database as SqliteDatabase } from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { sqliteSchema } from "@llm-vault/schema/db/sqlite";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

export interface VaultDatabase {
  db: BetterSQLite3Database<typeof sqliteSchema>;
  sqlite: SqliteDatabase;
  path: string;
}

export function initSchema(sqlite: Database.Database): void {
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      deployment_mode TEXT NOT NULL DEFAULT 'standalone',
      org_recovery_public_key TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      email TEXT NOT NULL,
      display_name TEXT NOT NULL,
      system_role TEXT NOT NULL DEFAULT 'SuperAdmin',
      kdf_algorithm TEXT NOT NULL DEFAULT 'PBKDF2-HMAC-SHA256',
      kdf_salt TEXT NOT NULL,
      kdf_iterations INTEGER NOT NULL DEFAULT 600000,
      server_password_hash TEXT,
      x25519_public_key TEXT NOT NULL,
      ed25519_public_key TEXT NOT NULL,
      public_key_fingerprint TEXT NOT NULL,
      encrypted_x25519_private_key TEXT NOT NULL,
      encrypted_ed25519_private_key TEXT NOT NULL,
      totp_secret TEXT,
      is_break_glass_admin INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE (tenant_id, email)
    );

    CREATE TABLE IF NOT EXISTS vaults (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      key_version INTEGER NOT NULL DEFAULT 1,
      rotation_required INTEGER NOT NULL DEFAULT 0,
      org_recovery_encrypted_vault_key TEXT,
      created_by_user_id TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vault_member_keys (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      vault_id TEXT NOT NULL REFERENCES vaults(id),
      user_id TEXT NOT NULL REFERENCES users(id),
      vault_role TEXT NOT NULL,
      key_version INTEGER NOT NULL,
      encrypted_vault_key TEXT,
      iv TEXT,
      auth_tag TEXT,
      aad TEXT,
      granted_by_user_id TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL,
      revoked_at TEXT,
      UNIQUE (vault_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      vault_id TEXT NOT NULL REFERENCES vaults(id),
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      vault_role TEXT NOT NULL DEFAULT 'SecretConsumer',
      scopes_json TEXT NOT NULL DEFAULT '[]',
      key_version INTEGER NOT NULL,
      agent_encrypted_vault_key TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      aad TEXT NOT NULL,
      allow_raw_context_reveal INTEGER NOT NULL DEFAULT 0,
      token_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_by_user_id TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL,
      revoked_at TEXT
    );

    CREATE TABLE IF NOT EXISTS folders (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      vault_id TEXT NOT NULL REFERENCES vaults(id),
      parent_folder_id TEXT,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS secrets (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      vault_id TEXT NOT NULL REFERENCES vaults(id),
      folder_id TEXT REFERENCES folders(id),
      current_version INTEGER NOT NULL DEFAULT 1,
      key_version INTEGER NOT NULL DEFAULT 1,
      encrypted_metadata TEXT NOT NULL,
      metadata_iv TEXT NOT NULL,
      metadata_auth_tag TEXT NOT NULL,
      metadata_aad TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_by_actor_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS secret_versions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      vault_id TEXT NOT NULL REFERENCES vaults(id),
      secret_id TEXT NOT NULL REFERENCES secrets(id),
      version INTEGER NOT NULL,
      key_version INTEGER NOT NULL,
      encrypted_payload TEXT NOT NULL,
      payload_iv TEXT NOT NULL,
      payload_auth_tag TEXT NOT NULL,
      payload_aad TEXT NOT NULL,
      created_by_actor_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE (secret_id, version)
    );

    CREATE TABLE IF NOT EXISTS secret_tag_indexes (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      vault_id TEXT NOT NULL REFERENCES vaults(id),
      secret_id TEXT NOT NULL REFERENCES secrets(id),
      tag_blind_index TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE (secret_id, tag_blind_index)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      vault_id TEXT,
      actor_id TEXT NOT NULL,
      actor_type TEXT NOT NULL,
      action TEXT NOT NULL,
      target_id TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      canonical_event_json TEXT NOT NULL,
      prev_event_hash TEXT NOT NULL,
      event_hash TEXT NOT NULL,
      signature TEXT,
      timestamp TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_vaults_tenant ON vaults(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_vault_member_keys_vault ON vault_member_keys(vault_id);
    CREATE INDEX IF NOT EXISTS idx_vault_member_keys_user ON vault_member_keys(user_id);
    CREATE INDEX IF NOT EXISTS idx_agents_vault ON agents(vault_id);
    CREATE INDEX IF NOT EXISTS idx_secrets_vault ON secrets(vault_id);
    CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id);
    CREATE INDEX IF NOT EXISTS idx_secret_tag_indexes_vault_tag ON secret_tag_indexes(vault_id, tag_blind_index);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_time ON audit_logs(tenant_id, timestamp);
  `);
}

export function getDefaultDbPath(): string {
  const custom = process.env["LLM_VAULT_DB_PATH"];
  if (custom) return custom;
  const dir = path.join(os.homedir(), ".llm-vault");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return path.join(dir, "vault.db");
}

export function createDatabase(dbPath?: string): VaultDatabase {
  const resolvedPath = dbPath ?? getDefaultDbPath();
  const sqlite = new Database(resolvedPath);
  initSchema(sqlite);
  const db = drizzle(sqlite, { schema: sqliteSchema });
  return { db, sqlite, path: resolvedPath };
}
