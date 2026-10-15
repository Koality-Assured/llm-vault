import crypto from "node:crypto";
import fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import { and, desc, eq } from "drizzle-orm";
import { generateEntityId } from "@llm-vault/ids";
import {
  isMcpAllowedScope,
  VAULT_ROLE_PERMISSIONS,
  type PermissionScope,
  type VaultRole,
} from "@llm-vault/schema";
import {
  agents,
  auditLogs,
  secrets,
  secretTagIndexes,
  secretVersions,
  tenants,
  users,
  vaultMemberKeys,
  vaults,
} from "@llm-vault/schema/db/sqlite";
import {
  authenticateRequest,
  ensureDefaultStandaloneTenant,
  hashAgentToken,
  hashServerPassword,
  issueSessionToken,
  type AuthenticatedCaller,
} from "./auth.js";
import { createDatabase, type VaultDatabase } from "./db.js";

declare module "fastify" {
  interface FastifyRequest {
    caller?: AuthenticatedCaller | null;
  }
}

export interface BuildServerOptions {
  database?: VaultDatabase;
  dbPath?: string;
  enableCors?: boolean;
}

export function buildServer(options: BuildServerOptions = {}): FastifyInstance {
  const database = options.database ?? createDatabase(options.dbPath);
  ensureDefaultStandaloneTenant(database);

  const app = fastify({
    logger: false,
  });

  if (options.enableCors !== false) {
    void app.register(cors, {
      origin: true,
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    });
  }

  // Authentication Hook
  app.addHook("preHandler", async (request: FastifyRequest) => {
    const caller = await authenticateRequest(database, request.headers.authorization);
    request.caller = caller;
  });

  // Guard Helper
  const requireAuth = (request: FastifyRequest, reply: FastifyReply): AuthenticatedCaller => {
    if (!request.caller) {
      reply.status(401).send({ error: "Unauthorized: Valid Bearer token required" });
      throw new Error("Unauthorized");
    }
    return request.caller;
  };

  const requireScope = (
    caller: AuthenticatedCaller,
    scope: PermissionScope,
    reply: FastifyReply,
  ) => {
    if (!caller.scopes.includes(scope)) {
      reply.status(403).send({ error: `Forbidden: Missing required scope "${scope}"` });
      throw new Error("Forbidden");
    }
  };

  // Helper to append audit logs
  const recordAudit = (
    tenantId: string,
    vaultId: string | null,
    actorId: string,
    actorType: "user" | "agent",
    action: string,
    targetId: string,
    ipAddress: string,
    metadataObj: Record<string, unknown> = {},
  ): string => {
    const auditId = generateEntityId("aud_");
    const timestamp = new Date().toISOString();
    const canonicalJson = JSON.stringify({
      id: auditId,
      tenantId,
      vaultId,
      actorId,
      actorType,
      action,
      targetId,
      timestamp,
      metadata: metadataObj,
    });

    const prevLogs = database.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.tenantId, tenantId))
      .orderBy(desc(auditLogs.timestamp))
      .limit(1)
      .all();

    const prevEventHash =
      prevLogs[0]?.eventHash ??
      "GENESIS_0000000000000000000000000000000000000000000000000000000000000000";
    const calculatedHash = crypto
      .createHash("sha256")
      .update(`${prevEventHash}:${canonicalJson}`)
      .digest("hex");

    database.db
      .insert(auditLogs)
      .values({
        id: auditId,
        tenantId,
        vaultId: vaultId ?? undefined,
        actorId,
        actorType,
        action,
        targetId,
        ipAddress,
        canonicalEventJson: canonicalJson,
        prevEventHash,
        eventHash: calculatedHash,
        timestamp,
      })
      .run();

    return auditId;
  };

  // -------------------------------------------------------------------------
  // Health & Status
  // -------------------------------------------------------------------------

  app.get("/api/v1/health", async () => {
    return { status: "ok" };
  });

  app.get("/api/v1/status", async () => {
    const tenantsList = database.db.select().from(tenants).all();
    const deploymentMode = tenantsList[0]?.deploymentMode ?? "standalone";
    return {
      status: "ok",
      deploymentMode,
      serverTime: new Date().toISOString(),
      version: "0.1.0",
    };
  });

  // -------------------------------------------------------------------------
  // Auth Routes
  // -------------------------------------------------------------------------

  app.post("/api/v1/auth/bootstrap", async (request, reply) => {
    const existingUsers = database.db.select().from(users).all();
    if (existingUsers.length > 0) {
      return reply.status(409).send({ error: "System already initialized. Use /auth/login." });
    }

    const body = request.body as {
      email: string;
      displayName: string;
      kdfSalt: string;
      kdfIterations?: number;
      clientAuthKeyHex: string;
      x25519PublicKey: string;
      ed25519PublicKey: string;
      publicKeyFingerprint: string;
      encryptedX25519PrivateKey: string;
      encryptedEd25519PrivateKey: string;
    };

    if (!body.email || !body.clientAuthKeyHex || !body.kdfSalt) {
      return reply.status(400).send({ error: "Missing required bootstrap parameters." });
    }

    const tenantId = ensureDefaultStandaloneTenant(database);
    const userId = generateEntityId("usr_");
    const serverPasswordHash = hashServerPassword(body.clientAuthKeyHex, body.kdfSalt);
    const now = new Date().toISOString();

    database.db
      .insert(users)
      .values({
        id: userId,
        tenantId,
        email: body.email.toLowerCase().trim(),
        displayName: body.displayName.trim() || "Local Administrator",
        systemRole: "SuperAdmin",
        kdfAlgorithm: "PBKDF2-HMAC-SHA256",
        kdfSalt: body.kdfSalt,
        kdfIterations: body.kdfIterations ?? 600000,
        serverPasswordHash,
        x25519PublicKey: body.x25519PublicKey,
        ed25519PublicKey: body.ed25519PublicKey,
        publicKeyFingerprint: body.publicKeyFingerprint,
        encryptedX25519PrivateKey: body.encryptedX25519PrivateKey,
        encryptedEd25519PrivateKey: body.encryptedEd25519PrivateKey,
        isBreakGlassAdmin: true,
        status: "active",
        createdAt: now,
        updatedAt: now,
      })
      .run();

    const caller: AuthenticatedCaller = {
      actorId: userId,
      actorType: "user",
      tenantId,
      email: body.email.toLowerCase().trim(),
      displayName: body.displayName.trim(),
      systemRole: "SuperAdmin",
      scopes: Object.values(VAULT_ROLE_PERMISSIONS.WorkspaceOwner),
    };

    const token = issueSessionToken(caller);
    return reply.status(201).send({
      userId,
      tenantId,
      sessionToken: token,
      message: "Standalone vault bootstrap successful.",
    });
  });

  app.post("/api/v1/auth/login", async (request, reply) => {
    const body = request.body as {
      email: string;
      clientAuthKeyHex: string;
    };

    if (!body.email || !body.clientAuthKeyHex) {
      return reply.status(400).send({ error: "Email and clientAuthKeyHex are required." });
    }

    const userList = database.db
      .select()
      .from(users)
      .where(eq(users.email, body.email.toLowerCase().trim()))
      .all();

    const user = userList[0];
    if (!user || user.status !== "active" || !user.serverPasswordHash) {
      return reply.status(401).send({ error: "Invalid credentials." });
    }

    const calculated = hashServerPassword(body.clientAuthKeyHex, user.kdfSalt);
    if (calculated !== user.serverPasswordHash) {
      return reply.status(401).send({ error: "Invalid credentials." });
    }

    const caller: AuthenticatedCaller = {
      actorId: user.id,
      actorType: "user",
      tenantId: user.tenantId,
      email: user.email,
      displayName: user.displayName,
      systemRole: user.systemRole,
      scopes: Object.values(VAULT_ROLE_PERMISSIONS.WorkspaceOwner),
    };

    const token = issueSessionToken(caller);
    return reply.send({
      userId: user.id,
      tenantId: user.tenantId,
      displayName: user.displayName,
      systemRole: user.systemRole,
      kdfSalt: user.kdfSalt,
      kdfIterations: user.kdfIterations,
      publicKeyFingerprint: user.publicKeyFingerprint,
      encryptedX25519PrivateKey: user.encryptedX25519PrivateKey,
      sessionToken: token,
    });
  });

  app.get("/api/v1/auth/me", async (request, reply) => {
    const caller = requireAuth(request, reply);
    return reply.send({ caller });
  });

  // -------------------------------------------------------------------------
  // Vault Routes
  // -------------------------------------------------------------------------

  app.post("/api/v1/vaults", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "vaults:create", reply);

    const body = request.body as {
      name: string;
      description?: string | undefined;
      encryptedVaultKey: {
        ciphertext: string;
        iv: string;
        authTag: string;
        aad: string;
        keyVersion?: number;
      };
    };

    if (!body.name || !body.encryptedVaultKey) {
      return reply
        .status(400)
        .send({ error: "Vault name and encryptedVaultKey envelope required." });
    }

    const vaultId = generateEntityId("vlt_");
    const now = new Date().toISOString();
    const keyVersion = body.encryptedVaultKey.keyVersion ?? 1;

    database.db
      .insert(vaults)
      .values({
        id: vaultId,
        tenantId: caller.tenantId,
        name: body.name.trim(),
        description: body.description?.trim() ?? "",
        keyVersion,
        createdByUserId: caller.actorId,
        createdAt: now,
        updatedAt: now,
      })
      .run();

    // Assign caller VaultAdmin/WorkspaceOwner in vault_member_keys
    const memberKeyId = generateEntityId("vlt_");
    database.db
      .insert(vaultMemberKeys)
      .values({
        id: memberKeyId,
        tenantId: caller.tenantId,
        vaultId,
        userId: caller.actorId,
        vaultRole: "WorkspaceOwner",
        keyVersion,
        encryptedVaultKey: body.encryptedVaultKey.ciphertext,
        iv: body.encryptedVaultKey.iv,
        authTag: body.encryptedVaultKey.authTag,
        aad: body.encryptedVaultKey.aad,
        grantedByUserId: caller.actorId,
        createdAt: now,
      })
      .run();

    recordAudit(
      caller.tenantId,
      vaultId,
      caller.actorId,
      caller.actorType,
      "vaults:create",
      vaultId,
      request.ip,
    );

    return reply.status(201).send({
      id: vaultId,
      name: body.name.trim(),
      keyVersion,
      createdAt: now,
    });
  });

  app.get("/api/v1/vaults", async (request, reply) => {
    const caller = requireAuth(request, reply);

    if (caller.actorType === "agent") {
      // Agents only see their bound vault
      const agentList = database.db
        .select()
        .from(agents)
        .where(eq(agents.id, caller.actorId))
        .all();
      const boundVaultId = agentList[0]?.vaultId;
      if (!boundVaultId) return reply.send({ vaults: [] });

      const vaultList = database.db.select().from(vaults).where(eq(vaults.id, boundVaultId)).all();
      return reply.send({ vaults: vaultList });
    }

    // Users see vaults where they have membership
    const memberships = database.db
      .select({
        vaultId: vaultMemberKeys.vaultId,
        role: vaultMemberKeys.vaultRole,
        encryptedVaultKey: vaultMemberKeys.encryptedVaultKey,
        iv: vaultMemberKeys.iv,
        authTag: vaultMemberKeys.authTag,
        aad: vaultMemberKeys.aad,
      })
      .from(vaultMemberKeys)
      .where(
        and(
          eq(vaultMemberKeys.userId, caller.actorId),
          eq(vaultMemberKeys.tenantId, caller.tenantId),
        ),
      )
      .all();

    const vaultIds = memberships.map((m) => m.vaultId);
    const vaultRecords = database.db
      .select()
      .from(vaults)
      .where(eq(vaults.tenantId, caller.tenantId))
      .all();
    const accessible = vaultRecords.filter((v) => vaultIds.includes(v.id));

    return reply.send({
      vaults: accessible.map((v) => {
        const mem = memberships.find((m) => m.vaultId === v.id);
        return {
          id: v.id,
          name: v.name,
          description: v.description,
          keyVersion: v.keyVersion,
          role: mem?.role,
          encryptedVaultKey: mem
            ? {
                ciphertext: mem.encryptedVaultKey,
                iv: mem.iv,
                authTag: mem.authTag,
                aad: mem.aad,
                keyVersion: v.keyVersion,
              }
            : undefined,
          createdAt: v.createdAt,
          updatedAt: v.updatedAt,
        };
      }),
    });
  });

  app.get("/api/v1/vaults/:id", async (request, reply) => {
    const caller = requireAuth(request, reply);
    const { id } = request.params as { id: string };

    const vaultList = database.db.select().from(vaults).where(eq(vaults.id, id)).all();
    const vault = vaultList[0];
    if (!vault) {
      return reply.status(404).send({ error: `Vault ${id} not found.` });
    }

    let wrappedKeyEnvelope: Record<string, unknown> | null = null;
    if (caller.actorType === "agent") {
      const agList = database.db.select().from(agents).where(eq(agents.id, caller.actorId)).all();
      const ag = agList[0];
      if (ag && ag.vaultId === vault.id) {
        wrappedKeyEnvelope = {
          ciphertext: ag.agentEncryptedVaultKey,
          iv: ag.iv,
          authTag: ag.authTag,
          aad: ag.aad,
          keyVersion: ag.keyVersion,
        };
      }
    } else {
      const memList = database.db
        .select()
        .from(vaultMemberKeys)
        .where(and(eq(vaultMemberKeys.vaultId, id), eq(vaultMemberKeys.userId, caller.actorId)))
        .all();
      const mem = memList[0];
      if (mem) {
        wrappedKeyEnvelope = {
          ciphertext: mem.encryptedVaultKey,
          iv: mem.iv,
          authTag: mem.authTag,
          aad: mem.aad,
          keyVersion: mem.keyVersion,
        };
      }
    }

    return reply.send({
      vault: {
        id: vault.id,
        name: vault.name,
        description: vault.description,
        keyVersion: vault.keyVersion,
        createdAt: vault.createdAt,
        updatedAt: vault.updatedAt,
      },
      encryptedVaultKey: wrappedKeyEnvelope,
    });
  });

  // -------------------------------------------------------------------------
  // Secret Routes (Zero-Knowledge Envelope CRUD & Blind-Index Search)
  // -------------------------------------------------------------------------

  app.post("/api/v1/vaults/:vaultId/secrets", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "secrets:create", reply);
    const { vaultId } = request.params as { vaultId: string };

    const body = request.body as {
      id?: string | undefined;
      folderId?: string | undefined;
      version?: number;
      keyVersion?: number;
      encryptedMetadata: {
        algorithm: "AES-256-GCM";
        ciphertext: string;
        iv: string;
        authTag: string;
        aad: string;
        keyVersion: number;
      };
      encryptedPayload: {
        algorithm: "AES-256-GCM";
        ciphertext: string;
        iv: string;
        authTag: string;
        aad: string;
        keyVersion: number;
      };
      tagBlindIndexes?: string[] | undefined;
    };

    if (!body.encryptedMetadata || !body.encryptedPayload) {
      return reply.status(400).send({ error: "Missing encryptedMetadata or encryptedPayload." });
    }

    const secretId = body.id ?? generateEntityId("sec_");
    const version = 1;
    const keyVersion = body.keyVersion ?? 1;
    const now = new Date().toISOString();

    database.db
      .insert(secrets)
      .values({
        id: secretId,
        tenantId: caller.tenantId,
        vaultId,
        folderId: body.folderId ?? undefined,
        currentVersion: version,
        keyVersion,
        encryptedMetadata: body.encryptedMetadata.ciphertext,
        metadataIv: body.encryptedMetadata.iv,
        metadataAuthTag: body.encryptedMetadata.authTag,
        metadataAad: body.encryptedMetadata.aad,
        status: "active",
        createdByActorId: caller.actorId,
        createdAt: now,
        updatedAt: now,
      })
      .run();

    database.db
      .insert(secretVersions)
      .values({
        id: generateEntityId("sec_"),
        tenantId: caller.tenantId,
        vaultId,
        secretId,
        version,
        keyVersion,
        encryptedPayload: body.encryptedPayload.ciphertext,
        payloadIv: body.encryptedPayload.iv,
        payloadAuthTag: body.encryptedPayload.authTag,
        payloadAad: body.encryptedPayload.aad,
        createdByActorId: caller.actorId,
        createdAt: now,
      })
      .run();

    if (body.tagBlindIndexes && Array.isArray(body.tagBlindIndexes)) {
      for (const idx of body.tagBlindIndexes) {
        database.db
          .insert(secretTagIndexes)
          .values({
            id: generateEntityId("sec_"),
            tenantId: caller.tenantId,
            vaultId,
            secretId,
            tagBlindIndex: idx,
            createdAt: now,
          })
          .run();
      }
    }

    recordAudit(
      caller.tenantId,
      vaultId,
      caller.actorId,
      caller.actorType,
      "secrets:create",
      secretId,
      request.ip,
    );

    return reply.status(201).send({
      id: secretId,
      vaultId,
      version,
      keyVersion,
      createdAt: now,
    });
  });

  app.get("/api/v1/vaults/:vaultId/secrets", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "secrets:read", reply);
    const { vaultId } = request.params as { vaultId: string };
    const query = request.query as { tagBlindIndex?: string | undefined };

    let secretRows = database.db
      .select()
      .from(secrets)
      .where(and(eq(secrets.vaultId, vaultId), eq(secrets.status, "active")))
      .all();

    if (query.tagBlindIndex) {
      const matchingTags = database.db
        .select()
        .from(secretTagIndexes)
        .where(
          and(
            eq(secretTagIndexes.vaultId, vaultId),
            eq(secretTagIndexes.tagBlindIndex, query.tagBlindIndex),
          ),
        )
        .all();
      const matchSecretIds = new Set(matchingTags.map((t) => t.secretId));
      secretRows = secretRows.filter((s) => matchSecretIds.has(s.id));
    }

    const items = secretRows.map((s) => {
      const tagRows = database.db
        .select()
        .from(secretTagIndexes)
        .where(eq(secretTagIndexes.secretId, s.id))
        .all();
      return {
        id: s.id,
        vaultId: s.vaultId,
        folderId: s.folderId,
        version: s.currentVersion,
        keyVersion: s.keyVersion,
        encryptedMetadata: {
          algorithm: "AES-256-GCM" as const,
          ciphertext: s.encryptedMetadata,
          iv: s.metadataIv,
          authTag: s.metadataAuthTag,
          aad: s.metadataAad,
          keyVersion: s.keyVersion,
        },
        tagBlindIndexes: tagRows.map((t) => t.tagBlindIndex),
        createdAt: s.createdAt,
        updatedAt: s.updatedAt,
      };
    });

    return reply.send({ secrets: items });
  });

  app.get("/api/v1/secrets/:id", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "secrets:read", reply);
    const { id } = request.params as { id: string };

    const secretList = database.db.select().from(secrets).where(eq(secrets.id, id)).all();
    const secret = secretList[0];
    if (!secret || secret.status !== "active") {
      return reply.status(404).send({ error: `Secret ${id} not found.` });
    }

    const tagRows = database.db
      .select()
      .from(secretTagIndexes)
      .where(eq(secretTagIndexes.secretId, secret.id))
      .all();

    return reply.send({
      id: secret.id,
      vaultId: secret.vaultId,
      folderId: secret.folderId,
      version: secret.currentVersion,
      keyVersion: secret.keyVersion,
      encryptedMetadata: {
        algorithm: "AES-256-GCM" as const,
        ciphertext: secret.encryptedMetadata,
        iv: secret.metadataIv,
        authTag: secret.metadataAuthTag,
        aad: secret.metadataAad,
        keyVersion: secret.keyVersion,
      },
      tagBlindIndexes: tagRows.map((t) => t.tagBlindIndex),
      createdAt: secret.createdAt,
      updatedAt: secret.updatedAt,
    });
  });

  // Zero-knowledge secret reveal endpoint
  app.post("/api/v1/secrets/:id/reveal", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "secrets:reveal", reply);
    const { id } = request.params as { id: string };

    const secretList = database.db.select().from(secrets).where(eq(secrets.id, id)).all();
    const secret = secretList[0];
    if (!secret || secret.status !== "active") {
      return reply.status(404).send({ error: `Secret ${id} not found.` });
    }

    const versionList = database.db
      .select()
      .from(secretVersions)
      .where(
        and(eq(secretVersions.secretId, id), eq(secretVersions.version, secret.currentVersion)),
      )
      .all();
    const currentVersion = versionList[0];
    if (!currentVersion) {
      return reply.status(404).send({ error: `Payload version for ${id} not found.` });
    }

    // Retrieve caller's wrapped VaultKey envelope
    let callerVaultKeyEnvelope: Record<string, unknown> | null = null;
    if (caller.actorType === "agent") {
      const agList = database.db.select().from(agents).where(eq(agents.id, caller.actorId)).all();
      const ag = agList[0];
      if (ag && ag.vaultId === secret.vaultId) {
        callerVaultKeyEnvelope = {
          ciphertext: ag.agentEncryptedVaultKey,
          iv: ag.iv,
          authTag: ag.authTag,
          aad: ag.aad,
          keyVersion: ag.keyVersion,
        };
      }
    } else {
      const memList = database.db
        .select()
        .from(vaultMemberKeys)
        .where(
          and(
            eq(vaultMemberKeys.vaultId, secret.vaultId),
            eq(vaultMemberKeys.userId, caller.actorId),
          ),
        )
        .all();
      const mem = memList[0];
      if (mem) {
        callerVaultKeyEnvelope = {
          ciphertext: mem.encryptedVaultKey,
          iv: mem.iv,
          authTag: mem.authTag,
          aad: mem.aad,
          keyVersion: mem.keyVersion,
        };
      }
    }

    if (!callerVaultKeyEnvelope) {
      return reply
        .status(403)
        .send({ error: "Access denied: caller does not have an active vault key grant." });
    }

    const auditEventId = recordAudit(
      caller.tenantId,
      secret.vaultId,
      caller.actorId,
      caller.actorType,
      "secrets:reveal",
      secret.id,
      request.ip,
      { version: secret.currentVersion },
    );

    return reply.send({
      id: secret.id,
      vaultId: secret.vaultId,
      version: secret.currentVersion,
      keyVersion: secret.keyVersion,
      encryptedPayload: {
        algorithm: "AES-256-GCM",
        ciphertext: currentVersion.encryptedPayload,
        iv: currentVersion.payloadIv,
        authTag: currentVersion.payloadAuthTag,
        aad: currentVersion.payloadAad,
        keyVersion: currentVersion.keyVersion,
      },
      encryptedVaultKey: callerVaultKeyEnvelope,
      auditEventId,
    });
  });

  app.put("/api/v1/secrets/:id", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "secrets:update", reply);
    const { id } = request.params as { id: string };

    const secretList = database.db.select().from(secrets).where(eq(secrets.id, id)).all();
    const current = secretList[0];
    if (!current || current.status !== "active") {
      return reply.status(404).send({ error: `Secret ${id} not found.` });
    }

    const body = request.body as {
      encryptedMetadata: {
        algorithm: "AES-256-GCM";
        ciphertext: string;
        iv: string;
        authTag: string;
        aad: string;
        keyVersion: number;
      };
      encryptedPayload: {
        algorithm: "AES-256-GCM";
        ciphertext: string;
        iv: string;
        authTag: string;
        aad: string;
        keyVersion: number;
      };
      tagBlindIndexes?: string[] | undefined;
    };

    const nextVersion = current.currentVersion + 1;
    const now = new Date().toISOString();

    database.db
      .update(secrets)
      .set({
        currentVersion: nextVersion,
        encryptedMetadata: body.encryptedMetadata.ciphertext,
        metadataIv: body.encryptedMetadata.iv,
        metadataAuthTag: body.encryptedMetadata.authTag,
        metadataAad: body.encryptedMetadata.aad,
        updatedAt: now,
      })
      .where(eq(secrets.id, id))
      .run();

    database.db
      .insert(secretVersions)
      .values({
        id: generateEntityId("sec_"),
        tenantId: caller.tenantId,
        vaultId: current.vaultId,
        secretId: id,
        version: nextVersion,
        keyVersion: current.keyVersion,
        encryptedPayload: body.encryptedPayload.ciphertext,
        payloadIv: body.encryptedPayload.iv,
        payloadAuthTag: body.encryptedPayload.authTag,
        payloadAad: body.encryptedPayload.aad,
        createdByActorId: caller.actorId,
        createdAt: now,
      })
      .run();

    if (body.tagBlindIndexes) {
      database.db.delete(secretTagIndexes).where(eq(secretTagIndexes.secretId, id)).run();
      for (const idx of body.tagBlindIndexes) {
        database.db
          .insert(secretTagIndexes)
          .values({
            id: generateEntityId("sec_"),
            tenantId: caller.tenantId,
            vaultId: current.vaultId,
            secretId: id,
            tagBlindIndex: idx,
            createdAt: now,
          })
          .run();
      }
    }

    recordAudit(
      caller.tenantId,
      current.vaultId,
      caller.actorId,
      caller.actorType,
      "secrets:update",
      id,
      request.ip,
      { version: nextVersion },
    );

    return reply.send({
      id,
      version: nextVersion,
      updatedAt: now,
    });
  });

  app.delete("/api/v1/secrets/:id", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "secrets:delete", reply);
    const { id } = request.params as { id: string };

    const secretList = database.db.select().from(secrets).where(eq(secrets.id, id)).all();
    const current = secretList[0];
    if (!current) {
      return reply.status(404).send({ error: `Secret ${id} not found.` });
    }

    database.db.delete(secrets).where(eq(secrets.id, id)).run();
    database.db.delete(secretVersions).where(eq(secretVersions.secretId, id)).run();
    database.db.delete(secretTagIndexes).where(eq(secretTagIndexes.secretId, id)).run();

    recordAudit(
      caller.tenantId,
      current.vaultId,
      caller.actorId,
      caller.actorType,
      "secrets:delete",
      id,
      request.ip,
    );

    return reply.send({ success: true, id });
  });

  app.get("/api/v1/secrets/:id/versions", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "secrets:read", reply);
    const { id } = request.params as { id: string };

    const versions = database.db
      .select()
      .from(secretVersions)
      .where(eq(secretVersions.secretId, id))
      .orderBy(desc(secretVersions.version))
      .all();

    return reply.send({
      versions: versions.map((v) => ({
        version: v.version,
        keyVersion: v.keyVersion,
        encryptedPayload: {
          algorithm: "AES-256-GCM" as const,
          ciphertext: v.encryptedPayload,
          iv: v.payloadIv,
          authTag: v.payloadAuthTag,
          aad: v.payloadAad,
          keyVersion: v.keyVersion,
        },
        createdAt: v.createdAt,
      })),
    });
  });

  // -------------------------------------------------------------------------
  // Agent Provisioning & Key Delegation
  // -------------------------------------------------------------------------

  app.post("/api/v1/agents", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "agent:token:create", reply);

    const body = request.body as {
      vaultId: string;
      name: string;
      description?: string | undefined;
      vaultRole?: VaultRole | undefined;
      scopes?: PermissionScope[] | undefined;
      keyVersion: number;
      agentEncryptedVaultKey: {
        ciphertext: string;
        iv: string;
        authTag: string;
        aad: string;
      };
      allowRawContextReveal?: boolean | undefined;
    };

    if (!body.vaultId || !body.name || !body.agentEncryptedVaultKey) {
      return reply.status(400).send({ error: "Missing vaultId, name, or agentEncryptedVaultKey." });
    }

    const assignedScopes =
      body.scopes ?? Object.values(VAULT_ROLE_PERMISSIONS[body.vaultRole ?? "SecretConsumer"]);
    const hasAdminScope = assignedScopes.some((s) => !isMcpAllowedScope(s as PermissionScope));
    if (hasAdminScope) {
      return reply.status(400).send({
        error: "Security violation: Agent identities cannot be granted human-only admin scopes.",
      });
    }

    const agentId = generateEntityId("agt_");
    const secretTokenPart = crypto.randomBytes(32).toString("hex");
    const fullAgentToken = `${agentId}.${secretTokenPart}`;
    const tokenHash = hashAgentToken(fullAgentToken);
    const now = new Date().toISOString();

    database.db
      .insert(agents)
      .values({
        id: agentId,
        tenantId: caller.tenantId,
        vaultId: body.vaultId,
        name: body.name.trim(),
        description: body.description?.trim() ?? "",
        vaultRole: body.vaultRole ?? "SecretConsumer",
        scopesJson: JSON.stringify(assignedScopes),
        keyVersion: body.keyVersion,
        agentEncryptedVaultKey: body.agentEncryptedVaultKey.ciphertext,
        iv: body.agentEncryptedVaultKey.iv,
        authTag: body.agentEncryptedVaultKey.authTag,
        aad: body.agentEncryptedVaultKey.aad,
        allowRawContextReveal: Boolean(body.allowRawContextReveal),
        tokenHash,
        status: "active",
        createdByUserId: caller.actorId,
        createdAt: now,
      })
      .run();

    recordAudit(
      caller.tenantId,
      body.vaultId,
      caller.actorId,
      caller.actorType,
      "agent:token:create",
      agentId,
      request.ip,
    );

    return reply.status(201).send({
      id: agentId,
      vaultId: body.vaultId,
      name: body.name.trim(),
      token: fullAgentToken,
      message:
        "Agent token generated. Save token securely in workstation keychain; token will not be shown again.",
    });
  });

  app.get("/api/v1/agents/:id/vault-key", async (request, reply) => {
    const caller = requireAuth(request, reply);
    const { id } = request.params as { id: string };

    if (caller.actorType === "agent" && caller.actorId !== id) {
      return reply
        .status(403)
        .send({ error: "Forbidden: Agent can only request its own vault key." });
    }

    const agList = database.db.select().from(agents).where(eq(agents.id, id)).all();
    const ag = agList[0];
    if (!ag || ag.status !== "active") {
      return reply.status(404).send({ error: `Agent ${id} not found.` });
    }

    return reply.send({
      agentId: ag.id,
      vaultId: ag.vaultId,
      keyVersion: ag.keyVersion,
      agentEncryptedVaultKey: {
        ciphertext: ag.agentEncryptedVaultKey,
        iv: ag.iv,
        authTag: ag.authTag,
        aad: ag.aad,
        keyVersion: ag.keyVersion,
      },
    });
  });

  // -------------------------------------------------------------------------
  // Audit Logs
  // -------------------------------------------------------------------------

  app.get("/api/v1/audit/logs", async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (
      caller.systemRole !== "SuperAdmin" &&
      caller.systemRole !== "ComplianceAuditor" &&
      !caller.scopes.includes("admin:audit:read")
    ) {
      return reply.status(403).send({ error: 'Forbidden: Missing "admin:audit:read" scope' });
    }

    const logs = database.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.tenantId, caller.tenantId))
      .orderBy(desc(auditLogs.timestamp))
      .limit(100)
      .all();

    return reply.send({ logs });
  });

  return app;
}
