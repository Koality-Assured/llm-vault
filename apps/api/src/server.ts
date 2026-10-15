import crypto from "node:crypto";
import fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { and, desc, eq } from "drizzle-orm";
import { generateEntityId } from "@llm-vault/ids";
import {
  AdminCreateUserRequestSchema,
  AdminSiemConfigRequestSchema,
  AdminUpdateIdpRequestSchema,
  AdminUpdateUserRequestSchema,
  ApproveRecoveryRequestSchema,
  InitiateRecoveryRequestSchema,
  SYSTEM_ROLES,
  SYSTEM_ROLE_PERMISSIONS,
  VAULT_ROLES,
  VAULT_ROLE_PERMISSIONS,
  isMcpAllowedScope,
  type PermissionScope,
  type SystemRole,
  type VaultRole,
} from "@llm-vault/schema";
import {
  agents,
  auditLogs,
  idpConfigs,
  recoveryRequests,
  secrets,
  secretTagIndexes,
  secretVersions,
  siemConfigs,
  tenants,
  users,
  vaultMemberKeys,
  vaults,
} from "@llm-vault/schema/db/sqlite";
import {
  authenticateRequest,
  createMockOidcAuthorization,
  ensureDefaultEnterpriseTenant,
  ensureDefaultStandaloneTenant,
  exchangeMockOidcCode,
  hashAgentToken,
  hashServerPassword,
  issueSessionToken,
  parseMockSamlResponse,
  type AuthenticatedCaller,
  type OidcClaims,
} from "./auth.js";
import {
  combineRecoveryKey,
  unwrapVaultKeyWithOrgRecoveryKey,
  verifyTotpCode,
  zeroizeBuffer,
  type OrgRecoveryWrappedVaultKey,
} from "@llm-vault/crypto";
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
  deploymentMode?: "enterprise" | "standalone";
}

export function buildServer(options: BuildServerOptions = {}): FastifyInstance {
  const database = options.database ?? createDatabase(options.dbPath);
  const deploymentMode =
    options.deploymentMode ??
    (process.env["DEPLOYMENT_MODE"] === "enterprise" ? "enterprise" : "standalone");
  if (deploymentMode === "enterprise") {
    ensureDefaultEnterpriseTenant(database);
  } else {
    ensureDefaultStandaloneTenant(database);
  }

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

  void app.register(rateLimit, {
    max: 1000,
    timeWindow: "1 minute",
  });

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

  const requireHumanAdmin = (caller: AuthenticatedCaller, reply: FastifyReply) => {
    if (caller.actorType !== "user") {
      reply.status(403).send({
        error:
          "Forbidden: Administrative mutation endpoints are restricted to human administrators.",
      });
      throw new Error("Forbidden");
    }
  };

  const requireSystemRole = (
    caller: AuthenticatedCaller,
    allowedRoles: SystemRole[],
    reply: FastifyReply,
  ) => {
    if (!caller.systemRole || !allowedRoles.includes(caller.systemRole as SystemRole)) {
      reply.status(403).send({
        error: `Forbidden: Caller requires one of the following system roles: ${allowedRoles.join(", ")}`,
      });
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

    if (deploymentMode === "enterprise") {
      void (async () => {
        try {
          const siemList = database.db
            .select()
            .from(siemConfigs)
            .where(eq(siemConfigs.tenantId, tenantId))
            .all();
          const siem = siemList[0];
          const webhookUrl =
            siem && siem.enabled ? siem.webhookUrl : process.env["SIEM_WEBHOOK_URL"];
          const sharedSecret =
            siem?.sharedSecret ?? process.env["SIEM_WEBHOOK_SECRET"] ?? "default-secret";
          if (webhookUrl) {
            const hmac = crypto
              .createHmac("sha256", sharedSecret)
              .update(canonicalJson)
              .digest("hex");
            await fetch(webhookUrl, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Llm-Vault-Event-Id": auditId,
                "X-Llm-Vault-Timestamp": timestamp,
                "X-Llm-Vault-Signature": hmac,
              },
              body: canonicalJson,
            }).catch(() => {
              // Non-blocking SIEM delivery failure tolerance
            });
          }
        } catch {
          // Non-blocking
        }
      })();
    }

    return auditId;
  };

  // -------------------------------------------------------------------------
  // Health & Status
  // -------------------------------------------------------------------------

  app.get("/api/v1/health", async () => {
    return { status: "ok" };
  });

  app.get("/api/v1/status", async () => {
    return {
      status: "ok",
      deploymentMode,
      serverTime: new Date().toISOString(),
      version: "0.1.0",
    };
  });

  // -------------------------------------------------------------------------
  // Tenant Routes
  // -------------------------------------------------------------------------

  app.post("/api/v1/tenants", async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (caller.systemRole !== "SuperAdmin") {
      return reply.status(403).send({ error: "Forbidden: SuperAdmin required to create tenants." });
    }

    const body = request.body as {
      name: string;
      slug: string;
      deploymentMode?: "enterprise" | "standalone";
      orgRecoveryPublicKey?: string;
    };

    if (!body.name || !body.slug) {
      return reply.status(400).send({ error: "name and slug are required." });
    }

    const tenantId = `tnt_${crypto.randomBytes(12).toString("hex")}`;
    const now = new Date().toISOString();
    database.db
      .insert(tenants)
      .values({
        id: tenantId,
        name: body.name.trim(),
        slug: body.slug.toLowerCase().trim(),
        deploymentMode: body.deploymentMode ?? "enterprise",
        orgRecoveryPublicKey: body.orgRecoveryPublicKey,
        createdAt: now,
        updatedAt: now,
      })
      .run();

    recordAudit(
      tenantId,
      null,
      caller.actorId,
      caller.actorType,
      "admin:users:manage",
      tenantId,
      request.ip,
      { action: "create_tenant", slug: body.slug },
    );

    return reply.status(201).send({
      id: tenantId,
      name: body.name.trim(),
      slug: body.slug.toLowerCase().trim(),
      deploymentMode: body.deploymentMode ?? "enterprise",
      createdAt: now,
    });
  });

  app.get("/api/v1/tenants", async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (caller.systemRole === "SuperAdmin") {
      const allTenants = database.db.select().from(tenants).all();
      return reply.send({ tenants: allTenants });
    }
    const tenantList = database.db
      .select()
      .from(tenants)
      .where(eq(tenants.id, caller.tenantId))
      .all();
    return reply.send({ tenants: tenantList });
  });

  app.get("/api/v1/tenants/:id", async (request, reply) => {
    const caller = requireAuth(request, reply);
    const { id } = request.params as { id: string };
    if (caller.systemRole !== "SuperAdmin" && caller.tenantId !== id) {
      return reply.status(403).send({ error: "Forbidden: Access to tenant denied." });
    }

    const tenantList = database.db.select().from(tenants).where(eq(tenants.id, id)).all();
    const tenant = tenantList[0];
    if (!tenant) {
      return reply.status(404).send({ error: `Tenant ${id} not found.` });
    }
    return reply.send({ tenant });
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
      isBreakGlassAdmin?: boolean;
      totpSecret?: string;
    };

    if (!body.email || !body.clientAuthKeyHex || !body.kdfSalt) {
      return reply.status(400).send({ error: "Missing required bootstrap parameters." });
    }

    const tenantId =
      deploymentMode === "enterprise"
        ? ensureDefaultEnterpriseTenant(database)
        : ensureDefaultStandaloneTenant(database);
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
        totpSecret: body.totpSecret,
        isBreakGlassAdmin: body.isBreakGlassAdmin ?? true,
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
      message: "Vault bootstrap successful.",
    });
  });

  const handlePasswordLogin = async (request: FastifyRequest, reply: FastifyReply) => {
    if (deploymentMode === "enterprise") {
      return reply.status(403).send({
        error:
          "Direct password authentication is disabled in enterprise mode. Use OIDC/SAML SSO or break-glass authentication.",
      });
    }

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

    const userSysRole = (user.systemRole ?? "SecretConsumer") as SystemRole;
    const systemScopes = (SYSTEM_ROLE_PERMISSIONS[userSysRole] ?? []) as string[];
    const caller: AuthenticatedCaller = {
      actorId: user.id,
      actorType: "user",
      tenantId: user.tenantId,
      email: user.email,
      displayName: user.displayName,
      systemRole: user.systemRole,
      scopes: systemScopes,
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
  };

  app.post("/api/v1/auth/login", handlePasswordLogin);
  app.post("/api/v1/auth/standalone/login", handlePasswordLogin);

  // -------------------------------------------------------------------------
  // Enterprise SSO Routes (OIDC PKCE & SAML 2.0)
  // -------------------------------------------------------------------------

  app.post("/api/v1/auth/oidc/authorize", async (request, reply) => {
    const body = request.body as {
      email: string;
      name?: string;
      tenantId?: string;
      codeChallenge: string;
    };

    if (!body.email || !body.codeChallenge) {
      return reply.status(400).send({ error: "email and codeChallenge are required." });
    }

    const tenantId = body.tenantId ?? database.db.select().from(tenants).all()[0]?.id ?? "default";

    const { code, state } = createMockOidcAuthorization(
      {
        sub: `oidc_sub_${crypto.randomBytes(8).toString("hex")}`,
        email: body.email.toLowerCase().trim(),
        name: body.name ?? body.email.split("@")[0],
        tenantId,
      },
      body.codeChallenge,
    );

    return reply.send({
      code,
      state,
      redirectUri: "/api/v1/auth/oidc/callback",
    });
  });

  app.post("/api/v1/auth/oidc/callback", async (request, reply) => {
    const body = request.body as {
      code: string;
      codeVerifier: string;
      state?: string;
      tenantId?: string;
    };

    if (!body.code || !body.codeVerifier) {
      return reply.status(400).send({ error: "code and codeVerifier are required." });
    }

    let claims: OidcClaims;
    try {
      claims = exchangeMockOidcCode(body.code, body.codeVerifier);
    } catch (err: unknown) {
      return reply.status(401).send({ error: (err as Error).message });
    }

    const tenantId =
      body.tenantId ??
      claims.tenantId ??
      database.db.select().from(tenants).all()[0]?.id ??
      "default";

    const userList = database.db
      .select()
      .from(users)
      .where(and(eq(users.email, claims.email.toLowerCase().trim()), eq(users.tenantId, tenantId)))
      .all();

    let user = userList[0];
    const now = new Date().toISOString();

    if (!user) {
      const userId = generateEntityId("usr_");
      database.db
        .insert(users)
        .values({
          id: userId,
          tenantId,
          email: claims.email.toLowerCase().trim(),
          displayName: claims.name ?? claims.email.split("@")[0] ?? "SSO User",
          systemRole: "SecretConsumer",
          kdfAlgorithm: "PBKDF2-HMAC-SHA256",
          kdfSalt: crypto.randomBytes(32).toString("hex"),
          kdfIterations: 600000,
          x25519PublicKey: "",
          ed25519PublicKey: "",
          publicKeyFingerprint: "",
          encryptedX25519PrivateKey: "",
          encryptedEd25519PrivateKey: "",
          isBreakGlassAdmin: false,
          status: "active",
          createdAt: now,
          updatedAt: now,
        })
        .run();
      user = database.db.select().from(users).where(eq(users.id, userId)).all()[0]!;
    }

    const userSysRole = (user.systemRole ?? "SecretConsumer") as SystemRole;
    const systemScopes = (SYSTEM_ROLE_PERMISSIONS[userSysRole] ?? []) as string[];
    const caller: AuthenticatedCaller = {
      actorId: user.id,
      actorType: "user",
      tenantId: user.tenantId,
      email: user.email,
      displayName: user.displayName,
      systemRole: user.systemRole,
      scopes: systemScopes,
    };

    const token = issueSessionToken(caller);
    recordAudit(tenantId, null, user.id, "user", "secrets:read", user.id, request.ip, {
      method: "oidc_pkce",
      sub: claims.sub,
    });

    return reply.send({
      userId: user.id,
      tenantId: user.tenantId,
      email: user.email,
      displayName: user.displayName,
      systemRole: user.systemRole,
      kdfSalt: user.kdfSalt,
      kdfIterations: user.kdfIterations,
      publicKeyFingerprint: user.publicKeyFingerprint,
      encryptedX25519PrivateKey: user.encryptedX25519PrivateKey,
      sessionToken: token,
      unlockRequired: true,
    });
  });

  app.post("/api/v1/auth/saml/login", async (request, reply) => {
    const body = (request.body ?? {}) as { tenantId?: string; relayState?: string };
    const relayState = body.relayState ?? crypto.randomBytes(16).toString("hex");
    const samlRequest = Buffer.from(
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_${crypto.randomBytes(16).toString("hex")}" Version="2.0" IssueInstant="${new Date().toISOString()}"/>`,
    ).toString("base64");

    return reply.send({
      ssoUrl: "/api/v1/auth/saml/callback",
      samlRequest,
      relayState,
    });
  });

  app.post("/api/v1/auth/saml/callback", async (request, reply) => {
    const body = request.body as { samlResponse: string; relayState?: string; tenantId?: string };
    if (!body.samlResponse) {
      return reply.status(400).send({ error: "samlResponse is required." });
    }

    let claims: { email: string; name: string; sub: string };
    try {
      claims = parseMockSamlResponse(body.samlResponse);
    } catch (err: unknown) {
      return reply.status(401).send({ error: (err as Error).message });
    }

    const tenantId = body.tenantId ?? database.db.select().from(tenants).all()[0]?.id ?? "default";
    const userList = database.db
      .select()
      .from(users)
      .where(and(eq(users.email, claims.email.toLowerCase().trim()), eq(users.tenantId, tenantId)))
      .all();

    let user = userList[0];
    const now = new Date().toISOString();

    if (!user) {
      const userId = generateEntityId("usr_");
      database.db
        .insert(users)
        .values({
          id: userId,
          tenantId,
          email: claims.email.toLowerCase().trim(),
          displayName: claims.name,
          systemRole: "SecretConsumer",
          kdfAlgorithm: "PBKDF2-HMAC-SHA256",
          kdfSalt: crypto.randomBytes(32).toString("hex"),
          kdfIterations: 600000,
          x25519PublicKey: "",
          ed25519PublicKey: "",
          publicKeyFingerprint: "",
          encryptedX25519PrivateKey: "",
          encryptedEd25519PrivateKey: "",
          isBreakGlassAdmin: false,
          status: "active",
          createdAt: now,
          updatedAt: now,
        })
        .run();
      user = database.db.select().from(users).where(eq(users.id, userId)).all()[0]!;
    }

    const userSysRole = (user.systemRole ?? "SecretConsumer") as SystemRole;
    const systemScopes = (SYSTEM_ROLE_PERMISSIONS[userSysRole] ?? []) as string[];
    const caller: AuthenticatedCaller = {
      actorId: user.id,
      actorType: "user",
      tenantId: user.tenantId,
      email: user.email,
      displayName: user.displayName,
      systemRole: user.systemRole,
      scopes: systemScopes,
    };

    const token = issueSessionToken(caller);
    recordAudit(tenantId, null, user.id, "user", "secrets:read", user.id, request.ip, {
      method: "saml2",
      sub: claims.sub,
    });

    return reply.send({
      userId: user.id,
      tenantId: user.tenantId,
      email: user.email,
      displayName: user.displayName,
      systemRole: user.systemRole,
      kdfSalt: user.kdfSalt,
      kdfIterations: user.kdfIterations,
      publicKeyFingerprint: user.publicKeyFingerprint,
      encryptedX25519PrivateKey: user.encryptedX25519PrivateKey,
      sessionToken: token,
      unlockRequired: true,
    });
  });

  app.post("/api/v1/auth/break-glass/login", async (request, reply) => {
    const body = request.body as {
      email: string;
      clientAuthKeyHex: string;
      totpCode: string;
      reason: string;
      tenantId?: string;
    };

    if (!body.email || !body.clientAuthKeyHex || !body.totpCode || !body.reason) {
      return reply.status(400).send({
        error: "email, clientAuthKeyHex, totpCode, and reason are required for break-glass login.",
      });
    }

    const userList = database.db
      .select()
      .from(users)
      .where(eq(users.email, body.email.toLowerCase().trim()))
      .all();

    const user = userList[0];
    if (!user || user.status !== "active" || !user.isBreakGlassAdmin || !user.serverPasswordHash) {
      return reply.status(401).send({ error: "Invalid break-glass credentials or unauthorized." });
    }

    const calculatedHash = hashServerPassword(body.clientAuthKeyHex, user.kdfSalt);
    if (calculatedHash !== user.serverPasswordHash) {
      return reply.status(401).send({ error: "Invalid break-glass credentials." });
    }

    if (!user.totpSecret) {
      return reply.status(403).send({ error: "MFA not configured for this break-glass admin." });
    }

    const isTotpValid = await verifyTotpCode(body.totpCode, user.totpSecret);
    if (!isTotpValid) {
      return reply.status(401).send({ error: "Invalid or expired TOTP MFA code." });
    }

    const caller: AuthenticatedCaller = {
      actorId: user.id,
      actorType: "user",
      tenantId: user.tenantId,
      email: user.email,
      displayName: user.displayName,
      systemRole: "SuperAdmin",
      scopes: [...SYSTEM_ROLE_PERMISSIONS.SuperAdmin],
    };

    const token = issueSessionToken(caller);
    recordAudit(user.tenantId, null, user.id, "user", "admin:users:manage", user.id, request.ip, {
      severity: "CRITICAL",
      action: "break_glass_login",
      reason: body.reason,
    });

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
      isBreakGlass: true,
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

    const vaultId = (body as { id?: string }).id ?? generateEntityId("vlt_");
    const now = new Date().toISOString();
    const keyVersion = body.encryptedVaultKey.keyVersion ?? 1;

    const rawRecoveryKey = (body as { orgRecoveryEncryptedVaultKey?: unknown })
      .orgRecoveryEncryptedVaultKey;
    const orgRecoveryEncryptedVaultKey =
      typeof rawRecoveryKey === "object" && rawRecoveryKey !== null
        ? JSON.stringify(rawRecoveryKey)
        : typeof rawRecoveryKey === "string"
          ? rawRecoveryKey
          : undefined;

    database.db
      .insert(vaults)
      .values({
        id: vaultId,
        tenantId: caller.tenantId,
        name: body.name.trim(),
        description: body.description?.trim() ?? "",
        keyVersion,
        orgRecoveryEncryptedVaultKey,
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
        if (mem.vaultRole === "SecretReader" || !mem.encryptedVaultKey) {
          wrappedKeyEnvelope = null;
        } else {
          wrappedKeyEnvelope = {
            ciphertext: mem.encryptedVaultKey,
            iv: mem.iv,
            authTag: mem.authTag,
            aad: mem.aad,
            keyVersion: mem.keyVersion,
          };
        }
      }
    }

    return reply.send({
      vault: {
        id: vault.id,
        name: vault.name,
        description: vault.description,
        keyVersion: vault.keyVersion,
        rotationRequired: Boolean(vault.rotationRequired),
        createdAt: vault.createdAt,
        updatedAt: vault.updatedAt,
      },
      encryptedVaultKey: wrappedKeyEnvelope,
    });
  });

  // -------------------------------------------------------------------------
  // Vault Sharing, Revocation & Key Rotation Routes
  // -------------------------------------------------------------------------

  app.post("/api/v1/vaults/:vaultId/members", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "vaults:share", reply);
    const { vaultId } = request.params as { vaultId: string };

    const body = request.body as {
      userId: string;
      vaultRole: VaultRole;
      encryptedVaultKey?: {
        ciphertext: string;
        iv: string;
        authTag: string;
        aad: string;
        keyVersion: number;
      };
    };

    const isSecretReader = body.vaultRole === "SecretReader";
    if (!body.userId || !body.vaultRole || (!isSecretReader && !body.encryptedVaultKey)) {
      return reply.status(400).send({
        error: "userId, vaultRole, and encryptedVaultKey are required (unless SecretReader).",
      });
    }

    const vaultList = database.db.select().from(vaults).where(eq(vaults.id, vaultId)).all();
    const vault = vaultList[0];
    if (!vault) {
      return reply.status(404).send({ error: `Vault ${vaultId} not found.` });
    }

    const recipientList = database.db.select().from(users).where(eq(users.id, body.userId)).all();
    const recipient = recipientList[0];
    if (!recipient || recipient.status !== "active") {
      return reply.status(404).send({ error: `Recipient user ${body.userId} not found.` });
    }

    const now = new Date().toISOString();
    const existing = database.db
      .select()
      .from(vaultMemberKeys)
      .where(and(eq(vaultMemberKeys.vaultId, vaultId), eq(vaultMemberKeys.userId, body.userId)))
      .all();

    const keyVersion = isSecretReader
      ? (vault.keyVersion ?? 1)
      : body.encryptedVaultKey!.keyVersion;
    const encKey = isSecretReader ? null : body.encryptedVaultKey!.ciphertext;
    const iv = isSecretReader ? null : body.encryptedVaultKey!.iv;
    const authTag = isSecretReader ? null : body.encryptedVaultKey!.authTag;
    const aad = isSecretReader ? null : body.encryptedVaultKey!.aad;

    let memberKeyId: string;
    if (existing.length > 0 && existing[0]?.id) {
      memberKeyId = existing[0].id;
      database.db
        .update(vaultMemberKeys)
        .set({
          vaultRole: body.vaultRole,
          keyVersion,
          encryptedVaultKey: encKey,
          iv,
          authTag,
          aad,
          grantedByUserId: caller.actorId,
          revokedAt: null,
        })
        .where(eq(vaultMemberKeys.id, memberKeyId))
        .run();
    } else {
      memberKeyId = generateEntityId("vlt_");
      database.db
        .insert(vaultMemberKeys)
        .values({
          id: memberKeyId,
          tenantId: caller.tenantId,
          vaultId,
          userId: body.userId,
          vaultRole: body.vaultRole,
          keyVersion,
          encryptedVaultKey: encKey,
          iv,
          authTag,
          aad,
          grantedByUserId: caller.actorId,
          createdAt: now,
          revokedAt: null,
        })
        .run();
    }

    recordAudit(
      caller.tenantId,
      vaultId,
      caller.actorId,
      caller.actorType,
      "vaults:share",
      body.userId,
      request.ip,
      { vaultRole: body.vaultRole, keyVersion },
    );

    return reply.status(201).send({
      id: memberKeyId,
      vaultId,
      userId: body.userId,
      vaultRole: body.vaultRole,
      keyVersion,
    });
  });

  app.get("/api/v1/vaults/:vaultId/members", async (request, reply) => {
    requireAuth(request, reply);
    const { vaultId } = request.params as { vaultId: string };

    const members = database.db
      .select({
        id: vaultMemberKeys.id,
        userId: vaultMemberKeys.userId,
        vaultRole: vaultMemberKeys.vaultRole,
        keyVersion: vaultMemberKeys.keyVersion,
        grantedByUserId: vaultMemberKeys.grantedByUserId,
        createdAt: vaultMemberKeys.createdAt,
        revokedAt: vaultMemberKeys.revokedAt,
        email: users.email,
        displayName: users.displayName,
        x25519PublicKey: users.x25519PublicKey,
        publicKeyFingerprint: users.publicKeyFingerprint,
      })
      .from(vaultMemberKeys)
      .innerJoin(users, eq(vaultMemberKeys.userId, users.id))
      .where(eq(vaultMemberKeys.vaultId, vaultId))
      .all();

    return reply.send({ members });
  });

  app.delete("/api/v1/vaults/:vaultId/members/:userId", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "vaults:share", reply);
    const { vaultId, userId } = request.params as { vaultId: string; userId: string };

    const now = new Date().toISOString();
    database.db
      .update(vaultMemberKeys)
      .set({ revokedAt: now })
      .where(and(eq(vaultMemberKeys.vaultId, vaultId), eq(vaultMemberKeys.userId, userId)))
      .run();

    // Mandatory VaultKey rotation flag per [H-2]
    database.db
      .update(vaults)
      .set({ rotationRequired: true, updatedAt: now })
      .where(eq(vaults.id, vaultId))
      .run();

    recordAudit(
      caller.tenantId,
      vaultId,
      caller.actorId,
      caller.actorType,
      "vaults:share",
      userId,
      request.ip,
      { action: "revoke_member", rotationRequired: true },
    );

    return reply.send({
      status: "revoked",
      vaultId,
      userId,
      rotationRequired: true,
      message: "Member revoked. Mandatory VaultKey rotation is required on this vault.",
    });
  });

  app.delete("/api/v1/vaults/:vaultId/agents/:agentId", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "agent:token:revoke", reply);
    const { vaultId, agentId } = request.params as { vaultId: string; agentId: string };

    const now = new Date().toISOString();
    database.db
      .update(agents)
      .set({ status: "revoked", revokedAt: now })
      .where(and(eq(agents.vaultId, vaultId), eq(agents.id, agentId)))
      .run();

    // Mandatory VaultKey rotation flag per [H-2]
    database.db
      .update(vaults)
      .set({ rotationRequired: true, updatedAt: now })
      .where(eq(vaults.id, vaultId))
      .run();

    recordAudit(
      caller.tenantId,
      vaultId,
      caller.actorId,
      caller.actorType,
      "agent:token:revoke",
      agentId,
      request.ip,
      { action: "revoke_agent", rotationRequired: true },
    );

    return reply.send({
      status: "revoked",
      vaultId,
      agentId,
      rotationRequired: true,
      message: "Agent token revoked. Mandatory VaultKey rotation is required on this vault.",
    });
  });

  app.post("/api/v1/vaults/:vaultId/rotate-key", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireScope(caller, "vaults:rotate_key", reply);
    const { vaultId } = request.params as { vaultId: string };

    const body = request.body as {
      newKeyVersion: number;
      memberKeys: Array<{
        userId: string;
        encryptedVaultKey: string;
        iv: string;
        authTag: string;
        aad: string;
      }>;
      agentKeys?: Array<{
        agentId: string;
        agentEncryptedVaultKey: string;
        iv: string;
        authTag: string;
        aad: string;
      }>;
      reencryptedSecrets?: Array<{
        secretId: string;
        encryptedPayload: string;
        payloadIv: string;
        payloadAuthTag: string;
        payloadAad: string;
      }>;
    };

    if (!body.newKeyVersion || !body.memberKeys || body.memberKeys.length === 0) {
      return reply
        .status(400)
        .send({ error: "newKeyVersion and memberKeys for remaining members are required." });
    }

    const vaultList = database.db.select().from(vaults).where(eq(vaults.id, vaultId)).all();
    const vault = vaultList[0];
    if (!vault) {
      return reply.status(404).send({ error: `Vault ${vaultId} not found.` });
    }

    if (body.newKeyVersion !== vault.keyVersion + 1) {
      return reply.status(400).send({
        error: `Invalid newKeyVersion: expected ${vault.keyVersion + 1}, received ${body.newKeyVersion}`,
      });
    }

    const now = new Date().toISOString();

    // Update vault key version and clear rotationRequired
    database.db
      .update(vaults)
      .set({
        keyVersion: body.newKeyVersion,
        rotationRequired: false,
        updatedAt: now,
      })
      .where(eq(vaults.id, vaultId))
      .run();

    // Update active members with new wrapped key
    for (const mem of body.memberKeys) {
      database.db
        .update(vaultMemberKeys)
        .set({
          keyVersion: body.newKeyVersion,
          encryptedVaultKey: mem.encryptedVaultKey,
          iv: mem.iv,
          authTag: mem.authTag,
          aad: mem.aad,
          revokedAt: null,
        })
        .where(and(eq(vaultMemberKeys.vaultId, vaultId), eq(vaultMemberKeys.userId, mem.userId)))
        .run();
    }

    // Update active agents if provided
    if (body.agentKeys) {
      for (const ag of body.agentKeys) {
        database.db
          .update(agents)
          .set({
            keyVersion: body.newKeyVersion,
            agentEncryptedVaultKey: ag.agentEncryptedVaultKey,
            iv: ag.iv,
            authTag: ag.authTag,
            aad: ag.aad,
          })
          .where(and(eq(agents.vaultId, vaultId), eq(agents.id, ag.agentId)))
          .run();
      }
    }

    // Re-encrypt active secret payloads
    if (body.reencryptedSecrets) {
      for (const sec of body.reencryptedSecrets) {
        const secretRecords = database.db
          .select()
          .from(secrets)
          .where(eq(secrets.id, sec.secretId))
          .all();
        const currentSecret = secretRecords[0];
        if (currentSecret) {
          const nextVersion = currentSecret.currentVersion + 1;
          database.db
            .insert(secretVersions)
            .values({
              id: generateEntityId("sec_"),
              tenantId: caller.tenantId,
              vaultId,
              secretId: sec.secretId,
              version: nextVersion,
              keyVersion: body.newKeyVersion,
              encryptedPayload: sec.encryptedPayload,
              payloadIv: sec.payloadIv,
              payloadAuthTag: sec.payloadAuthTag,
              payloadAad: sec.payloadAad,
              createdByActorId: caller.actorId,
              createdAt: now,
            })
            .run();

          database.db
            .update(secrets)
            .set({
              currentVersion: nextVersion,
              keyVersion: body.newKeyVersion,
              updatedAt: now,
            })
            .where(eq(secrets.id, sec.secretId))
            .run();
        }
      }
    }

    recordAudit(
      caller.tenantId,
      vaultId,
      caller.actorId,
      caller.actorType,
      "vaults:rotate_key",
      vaultId,
      request.ip,
      {
        previousKeyVersion: vault.keyVersion,
        newKeyVersion: body.newKeyVersion,
        membersRotated: body.memberKeys.length,
        agentsRotated: body.agentKeys?.length ?? 0,
        secretsReencrypted: body.reencryptedSecrets?.length ?? 0,
      },
    );

    return reply.send({
      status: "rotated",
      vaultId,
      keyVersion: body.newKeyVersion,
      rotationRequired: false,
      membersCount: body.memberKeys.length,
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
      if (ag?.vaultRole === "SecretReader") {
        return reply
          .status(403)
          .send({ error: "Forbidden: SecretReader role cannot reveal secrets." });
      }
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
      if (mem?.vaultRole === "SecretReader") {
        return reply
          .status(403)
          .send({ error: "Forbidden: SecretReader role cannot reveal secrets." });
      }
      if (mem && mem.encryptedVaultKey) {
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

  // -------------------------------------------------------------------------
  // Human-Only Admin Management Routes (Section 5 & 6)
  // -------------------------------------------------------------------------

  // GET /api/v1/admin/users
  app.get("/api/v1/admin/users", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireScope(caller, "admin:users:manage", reply);

    const userList =
      caller.systemRole === "SuperAdmin"
        ? database.db.select().from(users).all()
        : database.db.select().from(users).where(eq(users.tenantId, caller.tenantId)).all();

    const safeUsers = userList.map((u) => ({
      id: u.id,
      tenantId: u.tenantId,
      email: u.email,
      displayName: u.displayName,
      systemRole: u.systemRole,
      status: u.status,
      isBreakGlassAdmin: Boolean(u.isBreakGlassAdmin),
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
    }));

    return reply.send({ users: safeUsers });
  });

  // POST /api/v1/admin/users
  app.post("/api/v1/admin/users", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireScope(caller, "admin:users:manage", reply);

    const body = AdminCreateUserRequestSchema.parse(request.body);
    const existing = database.db
      .select()
      .from(users)
      .where(
        and(eq(users.tenantId, caller.tenantId), eq(users.email, body.email.toLowerCase().trim())),
      )
      .all();
    if (existing.length > 0) {
      return reply.status(409).send({ error: `User with email ${body.email} already exists.` });
    }

    const userId = generateEntityId("usr_");
    const now = new Date().toISOString();
    const salt = crypto.randomBytes(32).toString("hex");
    const placeholderKey = crypto.randomBytes(32).toString("base64");

    database.db
      .insert(users)
      .values({
        id: userId,
        tenantId: caller.tenantId,
        email: body.email.toLowerCase().trim(),
        displayName: body.displayName.trim(),
        systemRole: body.systemRole ?? "SecretConsumer",
        kdfAlgorithm: "PBKDF2-HMAC-SHA256",
        kdfSalt: salt,
        kdfIterations: 600000,
        x25519PublicKey: placeholderKey,
        ed25519PublicKey: placeholderKey,
        publicKeyFingerprint: crypto.createHash("sha256").update(placeholderKey).digest("hex"),
        encryptedX25519PrivateKey: placeholderKey,
        encryptedEd25519PrivateKey: placeholderKey,
        status: body.status ?? "active",
        createdAt: now,
        updatedAt: now,
      })
      .run();

    recordAudit(
      caller.tenantId,
      null,
      caller.actorId,
      caller.actorType,
      "admin:users:manage",
      userId,
      request.ip,
      { action: "create_user", email: body.email },
    );

    return reply.status(201).send({
      id: userId,
      tenantId: caller.tenantId,
      email: body.email.toLowerCase().trim(),
      displayName: body.displayName.trim(),
      systemRole: body.systemRole ?? "SecretConsumer",
      status: body.status ?? "active",
      createdAt: now,
    });
  });

  // PUT /api/v1/admin/users/:id
  app.put("/api/v1/admin/users/:id", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    const { id } = request.params as { id: string };

    const body = AdminUpdateUserRequestSchema.parse(request.body);
    if (body.systemRole) {
      requireScope(caller, "admin:roles:manage", reply);
    } else {
      requireScope(caller, "admin:users:manage", reply);
    }

    const targetUser = database.db.select().from(users).where(eq(users.id, id)).all()[0];
    if (!targetUser) {
      return reply.status(404).send({ error: `User ${id} not found.` });
    }

    const now = new Date().toISOString();
    const updateValues: Record<string, unknown> = { updatedAt: now };
    if (body.displayName) updateValues["displayName"] = body.displayName.trim();
    if (body.status) updateValues["status"] = body.status;
    if (body.systemRole) updateValues["systemRole"] = body.systemRole;

    database.db.update(users).set(updateValues).where(eq(users.id, id)).run();

    recordAudit(
      caller.tenantId,
      null,
      caller.actorId,
      caller.actorType,
      "admin:users:manage",
      id,
      request.ip,
      { action: "update_user", updates: body },
    );

    return reply.send({
      id,
      displayName: body.displayName ?? targetUser.displayName,
      status: body.status ?? targetUser.status,
      systemRole: body.systemRole ?? targetUser.systemRole,
      updatedAt: now,
    });
  });

  // DELETE /api/v1/admin/users/:id
  app.delete("/api/v1/admin/users/:id", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireScope(caller, "admin:users:manage", reply);
    const { id } = request.params as { id: string };

    const targetUser = database.db.select().from(users).where(eq(users.id, id)).all()[0];
    if (!targetUser) {
      return reply.status(404).send({ error: `User ${id} not found.` });
    }

    const now = new Date().toISOString();
    database.db
      .update(users)
      .set({ status: "suspended", updatedAt: now })
      .where(eq(users.id, id))
      .run();

    recordAudit(
      caller.tenantId,
      null,
      caller.actorId,
      caller.actorType,
      "admin:users:manage",
      id,
      request.ip,
      { action: "suspend_user" },
    );

    return reply.send({ success: true, userId: id, status: "suspended" });
  });

  // GET /api/v1/admin/roles
  app.get("/api/v1/admin/roles", async (request, reply) => {
    requireAuth(request, reply);
    return reply.send({
      systemRoles: SYSTEM_ROLES,
      systemRolePermissions: SYSTEM_ROLE_PERMISSIONS,
      vaultRoles: VAULT_ROLES,
      vaultRolePermissions: VAULT_ROLE_PERMISSIONS,
    });
  });

  // PUT /api/v1/admin/users/:id/role
  app.put("/api/v1/admin/users/:id/role", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireScope(caller, "admin:roles:manage", reply);
    const { id } = request.params as { id: string };
    const body = request.body as { systemRole: SystemRole };

    if (!body.systemRole || !SYSTEM_ROLES.includes(body.systemRole)) {
      return reply.status(400).send({ error: "Valid systemRole is required." });
    }

    const targetUser = database.db.select().from(users).where(eq(users.id, id)).all()[0];
    if (!targetUser) {
      return reply.status(404).send({ error: `User ${id} not found.` });
    }

    const now = new Date().toISOString();
    database.db
      .update(users)
      .set({ systemRole: body.systemRole, updatedAt: now })
      .where(eq(users.id, id))
      .run();

    recordAudit(
      caller.tenantId,
      null,
      caller.actorId,
      caller.actorType,
      "admin:roles:manage",
      id,
      request.ip,
      { action: "update_user_role", systemRole: body.systemRole },
    );

    return reply.send({ userId: id, systemRole: body.systemRole });
  });

  // GET /api/v1/admin/idp
  app.get("/api/v1/admin/idp", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireScope(caller, "admin:idp:manage", reply);

    const config = database.db
      .select()
      .from(idpConfigs)
      .where(eq(idpConfigs.tenantId, caller.tenantId))
      .all()[0];

    return reply.send({ idpConfig: config ?? null });
  });

  // PUT /api/v1/admin/idp
  app.put("/api/v1/admin/idp", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireScope(caller, "admin:idp:manage", reply);

    const body = AdminUpdateIdpRequestSchema.parse(request.body);
    const now = new Date().toISOString();
    const existing = database.db
      .select()
      .from(idpConfigs)
      .where(eq(idpConfigs.tenantId, caller.tenantId))
      .all()[0];

    if (existing) {
      database.db
        .update(idpConfigs)
        .set({
          providerType: body.providerType,
          issuer: body.issuer,
          clientId: body.clientId,
          clientSecret: body.clientSecret,
          authorizationEndpoint: body.authorizationEndpoint,
          tokenEndpoint: body.tokenEndpoint,
          ssoUrl: body.ssoUrl,
          certificate: body.certificate,
          enabled: body.enabled,
          updatedAt: now,
        })
        .where(eq(idpConfigs.id, existing.id))
        .run();
    } else {
      const configId = `idp_${crypto.randomBytes(12).toString("hex")}`;
      database.db
        .insert(idpConfigs)
        .values({
          id: configId,
          tenantId: caller.tenantId,
          providerType: body.providerType,
          issuer: body.issuer,
          clientId: body.clientId,
          clientSecret: body.clientSecret,
          authorizationEndpoint: body.authorizationEndpoint,
          tokenEndpoint: body.tokenEndpoint,
          ssoUrl: body.ssoUrl,
          certificate: body.certificate,
          enabled: body.enabled,
          createdAt: now,
          updatedAt: now,
        })
        .run();
    }

    recordAudit(
      caller.tenantId,
      null,
      caller.actorId,
      caller.actorType,
      "admin:idp:manage",
      caller.tenantId,
      request.ip,
      { action: "update_idp_config", providerType: body.providerType },
    );

    return reply.send({ success: true, providerType: body.providerType, issuer: body.issuer });
  });

  // GET /api/v1/admin/siem
  app.get("/api/v1/admin/siem", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireSystemRole(caller, ["SuperAdmin", "SecurityAdmin"], reply);

    const config = database.db
      .select()
      .from(siemConfigs)
      .where(eq(siemConfigs.tenantId, caller.tenantId))
      .all()[0];

    return reply.send({
      siemConfig: config
        ? {
            id: config.id,
            webhookUrl: config.webhookUrl,
            enabled: Boolean(config.enabled),
            sharedSecretMasked: "********",
            createdAt: config.createdAt,
            updatedAt: config.updatedAt,
          }
        : null,
    });
  });

  // POST /api/v1/admin/siem
  app.post("/api/v1/admin/siem", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireSystemRole(caller, ["SuperAdmin", "SecurityAdmin"], reply);

    const body = AdminSiemConfigRequestSchema.parse(request.body);
    const now = new Date().toISOString();
    const existing = database.db
      .select()
      .from(siemConfigs)
      .where(eq(siemConfigs.tenantId, caller.tenantId))
      .all()[0];

    if (existing) {
      database.db
        .update(siemConfigs)
        .set({
          webhookUrl: body.webhookUrl,
          sharedSecret: body.sharedSecret,
          enabled: body.enabled,
          updatedAt: now,
        })
        .where(eq(siemConfigs.id, existing.id))
        .run();
    } else {
      const configId = `siem_${crypto.randomBytes(12).toString("hex")}`;
      database.db
        .insert(siemConfigs)
        .values({
          id: configId,
          tenantId: caller.tenantId,
          webhookUrl: body.webhookUrl,
          sharedSecret: body.sharedSecret,
          enabled: body.enabled,
          createdAt: now,
          updatedAt: now,
        })
        .run();
    }

    recordAudit(
      caller.tenantId,
      null,
      caller.actorId,
      caller.actorType,
      "admin:roles:manage",
      caller.tenantId,
      request.ip,
      { action: "update_siem_config", webhookUrl: body.webhookUrl },
    );

    return reply.send({ success: true, webhookUrl: body.webhookUrl, enabled: body.enabled });
  });

  // GET /api/v1/admin/audit-logs
  app.get("/api/v1/admin/audit-logs", async (request, reply) => {
    const caller = requireAuth(request, reply);
    if (
      caller.systemRole !== "SuperAdmin" &&
      caller.systemRole !== "SecurityAdmin" &&
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

  // GET & POST /api/v1/admin/audit-logs/verify
  const handleVerifyAuditLogs = async (request: FastifyRequest, reply: FastifyReply) => {
    const caller = requireAuth(request, reply);
    if (
      caller.systemRole !== "SuperAdmin" &&
      caller.systemRole !== "SecurityAdmin" &&
      caller.systemRole !== "ComplianceAuditor" &&
      !caller.scopes.includes("admin:audit:read")
    ) {
      return reply.status(403).send({ error: 'Forbidden: Missing "admin:audit:read" scope' });
    }

    const tenantId = caller.tenantId;
    const records = database.db
      .select()
      .from(auditLogs)
      .where(eq(auditLogs.tenantId, tenantId))
      .orderBy(auditLogs.timestamp)
      .all();

    if (records.length === 0) {
      return reply.send({
        valid: true,
        totalEvents: 0,
        genesisHash: "GENESIS_0000000000000000000000000000000000000000000000000000000000000000",
        latestHash: "GENESIS_0000000000000000000000000000000000000000000000000000000000000000",
      });
    }

    let expectedPrevHash =
      "GENESIS_0000000000000000000000000000000000000000000000000000000000000000";
    for (const record of records) {
      if (record.prevEventHash !== expectedPrevHash) {
        return reply.send({
          valid: false,
          totalEvents: records.length,
          genesisHash: records[0]!.prevEventHash,
          latestHash: record.eventHash,
          failedEventId: record.id,
          reason: `Broken hash chain: expected prev hash "${expectedPrevHash}", found "${record.prevEventHash}"`,
        });
      }
      const calculatedHash = crypto
        .createHash("sha256")
        .update(`${record.prevEventHash}:${record.canonicalEventJson}`)
        .digest("hex");
      if (calculatedHash !== record.eventHash) {
        return reply.send({
          valid: false,
          totalEvents: records.length,
          genesisHash: records[0]!.prevEventHash,
          latestHash: record.eventHash,
          failedEventId: record.id,
          reason: `Hash mismatch on event ${record.id}: expected "${calculatedHash}", found "${record.eventHash}"`,
        });
      }
      expectedPrevHash = record.eventHash;
    }

    return reply.send({
      valid: true,
      totalEvents: records.length,
      genesisHash: records[0]!.prevEventHash,
      latestHash: records[records.length - 1]!.eventHash,
    });
  };

  app.get("/api/v1/admin/audit-logs/verify", handleVerifyAuditLogs);
  app.post("/api/v1/admin/audit-logs/verify", handleVerifyAuditLogs);

  // -------------------------------------------------------------------------
  // Dual-Control Organization Recovery Key Escrow (Section 1 & 6)
  // -------------------------------------------------------------------------

  // POST /api/v1/vaults/:vaultId/recovery/initiate
  app.post("/api/v1/vaults/:vaultId/recovery/initiate", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireSystemRole(caller, ["SuperAdmin", "SecurityAdmin"], reply);

    const { vaultId } = request.params as { vaultId: string };
    const parsed = InitiateRecoveryRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply
        .status(400)
        .send({ error: parsed.error.issues[0]?.message ?? "Invalid initiate recovery payload." });
    }
    const body = parsed.data;

    const vault = database.db.select().from(vaults).where(eq(vaults.id, vaultId)).all()[0];
    if (!vault || vault.tenantId !== caller.tenantId) {
      return reply.status(404).send({ error: `Vault ${vaultId} not found.` });
    }
    if (!vault.orgRecoveryEncryptedVaultKey) {
      return reply
        .status(400)
        .send({ error: "Vault does not have an escrowed OrgRecoveryEncryptedVaultKey." });
    }

    const recoveryId = `rec_${crypto.randomBytes(12).toString("hex")}`;
    const now = new Date().toISOString();

    database.db
      .insert(recoveryRequests)
      .values({
        id: recoveryId,
        tenantId: caller.tenantId,
        vaultId,
        initiatorUserId: caller.actorId,
        initiatorSystemRole: caller.systemRole!,
        initiatorShare: body.initiatorShare,
        status: "pending",
        reason: body.reason,
        createdAt: now,
        updatedAt: now,
      })
      .run();

    recordAudit(
      caller.tenantId,
      vaultId,
      caller.actorId,
      caller.actorType,
      "secrets:export",
      vaultId,
      request.ip,
      { severity: "HIGH", action: "recovery_initiate", recoveryId, reason: body.reason },
    );

    return reply.status(201).send({
      recoveryId,
      vaultId,
      status: "pending",
      message: "Recovery initiated. Counterpart admin quorum approval required.",
    });
  });

  // POST /api/v1/vaults/:vaultId/recovery/approve
  app.post("/api/v1/vaults/:vaultId/recovery/approve", async (request, reply) => {
    const caller = requireAuth(request, reply);
    requireHumanAdmin(caller, reply);
    requireSystemRole(caller, ["SuperAdmin", "SecurityAdmin"], reply);

    const { vaultId } = request.params as { vaultId: string };
    const parsed = ApproveRecoveryRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply
        .status(400)
        .send({ error: parsed.error.issues[0]?.message ?? "Invalid approve recovery payload." });
    }
    const body = parsed.data;

    const recoveryReq = database.db
      .select()
      .from(recoveryRequests)
      .where(and(eq(recoveryRequests.id, body.recoveryId), eq(recoveryRequests.vaultId, vaultId)))
      .all()[0];

    if (!recoveryReq) {
      return reply.status(404).send({ error: `Recovery request ${body.recoveryId} not found.` });
    }
    if (recoveryReq.status !== "pending") {
      return reply.status(400).send({
        error: `Recovery request is not pending (status: ${recoveryReq.status}).`,
      });
    }

    // Dual-control enforcement: Approver must be distinct human user from initiator
    if (caller.actorId === recoveryReq.initiatorUserId) {
      return reply.status(403).send({
        error:
          "Forbidden: Dual-control quorum violation. Approver cannot be the same administrator who initiated recovery.",
      });
    }

    const vault = database.db.select().from(vaults).where(eq(vaults.id, vaultId)).all()[0];
    if (!vault || !vault.orgRecoveryEncryptedVaultKey) {
      return reply.status(404).send({ error: "Vault or escrowed recovery key not found." });
    }

    let recoveryKeyEnvelope: OrgRecoveryWrappedVaultKey;
    try {
      recoveryKeyEnvelope = JSON.parse(
        vault.orgRecoveryEncryptedVaultKey,
      ) as OrgRecoveryWrappedVaultKey;
    } catch {
      return reply.status(500).send({ error: "Failed to parse escrowed recovery key envelope." });
    }

    // Combine shares and unwrap VaultKey
    let reconstructedKey: Uint8Array | null = null;
    let recoveredVaultKey: Uint8Array | null = null;
    try {
      reconstructedKey = combineRecoveryKey(recoveryReq.initiatorShare, body.approverShare);
      recoveredVaultKey = await unwrapVaultKeyWithOrgRecoveryKey(
        recoveryKeyEnvelope,
        reconstructedKey,
        vaultId,
      );
    } catch (err: unknown) {
      return reply.status(400).send({
        error: `Recovery key unwrapping failed: ${err instanceof Error ? err.message : "Invalid key share."}`,
      });
    } finally {
      // Immediate memory zeroization of reconstructed key material
      if (reconstructedKey) zeroizeBuffer(reconstructedKey);
      if (recoveredVaultKey) zeroizeBuffer(recoveredVaultKey);
    }

    const now = new Date().toISOString();
    database.db
      .update(recoveryRequests)
      .set({
        approverUserId: caller.actorId,
        approverSystemRole: caller.systemRole,
        approverShare: body.approverShare,
        status: "completed",
        updatedAt: now,
      })
      .where(eq(recoveryRequests.id, recoveryReq.id))
      .run();

    recordAudit(
      caller.tenantId,
      vaultId,
      caller.actorId,
      caller.actorType,
      "secrets:export",
      vaultId,
      request.ip,
      {
        severity: "CRITICAL",
        action: "recovery_approved",
        recoveryId: recoveryReq.id,
        initiatorUserId: recoveryReq.initiatorUserId,
        approverUserId: caller.actorId,
      },
    );

    return reply.send({
      status: "completed",
      recoveryId: recoveryReq.id,
      vaultId,
      recovered: true,
      message: "Dual-control quorum verified. VaultKey successfully unescrowed.",
    });
  });

  return app;
}
