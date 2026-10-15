import crypto from "node:crypto";
import { eq } from "drizzle-orm";
import type { VaultDatabase } from "./db.js";
import { agents, tenants } from "@llm-vault/schema/db/sqlite";

export interface AuthenticatedCaller {
  actorId: string; // usr_<ulid> or agt_<ulid>
  actorType: "user" | "agent";
  tenantId: string;
  email?: string | undefined;
  displayName?: string | undefined;
  systemRole?: string | undefined;
  vaultRole?: string | undefined;
  scopes: string[];
  allowRawContextReveal?: boolean | undefined;
}

// In-memory active user session store (token -> caller)
const activeSessions = new Map<string, { caller: AuthenticatedCaller; expiresAt: number }>();

export function hashServerPassword(clientAuthKeyHex: string, serverSalt: string): string {
  return crypto.createHmac("sha256", serverSalt).update(clientAuthKeyHex).digest("hex");
}

export function hashAgentToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function issueSessionToken(caller: AuthenticatedCaller, ttlHours: number = 24): string {
  const token = `vlt_session_${crypto.randomBytes(32).toString("hex")}`;
  const expiresAt = Date.now() + ttlHours * 3600 * 1000;
  activeSessions.set(token, { caller, expiresAt });
  return token;
}

export function revokeSessionToken(token: string): void {
  activeSessions.delete(token);
}

export async function authenticateRequest(
  database: VaultDatabase,
  authHeader?: string,
): Promise<AuthenticatedCaller | null> {
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  const token = authHeader.slice(7).trim();
  if (!token) return null;

  // Check active user session
  const session = activeSessions.get(token);
  if (session) {
    if (Date.now() > session.expiresAt) {
      activeSessions.delete(token);
      return null;
    }
    return session.caller;
  }

  // Check agent token (agt_<ulid>.<secret>)
  if (token.startsWith("agt_") && token.includes(".")) {
    const [agentId] = token.split(".");
    if (!agentId) return null;

    const tokenHash = hashAgentToken(token);
    const agentRecords = database.db.select().from(agents).where(eq(agents.id, agentId)).all();

    const agent = agentRecords[0];
    if (!agent || agent.status !== "active" || agent.tokenHash !== tokenHash) {
      return null;
    }

    const scopes = JSON.parse(agent.scopesJson) as string[];
    return {
      actorId: agent.id,
      actorType: "agent",
      tenantId: agent.tenantId,
      vaultRole: agent.vaultRole,
      scopes,
      allowRawContextReveal: Boolean(agent.allowRawContextReveal),
    };
  }

  return null;
}

export function ensureDefaultStandaloneTenant(database: VaultDatabase): string {
  const existing = database.db.select().from(tenants).all();
  if (existing.length > 0 && existing[0]?.id) {
    return existing[0].id;
  }

  const tenantId = "local";
  const now = new Date().toISOString();
  database.db
    .insert(tenants)
    .values({
      id: tenantId,
      name: "Local Standalone Workspace",
      slug: "local",
      deploymentMode: "standalone",
      createdAt: now,
      updatedAt: now,
    })
    .run();

  return tenantId;
}
