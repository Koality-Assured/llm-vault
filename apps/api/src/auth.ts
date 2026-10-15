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
  return crypto.scryptSync(clientAuthKeyHex, serverSalt, 32).toString("hex");
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

export function ensureDefaultEnterpriseTenant(
  database: VaultDatabase,
  slug: string = "default",
  name: string = "Enterprise Organization",
): string {
  const existing = database.db.select().from(tenants).where(eq(tenants.slug, slug)).all();
  if (existing.length > 0 && existing[0]?.id) {
    return existing[0].id;
  }

  const tenantId = `tnt_${crypto.randomBytes(12).toString("hex")}`;
  const now = new Date().toISOString();
  database.db
    .insert(tenants)
    .values({
      id: tenantId,
      name,
      slug,
      deploymentMode: "enterprise",
      createdAt: now,
      updatedAt: now,
    })
    .run();

  return tenantId;
}

export interface OidcClaims {
  sub: string;
  email: string;
  name?: string | undefined;
  tenantId?: string | undefined;
}

export interface PendingOidcAuth {
  codeChallenge: string;
  claims: OidcClaims;
  expiresAt: number;
}

const mockOidcStore = new Map<string, PendingOidcAuth>();

export function createMockOidcAuthorization(
  claims: OidcClaims,
  codeChallenge: string,
  ttlMs: number = 300_000,
): { code: string; state: string } {
  const code = `oidc_code_${crypto.randomBytes(24).toString("hex")}`;
  const state = crypto.randomBytes(16).toString("hex");
  mockOidcStore.set(code, {
    codeChallenge,
    claims,
    expiresAt: Date.now() + ttlMs,
  });
  return { code, state };
}

export function exchangeMockOidcCode(code: string, codeVerifier: string): OidcClaims {
  const pending = mockOidcStore.get(code);
  if (!pending) {
    throw new Error("Invalid or expired OIDC authorization code");
  }
  if (Date.now() > pending.expiresAt) {
    mockOidcStore.delete(code);
    throw new Error("OIDC authorization code has expired");
  }

  const expectedChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  if (expectedChallenge !== pending.codeChallenge) {
    throw new Error("OIDC PKCE code_verifier challenge mismatch");
  }

  mockOidcStore.delete(code);
  return pending.claims;
}

export function createMockSamlResponseXml(claims: {
  email: string;
  name?: string;
  sub: string;
  issuer?: string;
  inResponseTo?: string;
}): string {
  const now = new Date().toISOString();
  const issuer = claims.issuer ?? "https://mock-idp.llm-vault.local";
  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_saml_${crypto.randomBytes(16).toString("hex")}" IssueInstant="${now}" Destination="http://localhost:8443/api/v1/auth/saml/callback">
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assert_${crypto.randomBytes(16).toString("hex")}" IssueInstant="${now}" Version="2.0">
    <saml:Issuer>${issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${claims.email}</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>${claims.email}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue>${claims.name ?? "SAML User"}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="sub"><saml:AttributeValue>${claims.sub}</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;
}

function extractTagContent(xml: string, openTag: string, closeTag: string): string | null {
  const start = xml.indexOf(openTag);
  if (start === -1) return null;
  const tagEnd = xml.indexOf(">", start + openTag.length);
  if (tagEnd === -1) return null;
  const end = xml.indexOf(closeTag, tagEnd + 1);
  if (end === -1) return null;
  return xml.slice(tagEnd + 1, end).trim();
}

function extractAttributeValue(xml: string, attributeName: string): string | null {
  const attrMarker = `Name="${attributeName}"`;
  const attrStart = xml.indexOf(attrMarker);
  if (attrStart === -1) return null;
  const valOpen = "<saml:AttributeValue";
  const valStart = xml.indexOf(valOpen, attrStart);
  if (valStart === -1) return null;
  const tagEnd = xml.indexOf(">", valStart + valOpen.length);
  if (tagEnd === -1) return null;
  const valClose = "</saml:AttributeValue>";
  const end = xml.indexOf(valClose, tagEnd + 1);
  if (end === -1) return null;
  return xml.slice(tagEnd + 1, end).trim();
}

export function parseMockSamlResponse(samlResponseBase64: string): {
  email: string;
  name: string;
  sub: string;
} {
  const xml = Buffer.from(samlResponseBase64, "base64").toString("utf8");
  if (!xml.includes("samlp:Response") || !xml.includes("Success")) {
    throw new Error("Invalid SAML response or non-success status");
  }

  const nameId = extractTagContent(xml, "<saml:NameID", "</saml:NameID>");
  const emailAttr = extractAttributeValue(xml, "email");
  const email = (emailAttr ?? nameId ?? "").trim();
  if (!email) {
    throw new Error("SAML response does not contain a valid email address");
  }

  const nameAttr = extractAttributeValue(xml, "displayName");
  const name = (nameAttr ?? email.split("@")[0] ?? "SAML User").trim();

  const subAttr = extractAttributeValue(xml, "sub");
  const sub = (subAttr ?? email).trim();

  return { email, name, sub };
}
