import { zeroizeBuffer } from "@llm-vault/crypto";
import type { ActiveSecret } from "./scrubber.js";
import { isValidEntityId } from "@llm-vault/ids";

export interface SecretPayloadData {
  value: string;
  username?: string;
  notes?: string;
  customFields?: Record<string, string>;
}

export type SecretFetchFunction = (secretId: string) => Promise<SecretPayloadData | string | null>;

export class SecretResolver {
  private activeSecrets: ActiveSecret[] = [];
  private cache = new Map<string, SecretPayloadData>();
  private fetcher: SecretFetchFunction;

  constructor(fetcher: SecretFetchFunction) {
    this.fetcher = fetcher;
  }

  /**
   * Resolves a secret reference by ID and optional field name.
   */
  async resolveSecret(secretId: string, field?: string): Promise<string> {
    if (!isValidEntityId(secretId, "sec_")) {
      throw new Error(`Invalid secret ID format: "${secretId}". Expected "sec_<ulid>".`);
    }

    let payload = this.cache.get(secretId);
    if (!payload) {
      const fetched = await this.fetcher(secretId);
      if (!fetched) {
        throw new Error(`Secret not found or access denied for ID: "${secretId}".`);
      }
      if (typeof fetched === "string") {
        payload = { value: fetched };
      } else {
        payload = fetched;
      }
      this.cache.set(secretId, payload);

      // Track active secret bytes for stream scrubber and memory hygiene
      const valBytes = new TextEncoder().encode(payload.value);
      this.activeSecrets.push({
        id: secretId,
        value: payload.value,
        valueBytes: valBytes,
      });

      if (payload.username) {
        this.activeSecrets.push({
          id: `${secretId}#username`,
          value: payload.username,
          valueBytes: new TextEncoder().encode(payload.username),
        });
      }
    }

    if (!field || field === "value") {
      return payload.value;
    }
    if (field === "username") {
      return payload.username ?? "";
    }
    if (field === "notes") {
      return payload.notes ?? "";
    }
    if (payload.customFields && field in payload.customFields) {
      return payload.customFields[field] ?? "";
    }
    throw new Error(`Secret "${secretId}" does not contain requested field "#${field}".`);
  }

  /**
   * Resolves all `{{vault:sec_<ulid>[#field]}}` placeholders in a text string.
   */
  async resolveString(template: string): Promise<string> {
    const pattern = /\{\{vault:(sec_[0-9A-HJ-NP-Za-km-z]{26})(?:#([a-zA-Z0-9_-]+))?\}\}/g;
    const matches = Array.from(template.matchAll(pattern));

    if (matches.length === 0) {
      return template;
    }

    let result = template;
    for (const match of matches) {
      const fullPlaceholder = match[0];
      const secId = match[1];
      const field = match[2];

      if (!secId) continue;
      const resolved = await this.resolveSecret(secId, field);
      result = result.split(fullPlaceholder).join(resolved);
    }
    return result;
  }

  /**
   * Resolves environment variable map, expanding any `vault:sec_...` or `{{vault:...}}` values.
   */
  async resolveEnv(
    inputEnv: Record<string, string | undefined>,
  ): Promise<{ resolvedEnv: Record<string, string>; activeSecrets: ActiveSecret[] }> {
    const resolvedEnv: Record<string, string> = {};

    for (const [key, value] of Object.entries(inputEnv)) {
      if (value === undefined) continue;

      // Handle bare handle: "vault:sec_01jk..."
      if (value.startsWith("vault:sec_")) {
        const parts = value.slice("vault:".length).split("#");
        const secId = parts[0]!;
        const field = parts[1];
        resolvedEnv[key] = await this.resolveSecret(secId, field);
      } else if (value.includes("{{vault:")) {
        resolvedEnv[key] = await this.resolveString(value);
      } else {
        resolvedEnv[key] = value;
      }
    }

    return {
      resolvedEnv,
      activeSecrets: [...this.activeSecrets],
    };
  }

  /**
   * Parses a dotenv-style template string into key-value pairs.
   */
  static parseDotenv(content: string): Record<string, string> {
    const env: Record<string, string> = {};
    const lines = content.split(/\r?\n/);

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const eqIdx = trimmed.indexOf("=");
      if (eqIdx === -1) continue;

      const key = trimmed.slice(0, eqIdx).trim();
      let value = trimmed.slice(eqIdx + 1).trim();

      // Strip surrounding quotes
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      env[key] = value;
    }

    return env;
  }

  /**
   * Returns all active revealed secrets tracked by this resolver.
   */
  getActiveSecrets(): ReadonlyArray<ActiveSecret> {
    return this.activeSecrets;
  }

  /**
   * Securely zeroizes all in-memory revealed secret buffers.
   */
  zeroizeAll(): void {
    for (const secret of this.activeSecrets) {
      zeroizeBuffer(secret.valueBytes);
    }
    this.activeSecrets = [];
    this.cache.clear();
  }
}
