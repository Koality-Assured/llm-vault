export interface ActiveSecret {
  id: string;
  value: string;
  valueBytes: Uint8Array;
}

interface ReplacementRule {
  needle: string;
  replacement: string;
}

const textDecoder = new TextDecoder();

function stripBase64Padding(value: string): string {
  return value.replace(/=+$/, "");
}

/**
 * Builds candidate encoded variants for a secret string to ensure leakage
 * via stdout/stderr in raw, Base64, or URL-encoded forms is intercepted.
 */
export function buildSecretVariants(valueBytes: Uint8Array): string[] {
  if (valueBytes.byteLength === 0) {
    return [];
  }

  const variants = new Set<string>();
  const utf8 = textDecoder.decode(valueBytes);
  if (utf8.length > 0) {
    variants.add(utf8);
    const trimmed = utf8.trim();
    if (trimmed.length >= 4) {
      variants.add(trimmed);
    }
    const urlEncoded = encodeURIComponent(utf8);
    if (urlEncoded.length > 0) {
      variants.add(urlEncoded);
    }
  }

  const buf = Buffer.from(valueBytes);
  const stdBase64 = buf.toString("base64");
  if (stdBase64.length >= 4) {
    variants.add(stdBase64);
    const unpaddedStd = stripBase64Padding(stdBase64);
    if (unpaddedStd.length >= 4) {
      variants.add(unpaddedStd);
    }
  }

  const urlBase64 = buf.toString("base64url");
  if (urlBase64.length >= 4) {
    variants.add(urlBase64);
  }

  return Array.from(variants);
}

/**
 * Redacts all occurrences of active secrets in text across raw, Base64, and URL encodings.
 */
export function scrubSecretsFromText(
  text: string,
  activeSecrets: ReadonlyArray<ActiveSecret>,
): string {
  if (!text || activeSecrets.length === 0) {
    return text;
  }

  const rules: ReplacementRule[] = [];
  for (const secret of activeSecrets) {
    if (secret.valueBytes.byteLength === 0) {
      continue;
    }
    const replacement = `[REDACTED:${secret.id}]`;
    for (const needle of buildSecretVariants(secret.valueBytes)) {
      rules.push({ needle, replacement });
    }
  }

  if (rules.length === 0) {
    return text;
  }

  // Sort longest needle first so partial variants do not shadow full tokens
  rules.sort((a, b) => b.needle.length - a.needle.length);

  let scrubbed = text;
  for (const rule of rules) {
    if (scrubbed.includes(rule.needle)) {
      scrubbed = scrubbed.split(rule.needle).join(rule.replacement);
    }
  }
  return scrubbed;
}

export interface StreamScrubber {
  write(data: string | Buffer): void;
  flush(): void;
}

/**
 * Creates a streaming output scrubber that wraps stdout/stderr chunks and
 * buffers a sliding window so secrets spanning across chunk boundaries are redacted.
 */
export function createStreamScrubber(
  activeSecrets: ReadonlyArray<ActiveSecret>,
  onChunk: (scrubbedText: string) => void,
): StreamScrubber {
  if (activeSecrets.length === 0) {
    return {
      write(data) {
        onChunk(typeof data === "string" ? data : data.toString("utf-8"));
      },
      flush() {},
    };
  }

  // Calculate maximum needle length across all variants to determine sliding window size
  let maxNeedleLength = 0;
  for (const secret of activeSecrets) {
    for (const variant of buildSecretVariants(secret.valueBytes)) {
      if (variant.length > maxNeedleLength) {
        maxNeedleLength = variant.length;
      }
    }
  }

  const overlapWindow = Math.max(maxNeedleLength, 16);
  let carryBuffer = "";

  return {
    write(data: string | Buffer) {
      const incoming = typeof data === "string" ? data : data.toString("utf-8");
      // Scrub the combined buffer so any secret fully formed across boundaries is redacted immediately
      const scrubbedCombined = scrubSecretsFromText(carryBuffer + incoming, activeSecrets);

      if (scrubbedCombined.length <= overlapWindow) {
        carryBuffer = scrubbedCombined;
        return;
      }

      // Safe region to emit: everything up to length - overlapWindow
      const safeLength = scrubbedCombined.length - overlapWindow;
      const toEmit = scrubbedCombined.slice(0, safeLength);
      carryBuffer = scrubbedCombined.slice(safeLength);

      onChunk(toEmit);
    },

    flush() {
      if (carryBuffer.length > 0) {
        const scrubbed = scrubSecretsFromText(carryBuffer, activeSecrets);
        carryBuffer = "";
        onChunk(scrubbed);
      }
    },
  };
}
