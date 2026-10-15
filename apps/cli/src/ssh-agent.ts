import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { generateEntityId } from "@llm-vault/ids";
import {
  SSH_AGENT_MSG,
  computeSshKeyFingerprint,
  decodeSignRequest,
  decodeSshAgentPacket,
  encodeAgentFailure,
  encodeIdentitiesAnswer,
  encodeOpenSshEd25519KeyBlob,
  encodeSignResponse,
  formatOpenSshPublicKey,
  readSshWireString,
  readSshWireUint32,
  signAuditOrKeyPayload,
} from "@llm-vault/crypto";
import type { SshAgentStatus, SshKeyIdentity } from "@llm-vault/schema";

export type ApprovalMode = "auto" | "interactive" | "oob";

export interface SshKeyEntry {
  id: string;
  comment: string;
  publicKeyBytes: Uint8Array;
  privateKey: CryptoKey | Uint8Array;
  fingerprint: string;
  createdAt: string;
  approvalRequired: boolean;
}

export interface SshAgentOptions {
  socketPath?: string | undefined;
  approvalMode?: ApprovalMode | undefined;
  keys?: SshKeyEntry[] | undefined;
  onApprovalRequest?: (request: {
    keyComment: string;
    dataToSign: Uint8Array;
    flags: number;
  }) => Promise<boolean>;
}

export interface SshAgentInstance {
  readonly socketPath: string;
  readonly server: net.Server;
  approvalMode: ApprovalMode;
  addKey(key: SshKeyEntry): void;
  removeKey(idOrFingerprint: string): boolean;
  listKeys(): SshKeyEntry[];
  getStatus(): Promise<SshAgentStatus>;
  stop(): Promise<void>;
}

export function getEffectiveSocketPath(customPath?: string): string {
  if (customPath) {
    if (process.platform === "win32" && !customPath.startsWith("\\\\.\\pipe\\")) {
      const sanitized = customPath.replace(/^[A-Za-z]:/, "").replace(/[\\/]/g, "-");
      return `\\\\.\\pipe\\llm-vault-${sanitized}`;
    }
    return customPath;
  }

  const id = generateEntityId("agt_");
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\llm-vault-ssh-agent-${id}`;
  }
  return path.join(os.tmpdir(), `llm-vault-ssh-agent-${id}.sock`);
}

export async function createSshKeyEntry(params: {
  id?: string | undefined;
  comment: string;
  publicKeyBytes: Uint8Array;
  privateKey: CryptoKey | Uint8Array;
  approvalRequired?: boolean | undefined;
}): Promise<SshKeyEntry> {
  const wireBlob = encodeOpenSshEd25519KeyBlob(params.publicKeyBytes);
  const fingerprint = await computeSshKeyFingerprint(wireBlob);
  return {
    id: params.id ?? generateEntityId("sec_"),
    comment: params.comment,
    publicKeyBytes: params.publicKeyBytes,
    privateKey: params.privateKey,
    fingerprint,
    createdAt: new Date().toISOString(),
    approvalRequired: params.approvalRequired ?? true,
  };
}

export function startSshAgentServer(options: SshAgentOptions = {}): Promise<SshAgentInstance> {
  return new Promise((resolve, reject) => {
    const socketPath = getEffectiveSocketPath(options.socketPath);
    let approvalMode: ApprovalMode = options.approvalMode ?? "interactive";
    const keys: SshKeyEntry[] = [...(options.keys ?? [])];

    // Clean up preexisting socket file on Unix
    if (process.platform !== "win32" && fs.existsSync(socketPath)) {
      try {
        fs.unlinkSync(socketPath);
      } catch {
        // ignore
      }
    }

    const server = net.createServer((socket) => {
      let buffer = Buffer.alloc(0);

      socket.on("data", async (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);

        while (buffer.length >= 4) {
          const packetLen = buffer.readUInt32BE(0);
          const totalPacketLen = 4 + packetLen;
          if (buffer.length < totalPacketLen) {
            break;
          }

          const packetBytes = new Uint8Array(buffer.subarray(0, totalPacketLen));
          buffer = buffer.subarray(totalPacketLen);

          try {
            const { msgType, payload } = decodeSshAgentPacket(packetBytes);

            if (msgType === SSH_AGENT_MSG.SSH2_AGENTC_REQUEST_IDENTITIES) {
              const answer = encodeIdentitiesAnswer(
                keys.map((k) => ({
                  publicKeyBytes: k.publicKeyBytes,
                  comment: k.comment,
                })),
              );
              socket.write(Buffer.from(answer.buffer, answer.byteOffset, answer.byteLength));
            } else if (msgType === SSH_AGENT_MSG.SSH2_AGENTC_SIGN_REQUEST) {
              const { keyBlob, dataToSign, flags } = decodeSignRequest(payload);

              // Find matching key by wire key blob
              const matchedKey = keys.find((k) => {
                const kBlob = encodeOpenSshEd25519KeyBlob(k.publicKeyBytes);
                return Buffer.compare(Buffer.from(kBlob), Buffer.from(keyBlob)) === 0;
              });

              if (!matchedKey) {
                const fail = encodeAgentFailure();
                socket.write(Buffer.from(fail.buffer, fail.byteOffset, fail.byteLength));
                continue;
              }

              // Evaluate approval mode
              let approved = false;
              if (approvalMode === "auto") {
                approved = true;
              } else if (options.onApprovalRequest) {
                try {
                  approved = await options.onApprovalRequest({
                    keyComment: matchedKey.comment,
                    dataToSign,
                    flags,
                  });
                } catch {
                  approved = false;
                }
              } else if (approvalMode === "interactive") {
                // Interactive fallback when no custom handler is provided
                approved = !matchedKey.approvalRequired;
              } else {
                // OOB requires explicit onApprovalRequest
                approved = false;
              }

              if (!approved) {
                const fail = encodeAgentFailure();
                socket.write(Buffer.from(fail.buffer, fail.byteOffset, fail.byteLength));
                continue;
              }

              const signatureBytes = await signAuditOrKeyPayload(matchedKey.privateKey, dataToSign);
              const signResponse = encodeSignResponse(signatureBytes);
              socket.write(
                Buffer.from(signResponse.buffer, signResponse.byteOffset, signResponse.byteLength),
              );
            } else {
              const fail = encodeAgentFailure();
              socket.write(Buffer.from(fail.buffer, fail.byteOffset, fail.byteLength));
            }
          } catch {
            const fail = encodeAgentFailure();
            socket.write(Buffer.from(fail.buffer, fail.byteOffset, fail.byteLength));
          }
        }
      });
    });

    server.on("error", (err) => {
      reject(err);
    });

    server.listen(socketPath, () => {
      // Set socket file permissions to 0600 on POSIX
      if (process.platform !== "win32") {
        try {
          fs.chmodSync(socketPath, 0o600);
        } catch {
          // ignore
        }
      }

      const instance: SshAgentInstance = {
        socketPath,
        server,
        get approvalMode() {
          return approvalMode;
        },
        set approvalMode(mode: ApprovalMode) {
          approvalMode = mode;
        },
        addKey(key: SshKeyEntry): void {
          keys.push(key);
        },
        removeKey(idOrFingerprint: string): boolean {
          const idx = keys.findIndex(
            (k) => k.id === idOrFingerprint || k.fingerprint === idOrFingerprint,
          );
          if (idx >= 0) {
            keys.splice(idx, 1);
            return true;
          }
          return false;
        },
        listKeys(): SshKeyEntry[] {
          return [...keys];
        },
        async getStatus(): Promise<SshAgentStatus> {
          const serializableKeys: SshKeyIdentity[] = keys.map((k) => ({
            id: k.id,
            publicKeyOpenSsh: formatOpenSshPublicKey(k.publicKeyBytes, k.comment),
            comment: k.comment,
            fingerprint: k.fingerprint,
            createdAt: k.createdAt,
            approvalRequired: k.approvalRequired,
          }));

          return {
            running: server.listening,
            socketPath,
            keyCount: keys.length,
            keys: serializableKeys,
            approvalMode,
          };
        },
        stop(): Promise<void> {
          return new Promise((res) => {
            server.close(() => {
              if (process.platform !== "win32" && fs.existsSync(socketPath)) {
                try {
                  fs.unlinkSync(socketPath);
                } catch {
                  // ignore
                }
              }
              res();
            });
          });
        },
      };

      resolve(instance);
    });
  });
}

// ---------------------------------------------------------------------------
// Client helpers for interacting with an SSH agent socket
// ---------------------------------------------------------------------------

export function querySshAgentIdentities(socketPath: string): Promise<
  Array<{
    publicKeyBytes: Uint8Array;
    comment: string;
    wireBlob: Uint8Array;
    openSshPublicKey: string;
    fingerprint: string;
  }>
> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let buffer = Buffer.alloc(0);

    socket.on("error", (err) => {
      reject(err);
    });

    socket.on("connect", () => {
      const packet = Buffer.from([0, 0, 0, 1, SSH_AGENT_MSG.SSH2_AGENTC_REQUEST_IDENTITIES]);
      socket.write(packet);
    });

    socket.on("data", async (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= 4) {
        const packetLen = buffer.readUInt32BE(0);
        if (buffer.length >= 4 + packetLen) {
          const packetBytes = new Uint8Array(buffer.subarray(0, 4 + packetLen));
          socket.end();

          try {
            const { msgType, payload } = decodeSshAgentPacket(packetBytes);
            if (msgType !== SSH_AGENT_MSG.SSH2_AGENT_IDENTITIES_ANSWER) {
              return reject(new Error(`Unexpected SSH agent response message type: ${msgType}`));
            }

            const { value: count, nextOffset: offset0 } = readSshWireUint32(payload, 0);
            const results: Array<{
              publicKeyBytes: Uint8Array;
              comment: string;
              wireBlob: Uint8Array;
              openSshPublicKey: string;
              fingerprint: string;
            }> = [];

            let currOffset = offset0;
            for (let i = 0; i < count; i++) {
              const { value: keyBlob, nextOffset: o1 } = readSshWireString(payload, currOffset);
              const { value: commentBytes, nextOffset: o2 } = readSshWireString(payload, o1);
              currOffset = o2;

              // Read key type and public key from keyBlob
              const { nextOffset: typeOff } = readSshWireString(keyBlob, 0);
              const { value: rawKeyBytes } = readSshWireString(keyBlob, typeOff);
              const comment = new TextDecoder().decode(commentBytes);
              const openSshPublicKey = formatOpenSshPublicKey(rawKeyBytes, comment);
              const fingerprint = await computeSshKeyFingerprint(keyBlob);

              results.push({
                publicKeyBytes: rawKeyBytes,
                comment,
                wireBlob: keyBlob,
                openSshPublicKey,
                fingerprint,
              });
            }

            resolve(results);
          } catch (err) {
            reject(err);
          }
        }
      }
    });
  });
}

export function requestSshAgentSignature(
  socketPath: string,
  keyBlob: Uint8Array,
  dataToSign: Uint8Array,
  flags = 0,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let buffer = Buffer.alloc(0);

    socket.on("error", (err) => {
      reject(err);
    });

    socket.on("connect", () => {
      // Build SSH2_AGENTC_SIGN_REQUEST packet
      const keyBlobWire = Buffer.alloc(4 + keyBlob.length);
      keyBlobWire.writeUInt32BE(keyBlob.length, 0);
      keyBlobWire.set(keyBlob, 4);

      const dataWire = Buffer.alloc(4 + dataToSign.length);
      dataWire.writeUInt32BE(dataToSign.length, 0);
      dataWire.set(dataToSign, 4);

      const flagsBuf = Buffer.alloc(4);
      flagsBuf.writeUInt32BE(flags, 0);

      const body = Buffer.concat([keyBlobWire, dataWire, flagsBuf]);
      const packet = Buffer.alloc(4 + 1 + body.length);
      packet.writeUInt32BE(1 + body.length, 0);
      packet[4] = SSH_AGENT_MSG.SSH2_AGENTC_SIGN_REQUEST;
      body.copy(packet, 5);

      socket.write(packet);
    });

    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= 4) {
        const packetLen = buffer.readUInt32BE(0);
        if (buffer.length >= 4 + packetLen) {
          const packetBytes = new Uint8Array(buffer.subarray(0, 4 + packetLen));
          socket.end();

          try {
            const { msgType, payload } = decodeSshAgentPacket(packetBytes);
            if (msgType === SSH_AGENT_MSG.SSH_AGENT_FAILURE) {
              return reject(new Error("SSH agent returned failure for signing request"));
            }
            if (msgType !== SSH_AGENT_MSG.SSH2_AGENT_SIGN_RESPONSE) {
              return reject(new Error(`Unexpected SSH agent response message type: ${msgType}`));
            }

            // payload is string sigBlob
            // sigBlob is string algo ("ssh-ed25519") + string rawSignature (64 bytes)
            const { value: sigBlob } = readSshWireString(payload, 0);
            const { nextOffset: sigOff } = readSshWireString(sigBlob, 0);
            const { value: rawSignature } = readSshWireString(sigBlob, sigOff);

            resolve(rawSignature);
          } catch (err) {
            reject(err);
          }
        }
      }
    });
  });
}
