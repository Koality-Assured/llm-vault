import * as net from "node:net";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { generateEntityId } from "@llm-vault/ids";
import { zeroizeBuffer } from "@llm-vault/crypto";

const execFileAsync = promisify(execFile);

export interface MemoryFifo {
  /**
   * File system path (or Windows named pipe path) to the ephemeral FIFO.
   */
  path: string;
  /**
   * Closes the FIFO server, releases OS resources, and zeroizes memory buffers.
   */
  close: () => Promise<void>;
}

/**
 * Creates an ephemeral, in-memory FIFO (Named Pipe on Windows, POSIX FIFO on Linux/macOS)
 * to serve configuration templates directly to a child process without ever writing
 * unencrypted plaintext secrets to disk.
 */
export async function createMemoryFifo(
  content: string | Uint8Array,
  options?: { pipeId?: string },
): Promise<MemoryFifo> {
  const isWindows = process.platform === "win32";
  const id = options?.pipeId ?? generateEntityId("fld_");
  const contentBytes =
    typeof content === "string" ? new TextEncoder().encode(content) : new Uint8Array(content);

  if (isWindows) {
    // Windows Named Pipe: \\.\pipe\llm-vault-fifo-<id>
    const pipePath = `\\\\.\\pipe\\llm-vault-fifo-${id}`;
    let isClosed = false;

    const server = net.createServer((socket) => {
      socket.write(Buffer.from(contentBytes), () => {
        socket.end();
      });
      socket.on("error", () => {
        // Reader may close early; ignore socket errors
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.listen(pipePath, () => resolve());
      server.on("error", (err) => reject(err));
    });

    const close = async () => {
      if (isClosed) return;
      isClosed = true;
      zeroizeBuffer(contentBytes);
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    };

    return {
      path: pipePath,
      close,
    };
  }

  // POSIX FIFO (Linux / macOS): mkfifo in a private 0700 temp directory
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "llm-vault-fifo-"));
  await fs.promises.chmod(tempDir, 0o700);
  const fifoPath = path.join(tempDir, `fifo-${id}`);

  // Create OS FIFO node
  await execFileAsync("mkfifo", [fifoPath]);
  await fs.promises.chmod(fifoPath, 0o600);

  let isClosed = false;
  let writeStream: fs.WriteStream | null = null;

  // Stream data into FIFO in background when reader opens it
  const backgroundFeed = () => {
    try {
      writeStream = fs.createWriteStream(fifoPath);
      writeStream.write(Buffer.from(contentBytes), () => {
        writeStream?.end();
      });
      writeStream.on("error", () => {
        // Reader closed early; handle gracefully
      });
    } catch {
      // Ignore if FIFO was closed before reader opened
    }
  };
  setImmediate(backgroundFeed);

  const close = async () => {
    if (isClosed) return;
    isClosed = true;
    zeroizeBuffer(contentBytes);
    try {
      if (writeStream) {
        writeStream.destroy();
      }
      if (fs.existsSync(fifoPath)) {
        await fs.promises.unlink(fifoPath);
      }
      if (fs.existsSync(tempDir)) {
        await fs.promises.rm(tempDir, { recursive: true, force: true });
      }
    } catch {
      // Best effort cleanup
    }
  };

  return {
    path: fifoPath,
    close,
  };
}
