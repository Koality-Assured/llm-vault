# @llm-vault/cli

Developer CLI binary for `llm-vault`: zero-knowledge secret management, in-memory child process environment variable injection, and zero-file template rendering.

## Key Capabilities

1. **Zero-File Process Injection (`llm-vault run`)**:
   - Injects decrypted secrets directly into child process memory (`process.env`) without writing plaintext `.env` files to disk.
   - Resolves `{{vault:sec_<ulid>}}` and `{{vault:sec_<ulid>#field}}` placeholders.
   - Supports `--env-file .env.vault` / `.env.tpl` templates.

2. **In-Memory Ephemeral FIFOs (`llm-vault inject`)**:
   - Renders path-based configuration files into ephemeral in-memory FIFOs (`\\.\pipe\llm-vault-fifo-...` on Windows, POSIX FIFOs on Linux/macOS) directly in memory.
   - The child process reads configuration normally via standard filesystem APIs, while zero bytes of plaintext secrets ever touch permanent disk storage.

3. **Real-Time Stream Scrubber**:
   - Monitors child `stdout` and `stderr` streams in real time.
   - Redacts raw secrets, Base64 variants (standard, unpadded, URL-safe), and URL-encoded strings with `[REDACTED:sec_<ulid>]`.
   - Employs a sliding-window overlap buffer to intercept secrets split across streaming chunk boundaries.

4. **Secure Local Session Cache**:
   - Stores authenticated session metadata with strict `0600` file permissions (and `0700` directory permissions) in `~/.llm-vault/session.json`.

## Usage

```bash
# Login and store session credentials
llm-vault login --endpoint http://localhost:3000 --token <jwt_or_agent_token> --tenant tnt_default --actor usr_admin

# Check active session
llm-vault status

# Run child process with environment variable injection and live output redacting
llm-vault run --env-file .env.vault -- npm start

# Inject configuration template via ephemeral in-memory pipe
llm-vault inject --template config.json.tpl -- node server.js --config {{FIFO_PATH}}

# Clear session
llm-vault logout
```
