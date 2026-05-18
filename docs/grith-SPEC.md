# grith — Core Platform Specification

> This is the architecture spec for the core grith platform. Originally
> drafted February 2026, declassified for the public mirror in May 2026.
> Authoritative for the workspace / crate / supervisor / filter
> structure; version numbers and metric targets may lag the live code
> (check `CHANGELOG.md` and `Cargo.toml` for the current state). For
> end-user documentation see [docs.grith.ai](https://docs.grith.ai/).

---

## 1. What This Project Is

A Rust monorepo producing a single cross-platform binary: the grith daemon. It contains the CLI supervisor (OS-level syscall interception for both built-in agent and external tools), multi-filter security proxy, LLM integration, CLI, embedded web dashboard, and audit system. This is the product.

**Licence:** MPL-2.0 (core). Pro / Enterprise features are gated by license at runtime but ship in the same binary (open-core model — unlicensed users receive `403 FEATURE_GATED` for gated endpoints rather than getting a stripped-down build).

---

## 2. Repository Structure

```
grith/
├── Cargo.toml                    # Workspace root
├── Cargo.lock
├── README.md
├── LICENSE                       # MPL-2.0
├── CONTRIBUTING.md
├── SPEC.md                       # This file
├── PLATFORM.md                   # Platform overview (shared reference)
├── .github/
│   └── workflows/
│       ├── ci.yml                # Build, test, lint, clippy
│       ├── release.yml           # Cross-platform binary builds
│       └── security-audit.yml    # cargo-audit, cargo-deny
├── config/
│   ├── default.toml              # Default configuration
│   ├── filters/
│   │   ├── paths.toml            # Default path matching rules
│   │   ├── secrets.toml          # Secret scanning patterns
│   │   ├── commands.toml         # Command denylist rules
│   ├── supervisor/
│   │   ├── profiles.toml           # Pre-built profiles for Claude Code, Codex, Aider, etc.
│   │   └── syscall_map.toml        # Syscall-to-ToolCallType mapping overrides
│   │   ├── domains.toml          # Domain reputation rules
│   │   └── meta_rules.toml      # Composite meta-rules
│   └── examples/
│       ├── strict.toml           # High-security preset
│       ├── permissive.toml       # Development/low-friction preset
│       └── air-gapped.toml       # No network, local-only preset
├── crates/
│   ├── grith-core/               # Main daemon binary
│   ├── grith-llm/                # LLM integration layer
│   ├── grith-proxy/              # Multi-filter security proxy
│   ├── grith-digest/             # Human review digest system
│   ├── grith-audit/              # Audit logging
│   ├── grith-cli/                # Terminal CLI interface
│   └── grith-server/             # HTTP/WebSocket server for dashboard
│   └── grith-supervisor/           # CLI supervisor (ptrace/seccomp, Endpoint Security, Minifilter)
├── dashboard/                    # React web dashboard (embedded in server)
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── src/
├── wit/                          # Legacy interface definitions (inactive)
├── tests/
│   ├── integration/
│   └── security/                 # Known attack pattern test suites
└── scripts/
    ├── install.sh                # curl | sh installer
    ├── build-release.sh          # Cross-platform release builds
    └── gen-api-types.sh          # Generate TS types from Rust for dashboard
```

---

## 3. Crate Architecture

### 3.1 Dependency Graph

```
grith-core (binary) — the main entry point
├── grith-cli            → terminal REPL and commands
│   └── grith-digest     → digest review in terminal
├── grith-server         → HTTP/WS server for dashboard
│   ├── grith-digest     → digest API endpoints
│   └── grith-audit      → audit API endpoints
├── grith-llm            → LLM provider abstraction
├── grith-supervisor     → CLI supervisor runtime (primary execution path)
│   └── grith-proxy      → security proxy (called on each intercepted syscall)
│       ├── grith-audit  → logs every evaluation
│       └── grith-digest → queues escalated calls
└── grith-audit          → top-level audit access
```

### 3.2 Workspace Configuration

```toml
# Cargo.toml (workspace root)
[workspace]
resolver = "2"
members = [
    "crates/grith-core",
    "crates/grith-llm",
    "crates/grith-proxy",
    "crates/grith-digest",
    "crates/grith-audit",
    "crates/grith-cli",
    "crates/grith-server",
    "crates/grith-supervisor",
    "crates/grith-tests",
]

[workspace.package]
version = "0.1.4"
edition = "2021"
license = "MPL-2.0"
rust-version = "1.88"
repository = "https://github.com/grith-ai/grith"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
axum = { version = "0.7", features = ["ws"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rusqlite = { version = "0.31", features = ["bundled"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
aho-corasick = "1"
regex = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
crossterm = "0.27"
toml = "0.8"
thiserror = "1"
anyhow = "1"
clap = { version = "4", features = ["derive"] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
nix = { version = "0.29", features = ["ptrace", "signal", "process"] }
portable-pty = "0.8"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "fs"] }
```

---

## 4. Crate: grith-core

**Path:** `crates/grith-core/`
**Type:** Binary crate — the main entry point.

### 4.1 Responsibilities

- CLI argument parsing (clap)
- Configuration loading (TOML + env vars + CLI flags)
- Daemon lifecycle: start async runtime, initialise all subsystems, signal handling (SIGTERM/SIGINT)
- Dispatch to CLI REPL or single-shot task execution

### 4.2 Source Files

```
src/
├── main.rs           # Entry point, clap CLI definition
├── daemon.rs         # Tokio runtime setup, subsystem init, shutdown
├── config.rs         # Config loading: CLI > env > project .grith/ > user ~/.config/grith/ > defaults
└── error.rs          # Unified error types (thiserror)
```

### 4.3 CLI Commands

```
grith                         # Start interactive REPL (default)
grith run <task>              # Execute a single task non-interactively
grith init                    # Create default config in ~/.config/grith/
grith config                  # Show current configuration
grith config set <key> <val>  # Set configuration value
grith audit                   # Browse audit logs
grith audit export            # Export audit logs as JSON/CSV
grith log                     # Show recent logs across all sessions
grith log --tail              # Tail logs (all sessions)
grith log --tail --session <name-or-id>  # Tail by session name or UUID
grith digest                  # Show pending digest items
grith digest review           # Interactive digest review
grith proxy test <call>       # Dry-run a tool call against the proxy
grith exec -- <cmd> [args]   # Supervise an external CLI tool
grith exec --profile <name> -- <cmd> [args]   # Supervise with a pre-built profile
grith exec --attach <pid>        # Attach to an already-running process
grith supervisor list             # List active supervised sessions
grith supervisor status <id>      # Show details of a supervised session
grith supervisor kill <id>        # Terminate a supervised session
grith version                 # Version info
```

`grith log` defaults to all sessions when `--session` is omitted. Agent session names are derived from the current working directory basename (for example `grith-website`).

### 4.4 Configuration

Configuration loaded in order of precedence (highest first):
1. CLI flags
2. Environment variables (`GRITH_*`)
3. Project-local `.grith/config.toml`
4. User config `~/.config/grith/config.toml`
5. Built-in defaults

Set `general.audit_sync = false` or `GRITH_AUDIT_SYNC=false` to disable audit uploads and keep audit records local-only. This does not disable license validation traffic — see [`LICENSE-REFRESH.md`](LICENSE-REFRESH.md) for the refresh cadence, grace windows, and air-gapped (no-network) deployment path.

```toml
# ~/.config/grith/config.toml — full reference

[general]
log_level = "info"                    # trace, debug, info, warn, error
audit_dir = "~/.local/share/grith/audit"
audit_sync = true                     # set false to keep audit records local-only

[llm]
default_provider = "ollama"           # ollama, openai, anthropic, openrouter, local

[llm.ollama]
base_url = "http://localhost:11434"
model = "llama3.1:8b"

[llm.openai]
api_key_env = "OPENAI_API_KEY"       # Read from env var, NEVER stored in config
model = "gpt-4o"

[llm.anthropic]
api_key_env = "ANTHROPIC_API_KEY"
model = "claude-sonnet-4-20250514"

[llm.openrouter]
api_key_env = "OPENROUTER_API_KEY"
model = "auto"

[llm.routing]
strategy = "rule"                     # rule | semantic
simple_threshold = 500                # Token count below which use cheap/local
complex_keywords = ["refactor", "architect", "security review"]

[proxy]
auto_allow_threshold = 3.0
auto_deny_threshold = 8.0
cold_start_calls = 200
cold_start_escalation_low = 2.0
cold_start_escalation_high = 10.0
review_timeout_seconds = 300            # auto-deny queued calls after 5 minutes of no review

[digest]
interval_active = "30m"
interval_idle = "24h"
delivery = "cli"                     # cli | web | email
max_queue_size = 100

[server]
enabled = true
host = "127.0.0.1"
port = 3141

[supervisor]
enabled = true
default_profile = "auto"               # auto-detect from command name, or explicit
freeze_timeout_seconds = 300            # auto-deny after 5 minutes of no approval
max_concurrent_sessions = 4
pty_forwarding = true                   # allocate PTY for interactive tools

[supervisor.platform]
linux_mechanism = "ptrace_seccomp"      # ptrace_seccomp | ptrace_only
macos_mechanism = "endpoint_security"   # endpoint_security
seccomp_pre_filter = true               # use seccomp-BPF to filter irrelevant syscalls

[supervisor.noise_reduction]
ignore_read_only_below_project = true   # don't intercept reads under project dir with score < 1.0
batch_rapid_file_reads = true           # batch rapid sequential reads into one proxy evaluation
batch_window_ms = 5                     # batching window
```

---

## 5. Crate: grith-llm

**Path:** `crates/grith-llm/`
**Type:** Library crate.

### 5.1 Source Files

```
src/
├── lib.rs
├── provider.rs       # LlmProvider trait definition
├── ollama.rs         # Ollama provider (ollama-rs crate)
├── openai_compat.rs  # OpenAI-compatible provider (reqwest HTTP)
├── router.rs         # Model routing / selection logic
└── types.rs          # CompletionRequest, CompletionResponse, ToolCall, etc.
```

### 5.2 Provider Trait

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse>;

    async fn complete_stream(
        &self,
        request: &CompletionRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionChunk>> + Send>>>;

    fn capabilities(&self) -> ProviderCapabilities;
    fn cost_estimate(&self, input_tokens: usize, output_tokens: usize) -> CostEstimate;
    fn name(&self) -> &str;
}
```

### 5.3 Core Types

```rust
pub struct CompletionRequest {
    pub messages: Vec<Message>,
    pub tools: Option<Vec<ToolDefinition>>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub system: Option<String>,
}

pub struct Message {
    pub role: Role,          // System, User, Assistant, Tool
    pub content: Content,    // Text, ToolCall, ToolResult, Mixed
}

pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,  // JSON Schema
}

pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

pub struct CompletionResponse {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
    pub model: String,
    pub finish_reason: FinishReason,
}

pub struct CompletionChunk {
    pub delta_content: Option<String>,
    pub delta_tool_calls: Vec<ToolCallDelta>,
    pub finish_reason: Option<FinishReason>,
}
```

### 5.4 Supported Providers

All communicate via the OpenAI-compatible `/v1/chat/completions` API unless noted:

| Provider | Implementation | Notes |
|----------|---------------|-------|
| Ollama | `ollama-rs` crate | Local, zero-cost, primary dev target |
| OpenAI-compatible | `reqwest` to `/v1/chat/completions` | Works for OpenAI, OpenRouter, LM Studio, llama.cpp server, LiteLLM, vLLM |
| Anthropic | `reqwest` to `/v1/messages` | Different API shape — adapter maps to common types |

### 5.5 Router

```rust
pub struct LlmRouter {
    providers: HashMap<String, Box<dyn LlmProvider>>,
    strategy: RoutingStrategy,
}

pub enum RoutingStrategy {
    Fixed { provider: String },
    RuleBased {
        simple_provider: String,
        complex_provider: String,
        simple_threshold: usize,       // Token count
        complex_keywords: Vec<String>,
    },
    Semantic {                          // v1.5
        router_model: String,          // all-MiniLM-L6-v2
        routes: Vec<SemanticRoute>,
    },
}
```

---

## 6. Historical: Removed WASM Runtime

`crates/grith-sandbox` was removed in February 2026 during the supervisor-only migration.

The active architecture no longer supports WASM plugin runtime, plugin installation/verification commands, or `[sandbox]` runtime configuration. All tool execution now flows through the supervisor + proxy path described in Section 7.

---

## 7. Crate: grith-supervisor

**Path:** `crates/grith-supervisor/`
**Type:** Library crate — OS-level CLI tool supervision.

### 7.1 Purpose

grith-supervisor is the primary execution path. It secures both grith's built-in agent (`grith run`) and **any external CLI tool** (`grith exec`) by intercepting syscalls at the OS level and routing them through the security proxy.

```
Path 1 (Built-in Agent): LLM → Tool Calls → grith-supervisor → grith-proxy
Path 2 (External CLI):   CLI Tool → Syscalls → grith-supervisor → grith-proxy
                                                       ↕
                                                 Same scoring engine
                                                 Same filters
                                                 Same audit trail
                                                 Same digest system
```

### 7.2 Source Files

```
src/
├── lib.rs
├── supervisor.rs        # Top-level supervisor orchestration
├── interceptor.rs       # Platform abstraction trait for syscall interception
├── platform/
│   ├── mod.rs           # Platform detection and dispatch
│   ├── linux.rs         # ptrace + seccomp-BPF implementation
│   ├── macos.rs         # Endpoint Security framework implementation
│   └── windows.rs       # Minifilter + ETW implementation (v2.0)
├── syscall_map.rs       # Syscall → ToolCallType conversion layer
├── process_tree.rs      # Process tree tracking (follows forks/exec)
├── pty.rs               # PTY allocation and I/O forwarding
├── freezer.rs           # Process freezing for QUEUE'd operations
└── profiles.rs          # Pre-built profiles for known CLI tools
```

### 7.3 Platform Abstraction Trait

```rust
#[async_trait]
pub trait SyscallInterceptor: Send + Sync {
    /// Spawn a child process under supervision.
    async fn spawn_supervised(
        &mut self,
        command: &str,
        args: &[String],
        env: &HashMap<String, String>,
    ) -> Result<u32>;

    /// Wait for the next intercepted syscall.
    async fn next_event(&mut self) -> Result<SyscallEvent>;

    /// Allow the intercepted syscall to proceed.
    fn allow(&mut self, event: &SyscallEvent) -> Result<()>;

    /// Block the intercepted syscall (return EPERM to the child).
    fn deny(&mut self, event: &SyscallEvent) -> Result<()>;

    /// Freeze the process (for QUEUE'd decisions).
    fn freeze(&mut self, pid: u32) -> Result<()>;

    /// Thaw a previously frozen process.
    fn thaw(&mut self, pid: u32) -> Result<()>;

    /// Detach from the process tree.
    async fn detach(&mut self) -> Result<()>;

    /// Platform name for logging.
    fn platform_name(&self) -> &str;
}
```

### 7.4 Syscall Event Types

```rust
pub struct SyscallEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp: DateTime<Utc>,
    pub syscall: SyscallKind,
    pub raw_number: u64,
}

pub enum SyscallKind {
    FileOpen { path: String, flags: OpenFlags },
    FileWrite { fd: i32, path: Option<String>, len: usize },
    FileRead { fd: i32, path: Option<String>, len: usize },
    FileDelete { path: String },
    FileRename { old: String, new: String },
    FileChmod { path: String, mode: u32 },
    DirCreate { path: String },
    DirList { path: String },
    ProcessExec { command: String, args: Vec<String> },
    ProcessFork { child_pid: u32 },
    NetConnect { address: String, port: u16, protocol: NetProtocol },
    NetBind { address: String, port: u16 },
    NetSendTo { address: String, port: u16, len: usize },
}
```

### 7.5 Syscall to ToolCallType Mapping

The `syscall_map.rs` module converts `SyscallKind` into the existing `ToolCallType` enum from grith-proxy. This is the critical convergence point — both execution paths produce the same type that feeds into the same proxy pipeline:

| SyscallKind | ToolCallType |
|-------------|-------------|
| FileOpen (read) | FileRead |
| FileOpen (write/create) | FileWrite |
| FileOpen (append) | FileAppend |
| FileDelete | FileDelete |
| FileRename | FileRename (new) |
| FileChmod | FileChmod (new) |
| DirCreate | DirCreate (new) |
| DirList | DirList |
| ProcessExec | ProcessSpawn (new) |
| NetConnect | NetConnect (new) |
| NetBind | NetListen (new) |

Syscalls that don't map to security-relevant operations (memory allocation, thread management, time queries) are pre-filtered by seccomp-BPF and never reach the proxy.

### 7.6 New ToolCallType Variants

These variants are added to the existing `ToolCallType` enum in `grith-proxy/src/types.rs` for supervisor-originated calls:

```rust
pub enum ToolCallType {
    // Existing variants (unchanged)
    FileRead { path: String },
    FileWrite { path: String, content_hash: String },
    FileAppend { path: String },
    FileDelete { path: String },
    DirList { path: String },
    ShellExec { command: String, args: Vec<String> },
    HttpRequest { method: String, url: String },

    // New variants for supervisor-originated calls
    FileRename { old_path: String, new_path: String },
    FileChmod { path: String, mode: u32 },
    DirCreate { path: String },
    NetConnect { address: String, port: u16 },
    NetListen { address: String, port: u16 },
    ProcessSpawn { command: String, args: Vec<String> },
}
```

`ProcessSpawn` is distinct from `ShellExec`: `ShellExec` represents a shell command execution request (e.g., from the built-in agent). `ProcessSpawn` comes from a supervised process calling `execve()`.

### 7.7 ToolCallContext Convention

The existing `ToolCallContext.plugin_id` field is reused with a naming convention:
- Built-in agent calls: `plugin_id = "agent:grith"` (the built-in agent)
- Supervisor calls: `plugin_id = "supervisor:<tool-name>"` (e.g., `"supervisor:claude-code"`)

This allows all existing filters, audit queries, and analytics to work without schema changes. Queries can filter by `plugin_id LIKE 'supervisor:%'` to isolate supervisor events.

### 7.8 Supervisor Event Loop

```rust
impl Supervisor {
    pub async fn run(
        &mut self,
        command: &str,
        args: &[String],
        proxy: Arc<SecurityProxy>,
        audit: Arc<Mutex<AuditStorage>>,
        digest: Arc<Mutex<DigestQueue>>,
    ) -> Result<ExitStatus> {
        let pid = self.interceptor.spawn_supervised(command, args, &self.env).await?;

        loop {
            let event = self.interceptor.next_event().await?;
            self.process_tree.handle_event(&event);

            let Some(call_type) = event.to_tool_call_type() else {
                self.interceptor.allow(&event)?;
                continue;
            };

            let ctx = ToolCallContext::new(
                format!("supervisor:{}", self.tool_name),
                call_type,
                self.session_id,
            );

            let decision = proxy.evaluate(&ctx).await;
            audit.lock().unwrap().log(&ctx, &decision)?;

            match decision.action {
                ProxyAction::Allow => self.interceptor.allow(&event)?,
                ProxyAction::Queue { .. } => {
                    self.interceptor.freeze(event.pid)?;
                    digest.lock().unwrap().enqueue(&ctx, &decision)?;
                    self.notify_pending_approval(&ctx, &decision).await;

                    let approved = self.wait_for_approval(&ctx.id).await?;
                    self.interceptor.thaw(event.pid)?;
                    if approved {
                        self.interceptor.allow(&event)?;
                    } else {
                        self.interceptor.deny(&event)?;
                    }
                }
                ProxyAction::Deny { .. } => self.interceptor.deny(&event)?,
            }
        }
    }
}
```

### 7.9 PTY Forwarding

For interactive tools (Claude Code REPL, Codex interactive mode), grith-supervisor allocates a PTY pair using `portable-pty`:

- **Primary PTY:** Connected to the supervised process's stdin/stdout/stderr
- **Secondary PTY:** Connected to the user's terminal

All terminal I/O passes through transparently. Interception happens at the syscall level, not the I/O stream. The user sees the tool's normal output; grith intercepts the actual file/network/process operations underneath. SIGWINCH is propagated for terminal resize handling.

### 7.10 Process Tree Tracking

When a supervised process forks or execs, grith-supervisor tracks the entire process tree:

```rust
pub struct ProcessTree {
    root_pid: u32,
    processes: HashMap<u32, ProcessInfo>,
}

pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub command: String,
    pub state: ProcessState,
}

pub enum ProcessState {
    Running,
    Frozen,
    Exited(i32),
}
```

On Linux, `PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE` automatically traces child processes. On macOS, Endpoint Security provides process lifecycle events natively. When a QUEUE decision freezes a process, all its descendants are frozen too.

### 7.11 Pre-built Profiles

Profiles provide sensible defaults for known CLI tools, reducing noise from routine operations:

```toml
# config/supervisor/profiles.toml

[profiles.claude-code]
display_name = "Claude Code"
routine_paths = ["${PROJECT_DIR}/**", "${HOME}/.claude/**", "/tmp/claude-*/**"]
routine_commands = ["node", "npm", "npx", "cargo", "python", "git", "tsc"]
routine_destinations = ["api.anthropic.com", "statsig.anthropic.com"]

[profiles.codex]
display_name = "OpenAI Codex CLI"
routine_paths = ["${PROJECT_DIR}/**", "${HOME}/.codex/**"]
routine_commands = ["node", "npm", "python", "git"]
routine_destinations = ["api.openai.com"]

[profiles.aider]
display_name = "Aider"
routine_paths = ["${PROJECT_DIR}/**", "${HOME}/.aider/**"]
routine_commands = ["git", "python"]
routine_destinations = ["api.openai.com", "api.anthropic.com"]
```

Profiles translate to allowlist entries in the proxy, giving score reductions for routine operations while maintaining full filter pipeline evaluation for anything outside the profile.

### 7.12 Platform Support Matrix

| Platform | Mechanism | Status | Notes |
|----------|-----------|--------|-------|
| Linux x86-64 | ptrace + seccomp-BPF | v1.5 | Primary implementation |
| Linux ARM64 | ptrace + seccomp-BPF | v1.5 | Same as x86-64, different syscall numbers |
| macOS (Apple Silicon) | Endpoint Security framework | v1.5 | Requires entitlement |
| macOS (Intel) | Endpoint Security framework | v1.5 | Same as Apple Silicon |
| Windows x86-64 | Minifilter + ETW | v2.0 | Requires driver signing |

### 7.13 Resource Constraints

| Resource | Limit | Mechanism |
|----------|-------|-----------|
| Syscall interception overhead | P95 < 50us per syscall | seccomp-BPF pre-filter |
| Memory for process tracking | < 10 MB per process tree | HashMap with bounded history |
| Freeze timeout | 5 minutes (configurable) | Auto-deny after timeout |
| Max concurrent sessions | 4 (configurable) | Tokio semaphore |
| Audit log rate | 100 events per flush | SQLite WAL mode batching |

### 7.14 Failure Mode

If grith-supervisor crashes or is killed, supervised processes **continue running unsupervised** (fail-open). This is the opposite of the proxy's fail-closed policy. Rationale: the supervisor wraps the user's primary tool — killing it would cause data loss. A critical audit event is logged and the user is notified.

---

## 8. Crate: grith-proxy

**Path:** `crates/grith-proxy/`
**Type:** Library crate — the security core.

### 8.1 Source Files

```
src/
├── lib.rs
├── engine.rs         # Proxy pipeline orchestrator
├── scoring.rs        # Score aggregation, thresholds, decision routing
├── meta_rules.rs     # Composite rule evaluation
├── adaptive.rs       # Bayesian auto-learning from digest feedback (v1.5)
├── types.rs          # ToolCallContext, FilterResult, ProxyDecision
└── filters/
    ├── mod.rs              # SecurityFilter trait + filter registry
    ├── path_match.rs       # Filter 1: Static path matching (Aho-Corasick)
    ├── allowlist.rs        # Filter 2: Allowlist/denylist
    ├── capability.rs       # Filter 3: Capability token validation
    ├── argument.rs         # Filter 4: Argument length/structure checks
    ├── secret_scan.rs      # Filter 5: Secret/credential scanning
    ├── command.rs          # Filter 6: Command structure analysis
    ├── reputation.rs       # Filter 7: Outbound destination reputation (v1.5)
    ├── semantic.rs         # Filter 8: Semantic context analysis (v1.5)
    ├── behavioural.rs      # Filter 9: Behavioural profiling (v1.5)
    ├── taint.rs            # Filter 10: Information flow taint tracking (v1.5)
    ├── rate_limit.rs       # Filter 11: Rate limiting / anomaly (v1.5)
    ├── egress_policy.rs    # Filter 12: Destination trust / egress allowlist (v1.6)
    ├── dlp_gate.rs         # Filter 13: Outbound DLP / payload scanning (v1.6)
    ├── canary.rs           # Filter 14: Canary secret detection (v1.6)
    ├── session_containment.rs # Filter 15: Post-read containment tightening (v1.6)
    ├── egress_rate.rs      # Filter 16: Egress rate / burst detection (v1.6)
    ├── operation_risk.rs   # Filter 17: Operation risk scoring (v1.6)
    └── sensitive_path.rs   # Filter 18: Sensitive path heuristic (v1.6)
```

### 8.2 Core Types

```rust
pub struct ToolCallContext {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub plugin_id: String,
    pub call_type: ToolCallType,
    pub arguments: serde_json::Value,
    pub session_id: Uuid,
    pub task_context: Option<String>,
    pub call_sequence_number: u64,
    pub source_taint: TaintLevel,
}

pub enum ToolCallType {
    // Built-in Agent and Supervisor shared variants
    FileRead { path: String },
    FileWrite { path: String, content_hash: String },
    FileAppend { path: String },
    FileDelete { path: String },
    DirList { path: String },
    ShellExec { command: String, args: Vec<String> },
    HttpRequest { method: String, url: String },

    // Supervisor-originated variants (§7.6)
    FileRename { old_path: String, new_path: String },
    FileChmod { path: String, mode: u32 },
    DirCreate { path: String },
    NetConnect { address: String, port: u16 },
    NetListen { address: String, port: u16 },
    ProcessSpawn { command: String, args: Vec<String> },
}

pub struct FilterResult {
    pub matched: bool,
    pub score: f64,
    pub rule_id: String,
    pub severity: Severity,     // Notice, Warning, Error, Critical
    pub message: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

pub struct ProxyDecision {
    pub action: ProxyAction,
    pub composite_score: f64,
    pub filter_results: Vec<FilterResult>,
    pub evaluation_time: Duration,
    pub decision_reason: String,
}

pub enum ProxyAction {
    Allow,
    Queue { priority: QueuePriority },
    Deny { reason: String },
}
```

### 8.3 SecurityFilter Trait

```rust
#[async_trait]
pub trait SecurityFilter: Send + Sync {
    fn name(&self) -> &str;
    fn phase(&self) -> FilterPhase;
    fn can_run_parallel(&self) -> bool { true }
    fn is_ready(&self) -> bool { true }
    async fn evaluate(&self, ctx: &ToolCallContext) -> Result<FilterResult>;
}

pub enum FilterPhase {
    Static,   // Phase 1 (~1ms): pure string ops, zero external deps
    Pattern,  // Phase 2 (~3-5ms): heavier pattern matching, CPU-bound
    Context,  // Phase 3 (~5-10ms): session-state-dependent, may use local LLM
}
```

### 8.4 Filter Implementations — MVP (v1.0)

**Filter 1: Static Path Matching** (`path_match.rs`)
- Aho-Corasick multi-pattern matching against sensitive paths
- Default patterns: `~/.ssh/*`, `~/.gnupg/*`, `~/.aws/*`, `~/.config/gcloud/*`, `*.pem`, `*.key`, `*id_rsa*`, `*id_ed25519*`, `.env`, `.env.*`, `*.tfstate`, `*credentials*`, `*secrets*`
- Score: +2 (config files) to +5 (private keys) — CRITICAL severity for keys

**Filter 2: Allowlist/Denylist** (`allowlist.rs`)
- User-configurable via project `.grith/allow.toml` and `.grith/deny.toml`
- Score: -1 (explicit allow) to +3 (explicit deny)

**Filter 3: Capability Token Validation** (`capability.rs`)
- Verifies the requesting plugin has the capability for this operation type and path
- Binary: valid token = score 0; invalid = immediate DENY (infinite score)

**Filter 4: Argument Length/Structure** (`argument.rs`)
- Detects abnormally long arguments (potential injection payloads)
- Validates structure against expected schemas
- Flags shell commands with suspicious characters: `;`, `|`, `&&`, `` ` ``, `$(`, `>>`
- Score: 0 to +2

**Filter 5: Secret/Credential Scanning** (`secret_scan.rs`)
- 1,600+ regex patterns from `secrets-patterns-db`
- Entropy analysis for high-entropy strings
- Scans tool call arguments AND content being written/sent
- Score: +3 to +5

**Filter 6: Command Structure Analysis** (`command.rs`)
- Parses shell commands into structural representation
- Detects: pipe chains to network tools (`| curl`, `| nc`), encoded payloads (`base64 -d`), history/profile modifications, package installs, cron/systemd changes, privilege escalation (`sudo`, `chmod +s`)
- Score: +2 to +4

### 8.5 Filter Implementations — v1.5

**Filter 7: Outbound Destination Reputation** — cached domain lookup, flags malicious/new/raw-IP destinations. Score: -1 to +4.

**Filter 8: Semantic Context Analysis** — local embedding model assesses contextual appropriateness. Score: -2 to +4.

**Filter 9: Behavioural Profiling** — statistical model of normal patterns, flags deviations. Activates after 200 calls. Score: +1 to +3.

**Filter 10: Taint Tracking** — tags data from untrusted sources, tracks propagation, blocks tainted data reaching sensitive sinks. Score: +3 to +5.

**Filter 11: Rate Limiting / Anomaly** — per-session rate limits on sensitive ops, burst detection. Score: +1 to +3.

### 8.6 Pipeline Execution

```rust
impl SecurityProxy {
    pub async fn evaluate(&self, ctx: &ToolCallContext) -> ProxyDecision {
        let mut results: Vec<FilterResult> = Vec::new();
        let mut score: f64 = 0.0;

        // Phase 1: Static checks (parallel via Tokio tasks)
        let phase1 = self.run_phase(FilterPhase::Static, ctx).await;
        results.extend(phase1);
        score = self.aggregate(&results);
        if score > self.config.auto_deny_threshold { return ProxyDecision::deny(score, results); }

        // Phase 2: Pattern checks (parallel)
        let phase2 = self.run_phase(FilterPhase::Pattern, ctx).await;
        results.extend(phase2);
        score = self.aggregate(&results);
        if score > self.config.auto_deny_threshold { return ProxyDecision::deny(score, results); }

        // Phase 3: Context checks (parallel, only if ready)
        let phase3 = self.run_phase(FilterPhase::Context, ctx).await;
        results.extend(phase3);
        score = self.aggregate(&results);

        // Meta-rules: composite pattern adjustments
        score += self.evaluate_meta_rules(&results, ctx);

        // Route decision
        match score {
            s if s > self.config.auto_deny_threshold => ProxyDecision::deny(s, results),
            s if s > self.config.auto_allow_threshold => ProxyDecision::queue(s, results),
            s => ProxyDecision::allow(s, results),
        }
    }
}
```

### 8.7 Meta-Rules

Composite rules that fire when specific filter combinations match:

```toml
# config/filters/meta_rules.toml

[[meta_rules]]
id = "ssh-key-access"
conditions = [{ filter = "path_match", rule_id = "ssh-private-key", matched = true }]
score_override = 8.0
message = "Direct SSH private key access"

[[meta_rules]]
id = "npm-dependency-resolution"
conditions = [
    { filter = "path_match", rule_id = "package-json", matched = true },
    { call_type = "DirList", path_contains = "node_modules" }
]
score_adjustment = -3.0
message = "Routine NPM dependency resolution"

[[meta_rules]]
id = "env-exfiltration-risk"
conditions = [
    { filter = "taint", taint_source = "env-file" },
    { call_type = "HttpRequest" }
]
score_adjustment = +5.0
message = "Potential credential exfiltration after .env read"
```

### 8.8 Declarative Rule Language

Simple filters expressed in TOML, lowering the contribution barrier:

```toml
[rules.sensitive-ssh-key]
type = "path_match"
pattern = "~/.ssh/id_*"
operations = ["read", "write", "delete"]
score = 5.0
severity = "critical"
message = "Access to SSH private key"
```

Scores are defined separately from detection logic — per-deployment tuning without code changes.

### 8.9 Exfiltration Containment Model (v1.6)

The v1.6 hardening track adds layered controls so sensitive data remains contained even if a local read succeeds:

- **Protocol-aware egress detection:** classify and score outbound behavior across HTTP(S), DNS, FTP/SFTP, SMTP, websocket, and shell transport wrappers.
- **Sink-side DLP gate:** scan outbound payloads before release and apply policy (`redact_and_allow`, `queue`, `deny`).
- **Session containment state:** after high-risk reads, temporarily tighten network/process thresholds until risk decays or operator approval is granted.
- **Destination trust policy:** allowlist/denylist/trust tiers by domain, suffix, IP, and CIDR.
- **Canary secret denial:** immediately deny and raise an incident if honey credentials appear in outbound payloads.
- **Correlated evidence:** attach stable source-to-sink correlation IDs in audit rows and exports for incident forensics.

---

## 9. Crate: grith-digest

**Path:** `crates/grith-digest/`
**Type:** Library crate.

### 9.1 Source Files

```
src/
├── lib.rs
├── queue.rs          # SQLite-backed digest queue
├── delivery.rs       # Delivery channels (CLI, web, email)
├── actions.rs        # Approve, deny, approve-and-learn, escalate
└── scheduler.rs      # Configurable digest intervals
```

### 9.2 Queue Schema (SQLite)

```sql
CREATE TABLE digest_queue (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    tool_call_context TEXT NOT NULL,     -- JSON blob
    composite_score REAL NOT NULL,
    filter_breakdown TEXT NOT NULL,      -- JSON array of FilterResult
    task_context TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, denied, expired, escalated
    reviewed_at TEXT,
    review_action TEXT,                  -- approve, deny, approve_and_learn, escalate
    reviewer_notes TEXT,
    escalated_at TEXT,
    escalated_by TEXT
);

CREATE INDEX idx_digest_status ON digest_queue(status);
CREATE INDEX idx_digest_created ON digest_queue(created_at);
```

### 9.3 Digest Item Display

Each queued item shows:
1. Timestamp and tool call type
2. What the agent was trying to do (human-readable summary)
3. Arguments (file paths, commands, URLs)
4. Composite score with visual bar (green/amber/red)
5. Filter breakdown — which filters fired and individual scores
6. Task context — what the agent was working on
7. Actions: **Approve** | **Deny** | **Approve & Learn** (trains adaptive classifier) | **Escalate** (marks for senior review, Pro/Enterprise tier)

### 9.4 Blocking on Queued Calls

Both execution paths (built-in agent and CLI supervisor) **block** when a tool call is queued for review. The agent loop pauses and polls the digest queue every 250ms until the user approves, denies, or the `review_timeout_seconds` (default: 300s) expires. On timeout, the call is auto-denied and the LLM receives a denial message.

**Status lifecycle:** `Pending → Approved|Denied` or `Pending → Escalated → Approved|Denied`. Escalation is an intermediate status — the blocking poll continues waiting while the item is escalated, since escalation is not a resolution. The item must still be approved or denied by a senior reviewer.

This unified blocking model ensures the agent never proceeds with stale or incorrect assumptions. The user approves or denies via the web dashboard or `grith digest review`.

### 9.5 Malicious Call Exclusion

Calls scoring above auto-deny appear in the digest as **informational items only** — visible for audit but not actionable. This prevents social engineering attacks tricking users into approving dangerous operations.

---

## 10. Crate: grith-audit

**Path:** `crates/grith-audit/`
**Type:** Library crate.

### 10.1 Source Files

```
src/
├── lib.rs
├── logger.rs         # Structured JSON audit log writer
├── storage.rs        # SQLite audit storage + rotation
└── query.rs          # Audit log querying / filtering
```

### 10.2 Audit Record

```rust
pub struct AuditRecord {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub session_id: Uuid,
    pub plugin_id: String,
    pub tool_call_type: String,
    pub arguments_summary: String,
    pub arguments_hash: String,         // SHA-256 for integrity
    pub composite_score: f64,
    pub proxy_action: String,           // allow, queue, deny
    pub filter_results: Vec<FilterResultSummary>,
    pub execution_result: Option<String>,
    pub evaluation_time_ms: f64,
    pub task_context: Option<String>,
}
```

### 10.3 Storage

SQLite at `~/.local/share/grith/audit/audit.db`. ~1 MB per 10K tool calls. Auto-rotation after 100 MB (configurable), keeping last 5 rotations.

### 10.4 Query Interface

```rust
pub struct AuditQuery {
    pub session_id: Option<Uuid>,
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub min_score: Option<f64>,
    pub action_filter: Option<Vec<String>>,
    pub plugin_filter: Option<Vec<String>>,
    pub call_type_filter: Option<Vec<String>>,
    pub limit: usize,
    pub offset: usize,
}
```

---

## 11. Crate: grith-cli

**Path:** `crates/grith-cli/`
**Type:** Library crate.

### 11.1 Source Files

```
src/
├── lib.rs
├── repl.rs           # Interactive REPL loop
├── render.rs         # Streaming output, syntax highlighting (crossterm)
├── diff.rs           # Inline diff display for file modifications
├── digest_ui.rs      # Terminal digest review interface
└── commands.rs       # In-REPL commands (/help, /digest, /audit, etc.)
```

### 11.2 REPL Example

```
$ grith
grith v0.1.4 | model: ollama/llama3.1:8b | proxy: active (6 filters)
Type /help for commands, /quit to exit

> Fix the type error in src/main.rs

[agent] Reading src/main.rs...                    ✓ score: 0.2
[agent] Analysing type annotations...
[agent] Writing fix to src/main.rs...             ✓ score: 1.4
[agent] Running cargo check...                    ✓ score: 0.8

✓ Fixed: Changed `String` to `&str` on line 42.

> /digest
┌─ Pending Review (2 items) ───────────────────────────────┐
│ 1. [5.2] ShellExec: curl https://api.example.com/...     │
│ 2. [4.1] FileRead: ~/.config/some-tool/config.json       │
│                                                           │
│ [a]pprove  [d]eny  [l]earn  [s]kip  [q]uit               │
└───────────────────────────────────────────────────────────┘
```

### 11.3 In-REPL Commands

```
/help              Show available commands
/quit              Exit grith
/digest            Review pending digest items
/audit [n]         Show last n audit entries
/config            Show current configuration
/model <name>      Switch LLM model
/proxy status      Show proxy filter status
/proxy test <cmd>  Dry-run a tool call through the proxy
/clear             Clear screen
/context           Show current task context
```

---

## 12. Crate: grith-server

**Path:** `crates/grith-server/`
**Type:** Library crate.

### 12.1 Source Files

```
src/
├── lib.rs
├── routes.rs         # Axum REST API routes
├── websocket.rs      # WebSocket handlers for live updates
├── auth.rs           # API key / session auth (Pro/Enterprise)
└── static_files.rs   # Serve embedded dashboard assets
```

### 12.2 REST API

```
GET    /api/health                    # Health check
GET    /api/config                    # Current configuration
PUT    /api/config                    # Update configuration

GET    /api/digest                    # List pending digest items
POST   /api/digest/:id/approve       # Approve a queued item
POST   /api/digest/:id/deny          # Deny a queued item
POST   /api/digest/:id/learn         # Approve and train classifier

GET    /api/audit                     # Query audit logs (with filters)
GET    /api/audit/export              # Export as JSON/CSV
GET    /api/audit/:id                 # Single audit record detail

GET    /api/proxy/status              # Proxy status and filter list
POST   /api/proxy/test               # Dry-run a tool call

POST   /api/events                    # Ingest events from CLI agent loop (forwarded to WebSocket)
POST   /api/server/shutdown           # Gracefully shut down the dashboard server

WS     /ws/live                       # Real-time tool call monitoring

GET    /api/supervisor/sessions          # List active supervised sessions
GET    /api/supervisor/sessions/:id      # Session details (process tree, stats)
POST   /api/supervisor/sessions/:id/kill # Terminate a supervised session
WS     /ws/supervisor/:id               # Real-time syscall feed for a supervised session
```

### 12.3 Background Dashboard Process

The dashboard server runs as a **separate background process** that persists between CLI invocations. This allows the dashboard to remain open and show live data across multiple `grith run` sessions.

**Lifecycle:**
- `grith dashboard start` — starts the server in the foreground (used by auto-start to spawn as a detached child process)
- `grith dashboard stop` — sends HTTP shutdown request to the running server, falls back to SIGTERM
- `grith dashboard status` — checks if the server is running, displays URL and PID

**Auto-start:** When `grith run` or `grith` (REPL) is invoked and `server.enabled = true`, the CLI checks if a dashboard process is already running (via PID file). If not, it spawns `grith dashboard start` as a detached background process.

**PID file:** Stored at `~/.config/grith/dashboard.pid`, contains the process PID and port number. The PID file is validated on read by checking if the process is still alive (`kill(pid, 0)` on Unix).

**Event forwarding:** When the dashboard runs as a separate process, the CLI agent loop forwards proxy evaluation events to `POST /api/events` via HTTP. In-process mode uses the WebSocket broadcast channel directly.

**Dashboard UI:** The sidebar footer includes a "Stop Dashboard" button that calls `POST /api/server/shutdown`.

**Fallback:** If the background process cannot be started (e.g., binary not found), the server starts in-process as part of the CLI process (legacy mode).

---

## 13. Dashboard (Embedded React App)

**Path:** `dashboard/`
**Build:** Vite + React + TypeScript + Tailwind CSS
**Served by:** `grith-server` on `localhost:3141` (as a background process or in-process fallback)

### 13.1 Structure

```
dashboard/
├── package.json
├── tsconfig.json
├── vite.config.ts
└── src/
    ├── App.tsx
    ├── main.tsx
    ├── components/
    │   ├── DigestViewer.tsx         # Quarantine digest review UI
    │   ├── FilterConfig.tsx         # Filter configuration editor
    │   ├── AuditBrowser.tsx         # Searchable audit log with score drilldown
    │   ├── ScoreBreakdown.tsx       # Visual per-call score breakdown
    │   ├── LiveMonitor.tsx          # Real-time tool call feed (WebSocket)
    │   ├── PolicyEditor.tsx         # Team policy management (Pro)
    │   └── UsageAnalytics.tsx       # Usage charts (Pro)
    ├── hooks/
    │   ├── useWebSocket.ts
    │   └── useDigest.ts
    ├── types/
    │   └── api.ts                   # Mirrors Rust types — generated via scripts/gen-api-types.sh
    └── lib/
        └── api.ts                   # REST API client
```

### 13.2 Design System

Uses the shared brand from `PLATFORM.md` §11: dark theme, Outfit font, forge orange accents, minimal border radius.

---

## 14. Supervisor Profiles

`grith-supervisor` ships pre-built profiles for common external tools and a generic fallback profile.

**Path:** `config/supervisor/profiles.toml`

Each profile contributes baseline allowlist hints and expected command/destination patterns while all intercepted operations still pass through the full security proxy pipeline.

---

## 15. Test Suites

### 15.1 Structure

```
tests/
├── integration/
│   ├── proxy_pipeline_test.rs      # Full proxy pipeline evaluation
│   ├── digest_test.rs              # Queue, review, learn cycle
│   └── end_to_end_test.rs          # User prompt → LLM → proxy → execution → result
│   ├── supervisor_test.rs            # Syscall interception, proxy routing, freeze/thaw
└── security/
    ├── prompt_injection_suite.rs   # Known prompt injection patterns
    ├── exfiltration_suite.rs       # Data exfiltration attempts
    └── supply_chain_suite.rs       # Malicious dependency/repo patterns
    └── supervisor_escape_suite.rs    # Attempts to bypass syscall interception
```

### 15.2 Coverage Targets

| Layer | Tool | Target |
|-------|------|--------|
| Unit (Rust) | `cargo test` | All filter logic, scoring, routing |
| Integration | `tests/integration/` | Proxy pipeline, supervisor lifecycle, digest flow |
| Security | `tests/security/` | Known attack patterns must be caught |
| Dashboard | Vitest | Component rendering, state management |

---

## 16. Platform Support

| Platform | Status | Supervisor Mechanism | Notes |
|----------|--------|---------------------|-------|
| macOS (Apple Silicon) | Primary | Endpoint Security framework | ARM64, macOS 13+ |
| macOS (Intel) | Primary | Endpoint Security framework | x86-64, macOS 13+ |
| Linux (x86-64) | Primary | ptrace + seccomp-BPF | Ubuntu 22.04+, Fedora 38+, Debian 12+ |
| Linux (ARM64) | Supported | ptrace + seccomp-BPF | RPi 4+, Graviton, Ampere |
| Windows (x86-64) | Primary | Minifilter + ETW (v2.0) | Windows 10 21H2+, WSL2 also supported |

Distribution: single static binary per platform. Install via `curl | sh`, Homebrew, Scoop/WinGet, `cargo install`, direct download.

---

## 17. Technical Success Metrics (v1.0)

| Metric | Target |
|--------|--------|
| Proxy latency | P95 < 15ms per tool call |
| False positive rate | < 5% of legitimate calls escalated (after 200-call warm-up) |
| False negative rate | < 0.1% of known-dangerous patterns reach auto-allow |
| Memory footprint | < 150 MB RSS (daemon + proxy, no active plugins) |
| Plugin cold start | < 500ms first compilation; < 1ms cached |
| LLM passthrough | < 5ms added latency |
| Audit completeness | 100% of tool calls logged |
| Supervisor interception overhead | P95 < 50us per intercepted syscall |
| Supervisor wall-clock impact | < 5% slowdown for typical dev workflows |
| Supervisor memory overhead | < 10 MB per supervised process tree |
| Freeze-to-notification latency | < 100ms from QUEUE decision to user notification |

---

## 18. Key Dependencies

| Dependency | Version | License | Purpose |
|-----------|---------|---------|---------|
| Wasmtime | Latest stable | Apache 2.0 | No longer required (was WASM runtime) |
| Extism | Latest stable | BSD-3 | No longer required (was plugin lifecycle) |
| Tokio | 1.x | MIT | Async runtime |
| Axum | 0.7+ | MIT | HTTP server |
| rusqlite | 0.31+ | MIT | SQLite bindings |
| reqwest | 0.12+ | MIT/Apache 2.0 | HTTP client for LLM APIs |
| serde / serde_json | 1.x | MIT/Apache 2.0 | Serialisation |
| aho-corasick | 1.x | MIT/Unlicense | Multi-pattern string matching |
| regex | 1.x | MIT/Apache 2.0 | Secret scanning |
| crossterm | 0.27+ | MIT | Terminal rendering |
| tracing | 0.1+ | MIT | Structured logging |
| clap | 4.x | MIT/Apache 2.0 | CLI parsing |
| nix | 0.29+ | MIT | Linux ptrace/seccomp/signal operations |
| portable-pty | 0.8+ | MIT | Cross-platform PTY allocation |
| seccompiler | 0.4+ | Apache 2.0 | seccomp-BPF filter compilation (Linux) |

---

## 19. Development Quick Start

```bash
# Prerequisites: Rust stable, Node.js 20+
git clone https://github.com/grith-ai/grith.git && cd grith

cargo build                          # Build all crates
cargo test --workspace               # Run all tests
cargo clippy --workspace -- -D warnings  # Lint

cd dashboard && npm install && npm run build && cd ..  # Build dashboard

cargo run -- --config config/default.toml  # Run daemon (dev mode)
cargo run -- run "list files in current directory"  # Single task

# Test individual crates
cargo test -p grith-proxy
cargo test -p grith-supervisor
```

---

## 20. Roadmap

### v1.0 (MVP) — 3–4 months
Core daemon, security proxy, Phase 1–2 filters (6 filters), CLI REPL, Ollama + cloud LLM support, audit logging.

### v1.5 — 2–3 months after v1.0
Phase 3 filters (5 more, 11 total), adaptive scoring, CLI supervisor mode (`grith exec` with ptrace/Endpoint Security for Linux/macOS), web dashboard, pre-built profiles for Claude Code/Codex/Aider, Pro tier team features.

### v1.6 — complete
Exfiltration containment and egress hardening (7 new filters, 19 total including profile allowlist): protocol-aware outbound controls, argument-level DLP/redaction, containment mode after sensitive reads, destination trust policies, canary secret denial, correlated source-to-sink incident evidence.

### v2.0 — 6–9 months after v1.0
Enterprise (SSO, RBAC, compliance, SIEM), Windows supervisor support (Minifilter + ETW), voice pipeline, messaging bridges, managed cloud, standalone scoring API.
