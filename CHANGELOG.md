# Changelog

All notable changes to the grith project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Conventional Commits](https://www.conventionalcommits.org/) and
will adopt [Semantic Versioning](https://semver.org/) starting at 1.0.0.

## [Unreleased]

## [0.1.2] - 2026-05-14

### Fixed

- `grith exec` now forwards mouse wheel and click events from the host
  terminal to the supervised tool's PTY, so Claude Code, Codex, and other
  mouse-aware tools can scroll their own content windows. Previously the
  host terminal translated wheel events into arrow keys (the default
  behaviour in alternate-screen mode), which Claude Code rejected with
  "Scroll wheel is sending arrow keys · use PgUp/PgDn to scroll". The
  exec TUI now enables mouse capture and re-encodes crossterm
  `MouseEvent`s using the SGR / UTF-8 / X10 protocol the inner tool
  requested (detected via vt100's `mouse_protocol_mode`). When the inner
  tool hasn't requested mouse, wheel events fall back to local vterm
  scrollback so the wheel still does something useful.

### Added

- New `grith-docgen` workspace crate (`crates/grith-docgen`). Build-time
  tool that emits structured JSON describing the grith product surface
  (`config.json`, `filters.json`, `cli.json`, `api.json`) for the public
  documentation site `grith-docs` to consume. Excluded from
  `default-members` so `cargo build --workspace` doesn't pay its build
  cost; invoke via `cargo run -p grith-docgen` to regenerate the doc
  data.

## [0.1.1] - 2026-05-14

### Fixed

- `grith init` and the daemon's base-config load both bake
  `config/default.toml` (and the rest of the `config/` tree) into the
  binary via `include_dir`. v0.1.0 only looked for these files at
  cwd-relative or build-time paths, so users installing via the curl
  one-liner hit `required config/default.toml unavailable:
  /project/crates/grith-core/../../config/default.toml does not
  exist`. The embedded copy is the final fallback after the existing
  disk-based lookup so source checkouts still pick up local edits.

## [0.1.0] - 2026-05-07

First public OSS release.

**Platform scope:** Linux x86_64 only. The supervisor uses ptrace+seccomp
which is Linux-specific, and the syscall-arg extraction hard-codes
x86_64 register names. macOS (via Endpoint Security), Windows (via ETW),
and Linux aarch64 are all tracked for v2.0; the installer prints a
clear message + workaround pointer on those platforms.

The full binary ships publicly with Pro/Enterprise features returning
`403 FEATURE_GATED` for unlicensed users (open-core model).

### Added
- Feature gate enforcement with upgrade metadata (C-01)
- Config sync endpoints for multi-device settings (C-02)
- Cost, activity, and compliance analytics APIs (C-03)
- Provider key encryption at rest with AES-256-GCM (C-04)
- 1,620 secret scanning patterns for API keys, tokens, and credentials (C-06)
- Forensic syscall tracing tests for post-incident reconstruction (Phase 47)
- Agent E2E tests with mock LLM harness (section 11.5)
- Adaptive scoring stats API (`GET /api/adaptive/stats`) and feedback endpoint (`POST /api/adaptive/feedback`)
- Adaptive scoring dashboard panel on the Settings page (Pro feature)
- Scheduler idle mode with activity-based active/idle transitions
- Connection pooling and WAL mode for the digest queue (concurrent readers)
- Per-filter score persistence in audit records
- Filter scores included in CSV export and cloud sync payloads

### Changed
- `DigestQueue` is now internally thread-safe (`Arc<DigestQueue>` replaces `Arc<Mutex<DigestQueue>>`)
- `DigestScheduler` tracks activity and switches between active/idle delivery intervals

### Fixed
- Clippy `match_result_ok` lint in scheduler queue overflow check

## [0.1.0-pre] - 2026-02-24

Initial pre-release encompassing phases 1–16 plus production hardening.

### Core Platform (Phases 1–8)
- Single cross-platform Rust binary: daemon, proxy, audit, CLI, and LLM integration
- Multi-phase security proxy with 17 filters across 3 phases (static, pattern, context)
- Additive scoring engine with configurable allow/queue/deny thresholds
- Cold-start threshold widening for the first 200 evaluations
- Meta-rule engine for composite filter adjustments
- Secret scanning with 1,620+ regex patterns for API keys, tokens, and credentials
- SQLite audit logging with 100% tool call coverage
- Tamper-evident hash chains on audit records
- Quarantine digest system with terminal and web delivery
- LLM provider abstraction: Ollama, OpenAI, Anthropic, OpenRouter
- Interactive CLI REPL with streaming output
- Configuration precedence: CLI flags > env vars > project config > user config > defaults

### Web Dashboard (Phase 13)
- React + Vite + TypeScript + Tailwind CSS dashboard served on `localhost:3141`
- Live monitoring via WebSocket events
- Audit log viewer with filtering and export (JSON, CSV)
- Digest queue management with approve/deny/escalate actions
- Proxy status and filter configuration panels
- Notification channel management
- Background process management (`grith dashboard start/stop/status`)

### Advanced Filters & Adaptive Scoring (Phase 14)
- Reputation scoring, semantic analysis, behavioural profiling
- Taint tracking across file/network/process tool calls
- Per-session and global rate limiting
- Adaptive Bayesian scoring engine that learns from digest review feedback
- Bounded ±2.0 score adjustments with configurable learning rate and confidence threshold

### CLI Supervisor (Phase 15)
- `grith exec -- <tool> <args>` for OS-level syscall interception
- ptrace + seccomp-BPF on Linux (full syscall interception)
- Process lifecycle fallback on macOS
- PTY forwarding for transparent interactive sessions
- Process tree tracking (fork, clone, exec)
- 11 pre-built supervisor profiles (claude-code, codex, aider, cursor, windsurf, cline, continue, copilot, goose, amp, generic)
- Profile auto-detection from command name
- `${PROJECT_DIR}` and `${HOME}` variable expansion in profile paths

### Exfiltration Containment (Phase 16)
- Protocol-aware outbound controls: HTTP(S), DNS, FTP/SFTP, SMTP, WebSocket, shell-transport
- Sink-side DLP scanning with irreversible secret redaction
- Session containment mode after sensitive reads (stricter outbound policy until review)
- Destination trust policy: allowlist/denylist/trust tiers by domain, IP, CIDR
- Canary token detection with runtime registry management and automatic deny
- Correlated source-to-sink audit evidence with incident snapshot export

### Production Hardening (Phases 17–22)
- API authentication enforcement for non-localhost access
- Per-bucket API rate limiting (general, write, proxy-test)
- Native TLS support for non-localhost exposure
- CI quality gates: TypeScript type-check, ESLint, `cargo fmt`, `cargo clippy`, `cargo deny`
- API type drift detection in CI (auto-generated TypeScript types)
- MSRV check (Rust 1.80)
- Feature gating by plan tier (Community, Pro, Enterprise)
- Notification channels: CLI, web, webhook (HMAC-SHA256 signed), email (SMTP)
- Billing portal integration via Polar.sh
- Release pipeline with cross-platform archives and checksums
