# Supervisor Profiles

This document explains what each built-in supervisor profile auto-allows and why.

Source of truth:

- [config/supervisor/profiles.toml](../config/supervisor/profiles.toml)

Profiles reduce noise by seeding the session allowlist with expected paths, commands, and destinations. They do not disable the rest of the proxy pipeline. Anything outside the profile still goes through normal scoring and review.

## Defaults (merged into every profile)

Every profile inherits these universal, local-only settings:

**Routine paths:**

- `/proc` — system introspection (read-only, world-readable)
- `/etc/profile.d` — shell environment discovery

**Routine commands:**

- Shells and environment: `bash`, `sh`, `env`
- File inspection: `cat`, `ls`, `find`, `grep`, `rg`, `fd`, `head`, `tail`, `wc`, `diff`, `patch`, `file`
- File manipulation: `mkdir`, `cp`, `mv`, `rm`, `touch`, `chmod`, `stat`, `ln`, `readlink`, `realpath`, `dirname`, `basename`
- Text processing: `tr`, `cut`, `sort`, `uniq`, `sed`, `awk`, `xargs`, `tee`, `jq`
- System info: `which`, `uname`, `id`, `whoami`, `date`
- Output and control flow: `test`, `true`, `false`, `echo`, `printf`
- Terminal: `stty`, `tput`
- System utilities: `getopt`, `getconf`, `lsb_release`, `dpkg-query`, `dpkg`, `ps`
- Git and SCM: `git`, `ssh`

**Routine exec roots:**

- `/usr/lib/git-core/` — git helper binaries (git-remote-http, git-credential-*, etc.)

**Read-only trusted paths** (auto-allow reads only, not writes):

- `${HOME}/.ssh/config`, `${HOME}/.ssh/known_hosts`, `${HOME}/.ssh/known_hosts2` — SSH metadata (NOT private keys)
- `${HOME}/.gitconfig`, `${HOME}/.config/git/config` — git config

**Read-only path patterns:**

- `${HOME}/.ssh/*.pub`, `${HOME}/.ssh/*-cert`, `${HOME}/.ssh/*-cert.pub` — SSH public keys and certificates (NOT secret material)

**No shared destinations** — outbound trust belongs in per-tool profiles.

---

## Base Profiles

### generic

The default fallback profile. Intentionally narrow.

**Routine paths:** `${PROJECT_DIR}/**`

**Routine commands:** none (inherits defaults only)

**Routine destinations:** none

**Routine listen addresses:** none

Why: Generic tools should not get broad file, network, or listener trust by default.

### generic-cli

Opt-in shared profile for local developer CLI tools that routinely use git, GitHub, and VS Code / Microsoft infrastructure but do not have a dedicated named profile. Use via `--profile generic-cli`. **NOT** the default parent for named tool profiles.

**Extends:** `generic`

**Additional commands:** `code`

**Routine destinations:**

- GitHub: `github.com`, `api.github.com`, `githubusercontent.com`, `raw.githubusercontent.com`
- VS Code / Microsoft: `visualstudio.com`, `vsassets.io`, `microsoft.com`

### grith-repl

Built-in Grith REPL policy base. Used with provider overlays to scope proxy and reputation behavior for interactive sessions.

**Extends:** `generic`

**Routine paths:** `${PROJECT_DIR}/**`

No additional commands or destinations — provider overlay supplies the destinations.

---

## Named Tool Profiles

All named tool profiles extend `generic` and list their own destinations explicitly.

### claude-code

Claude Code routinely reads project files, shells out to local build and SCM tools, and contacts Anthropic plus package and repository infrastructure.

**Launch contract:** requires `--dangerously-skip-permissions`

**Routine paths:**

- `${PROJECT_DIR}/**`
- `${HOME}/.config/claude-code/**`, `${HOME}/.claude/**`, `${HOME}/.local/state/claude/**`, `${HOME}/.cache/claude-cli-nodejs/**`, `${HOME}/.cache/claude/**`, `/tmp/claude-*` — Claude Code application state
- `${HOME}/.npm/**`, `${HOME}/.node_modules/**` — Node.js ecosystem
- `${HOME}/.config/Code/**`, `${HOME}/.vscode/**`, `${HOME}/.vscode-server/**` — VS Code application state

**Additional commands:**

- Node.js: `node`, `npm`, `npx`
- SCM extensions: `gh`
- Rust toolchain: `cargo`, `rustc`
- Python: `python`, `python3`, `pip`, `pip3`
- JavaScript tooling: `tsc`, `eslint`, `prettier`
- Text processing: `envsubst`, `gettext`
- Network: `curl`
- Archive / compression: `tar`, `gzip`, `gunzip`, `unzip`
- System utilities: `tmux`, `seq`, `yes`, `timeout`, `nproc`
- VS Code CLI: `code`

**Routine destinations:**

- Anthropic: `anthropic.com`, `api.anthropic.com`, `statsig.anthropic.com`, `cdn.anthropic.com`
- Claude web: `claude.ai`, `claude.com`
- GitHub: `github.com`, `api.github.com`, `githubusercontent.com`, `raw.githubusercontent.com`
- npm: `npmjs.org`, `registry.npmjs.org`
- Rust packages: `crates.io`, `static.crates.io`
- Python packages: `pypi.org`, `files.pythonhosted.org`
- Telemetry: `datadoghq.com`, `sentry.io`
- Statsig: `statsig.com`, `statsigapi.net`
- Google Cloud Storage: `storage.googleapis.com`, `googleapis.com`
- VS Code marketplace/CDN: `vscode.dev`, `visualstudio.com`, `vsassets.io`, `microsoft.com`

**Routine exec roots:**

- `${HOME}/.local/share/claude/versions/` — Claude-bundled helper binaries (rg, etc.)
- `/usr/share/code/` — VS Code system helpers
- `${HOME}/.nvm/versions/`, `${HOME}/.local/share/mise/`, `${HOME}/.local/share/nvm/` — version manager roots (node/python via nvm, mise, etc.)

**Routine listen addresses:** none

### codex

OpenAI Codex CLI. Reads project and local CLI state, shells out to common development tools, and contacts OpenAI and repository infrastructure.

**Routine paths:**

- `${PROJECT_DIR}/**`
- `${HOME}/.codex/**`, `${HOME}/.config/codex/**`, `${HOME}/.npm/**`, `/tmp/codex-*`

**Additional commands:**

- `node`, `npm`, `npx`, `cargo`, `rustc`, `python`, `python3`, `pip`, `pip3`
- `tmux`, `curl`
- `tsc`, `eslint`, `prettier`, `gh`
- `tar`, `gzip`, `gunzip`, `unzip`
- `seq`, `nproc`, `timeout`, `yes`

**Routine destinations:**

- OpenAI: `api.openai.com`, `openai.com`, `auth.openai.com`, `chatgpt.com`
- GitHub: `github.com`, `api.github.com`, `githubusercontent.com`, `raw.githubusercontent.com`
- npm: `npmjs.org`, `registry.npmjs.org`
- Rust packages: `crates.io`, `static.crates.io`
- Python packages: `pypi.org`, `files.pythonhosted.org`

**Routine listen addresses:** none (previously `0.0.0.0` — investigation confirmed no default Codex behaviour needs wildcard bind; loopback is auto-allowed by grith)

### aider

Aider is primarily a git- and Python-centric coding workflow with access to common LLM provider endpoints.

**Routine paths:**

- `${PROJECT_DIR}/**`
- `${HOME}/.aider*`, `${HOME}/.config/aider/**`, `${HOME}/.streamlit/**`, `/tmp/aider-*`

**Additional commands:**

- `python`, `python3`, `pip`, `pip3`, `cargo`, `node`, `npm`, `curl`
- `flake8`, `streamlit`

**Routine destinations:**

- LLM providers: `api.openai.com`, `api.anthropic.com`, `api.deepseek.com`, `openrouter.ai`
- Python packages: `pypi.org`
- PostHog analytics (opt-in): `us.i.posthog.com`
- Tokenizer data: `huggingface.co`

**Routine listen addresses:** none

### goose

Goose is a Rust-native AI coding agent by Block. It has no built-in sandbox, so grith provides the sole security boundary.

**Routine paths:**

- `${PROJECT_DIR}/**`
- `${HOME}/.config/goose/**`, `${HOME}/.local/share/goose/**`, `${HOME}/.local/state/goose/**`, `/tmp/goose-*`

**Additional commands:**

- `cargo`, `rustc`, `python`, `python3`, `pip`, `pip3`, `node`, `npm`, `npx`, `curl`
- `tar`, `gzip`, `gunzip`, `unzip`

**Routine destinations:**

- Anthropic: `anthropic.com`, `api.anthropic.com`
- OpenAI: `openai.com`, `api.openai.com`
- OpenRouter: `openrouter.ai`
- Telemetry: `statsig.com`, `statsigapi.net`

**Routine listen addresses:** none

### copilot

GitHub Copilot CLI. Bundles its own ripgrep binary and uses Node.js as its runtime.

**Routine paths:**

- `${PROJECT_DIR}/**`
- `${HOME}/.copilot/**`, `${HOME}/.npm/**`, `/tmp/copilot-*`

**Read-only paths:**

- `${HOME}/.config/github-copilot/apps.json` — legacy gh copilot extension OAuth credentials

**Additional commands:**

- `node`, `npm`, `npx`, `gh`, `cargo`, `rustc`, `python`, `python3`, `pip`, `pip3`
- `tsc`, `eslint`, `prettier`, `curl`
- `tar`, `gzip`, `gunzip`, `unzip`
- `seq`, `nproc`, `timeout`

**Routine destinations:**

- GitHub: `github.com`, `api.github.com`, `githubusercontent.com`, `raw.githubusercontent.com`
- Copilot infrastructure: `githubcopilot.com`, `api.githubcopilot.com`, `copilot.github.com`
- Telemetry: `visualstudio.com`
- npm: `npmjs.org`, `registry.npmjs.org`
- Rust packages: `crates.io`, `static.crates.io`
- Python packages: `pypi.org`, `files.pythonhosted.org`
- Statsig: `statsigcdn.com`, `api.statsigcdn.com`, `statsigapi.net`

**Routine listen addresses:** none

### cursor

Cursor CLI (by Anysphere). Bundles Node.js, ripgrep, and a sandbox binary. Under grith supervision, Cursor's built-in sandbox must be disabled to avoid ptrace conflict.

**Launch contract:** requires `--sandbox disabled`

**Routine paths:**

- `${PROJECT_DIR}/**`
- `${HOME}/.cursor/**`, `${HOME}/.cache/cursor-compile-cache/**`, `/tmp/cursor-*`

**Read-only paths:**

- `${HOME}/.config/cursor/auth.json` — auth credentials

**Additional commands:**

- `node`, `npm`, `npx`, `gh`, `cargo`, `rustc`, `python`, `python3`, `pip`, `pip3`
- `tsc`, `eslint`, `prettier`, `curl`
- `tar`, `gzip`, `gunzip`, `unzip`
- `seq`, `nproc`, `timeout`

**Routine destinations:**

- GitHub: `github.com`, `api.github.com`, `githubusercontent.com`, `raw.githubusercontent.com`
- Cursor API: `cursor.sh`, `api2.cursor.sh`, `cursor.com`, `api.cursor.com`, `cursorapi.com`, `marketplace.cursorapi.com`
- npm: `npmjs.org`, `registry.npmjs.org`
- Rust packages: `crates.io`, `static.crates.io`
- Python packages: `pypi.org`, `files.pythonhosted.org`
- Feature flags: `statsigcdn.com`, `api.statsigcdn.com`, `statsigapi.net`, `featureassets.org`

**Routine listen addresses:** none

### cline

Cline CLI (formerly Claude Dev). Bundles ripgrep and uses Node.js as its runtime.

**Routine paths:**

- `${PROJECT_DIR}/**`
- `${HOME}/.cline/**`, `/tmp/cline-*`

**Additional commands:**

- `node`, `npm`, `npx`, `cargo`, `rustc`, `python`, `python3`, `pip`, `pip3`
- `tsc`, `eslint`, `prettier`, `curl`
- `tar`, `gzip`, `gunzip`, `unzip`

**Routine destinations:**

- Cline platform: `cline.bot`, `api.cline.bot`, `app.cline.bot`, `data.cline.bot`, `otel.cline.bot`
- Anthropic: `anthropic.com`, `api.anthropic.com`
- OpenAI: `openai.com`, `api.openai.com`
- OpenRouter: `openrouter.ai`
- npm: `npmjs.org`, `registry.npmjs.org`

**Routine listen addresses:** none

---

## Standalone Profiles

### openclaw

OpenClaw is a local AI agent platform (Node.js) that orchestrates browser automation via Chromium/Chrome, messaging integrations via signal-cli and other helpers, and sandboxed code execution via Docker. This profile does **not** extend `generic`.

**Routine paths:**

- `${HOME}/.openclaw/**`, `${HOME}/.config/openclaw/**`, `${HOME}/.local/share/openclaw/**`, `${HOME}/.cache/openclaw/**`, `/tmp/openclaw-*`, `${PROJECT_DIR}/**`

**Routine commands:**

- OpenClaw runtime: `node`, `npm`, `npx`, `pnpm`, `openclaw`
- Browser automation: `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable`
- Messaging helpers: `signal-cli`
- Container execution: `docker`, `docker-compose`
- Python: `python3`, `pip3`
- Utilities: `tmux`, `curl`

**Routine destinations:**

- LLM providers: `anthropic.com`, `api.anthropic.com`, `openai.com`, `api.openai.com`, `openrouter.ai`, `ollama.ai`
- Messaging platforms: `telegram.org`, `api.telegram.org`, `slack.com`, `slack-edge.com`, `discord.com`, `discordapp.com`, `whatsapp.com`, `web.whatsapp.com`, `signal.org`, `storage.signal.org`, `chat.google.com`, `hangouts.google.com`, `matrix.org`, `mattermost.com`, `irc.libera.chat`
- Package management: `registry.npmjs.org`
- Asset delivery: `storage.googleapis.com`

**Routine listen addresses:** `127.0.0.1` (loopback only — Node.js gateway binds locally; `0.0.0.0` is intentionally excluded)

---

## Overlays

Overlays are small, additive trust extensions applied on top of a base profile. They do not replace any profile setting — they only add entries.

### Launcher Overlays

Automatically detected based on parent process name or environment variables.

| Overlay | Detection | Adds |
|---------|-----------|------|
| `vscode-terminal` | Parent process: `code`, `code-insiders`, `codium` or env `TERM_PROGRAM=vscode` | command: `code` |
| `cursor-terminal` | Parent process: `cursor` | (none — presence-only, for policy scope key) |

### Provider Overlays

Applied to `grith-repl` sessions based on the configured LLM provider.

| Overlay | Destinations |
|---------|-------------|
| `openai` | `openai.com`, `api.openai.com`, `auth.openai.com`, `chatgpt.com` |
| `anthropic` | `anthropic.com`, `api.anthropic.com`, `claude.ai`, `claude.com` |
| `openrouter` | `openrouter.ai` |

---

## Shared Rules

- `routine_paths` are auto-allowed because the tool is expected to read and write there during normal operation.
- `routine_commands` are auto-allowed because the tool commonly shells out to them as part of ordinary workflows.
- `routine_destinations` are trusted as expected network peers for that tool and reduce review noise for normal outbound traffic. Base domains (e.g. `anthropic.com`) enable subdomain matching (e.g. `mcp-proxy.anthropic.com`).
- `routine_listen_addresses` are explicit listener-address exceptions for tools that need to bind a specific address without repeated prompts.
- `routine_exec_roots` are directories whose executables are trusted for exec (e.g. git helper binaries, bundled tools).
- `readonly_paths` are auto-allowed for reads only (not writes).
- Non-loopback listeners are not auto-allowed by default. A bind like `0.0.0.0` or a specific non-loopback interface still requires explicit profile documentation before it should be auto-allowed.

---

## Remote Profile Overlay Updates

Supervisor profiles can receive over-the-air (OTA) updates between binary releases via signed remote overlay manifests. This allows reviewed allowlist additions to reach users without a full binary update.

### Trust Model

- Remote overlays are signed with a dedicated Ed25519 keypair separate from the license key.
- The public key is compiled into the binary. Server compromise alone cannot change policy.
- Remote overlays may only add entries to five vectors: `routine_paths`, `routine_commands`, `routine_destinations`, `readonly_paths`, `readonly_path_patterns`.
- Remote destination entries are validated conservatively because runtime matching uses DNS suffix semantics. Public-suffix-level values such as `com` or `co.uk` are rejected.
- Remote `routine_paths` are limited to tool-scoped `${HOME}` subtrees, project subpaths, and tool-prefixed temp paths. Exact `readonly_paths` and simple `${HOME}` / `${PROJECT_DIR}` read-only globs stay narrower.
- Structural changes (`launch_contract`, `extends`, `routine_exec_roots`, `routine_listen_addresses`, overlays, new profiles) require a binary update via `profiles.toml`.

### Configuration

```toml
[general]
profile_update_check = true   # default: true
```

Disable with `grith config set general.profile_update_check false` or `GRITH_NO_PROFILE_UPDATE=1`.

### Refresh Behavior

- Refresh runs on REPL, `run`, and `exec` commands (not `config`, `daemon`, etc.).
- No TTY requirement — `exec` with redirected output still gets fresh policy.
- TTL: 6 hours between network checks.
- Timeout: 3 seconds. Failure is silent (debug-level log).
- Never blocks session startup. Never downgrades to unverified data.

### Cache

- Cached manifest: `~/.config/grith/profiles.remote.json`
- Metadata: `~/.config/grith/profiles.remote.meta.json` (version, last-checked timestamp)
- Anti-rollback: `profiles_version` is monotonically increasing. Downgrades are rejected.
- Every load re-verifies the cached manifest before use. Invalid cache is ignored.

### Resolution Order

```
embedded bundled profiles (include_str!)
  -> optional developer filesystem override (`GRITH_DEV_PROFILE_OVERRIDE=1`)
    -> verified remote overlay (cached signed manifest, additive merge)
      -> launcher/provider overlays
        -> effective session policy
```

The developer filesystem override is opt-in. A normal runtime no longer trusts `./config/supervisor/profiles.toml` implicitly.

### Audit and Drift Detection

Use `grith profile audit` to analyze forensic traces and identify profile drift:

```bash
grith profile audit --profile claude-code --trace /tmp/trace.jsonl
```

Findings are classified into three buckets:
1. **Remote overlay candidates** — safe for OTA distribution
2. **Bundled-profile changes** — require editing `profiles.toml`
3. **Manual review** — suspicious or ambiguous events
