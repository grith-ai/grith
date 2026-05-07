# Manual Testing Guide

**Last updated:** 2026-03-19
**Purpose:** Captures all manual validation steps that cannot be automated. Run these before any production release.

---

## Prerequisites

- Linux with ptrace support (`sysctl kernel.yama.ptrace_scope` should be 0 or 1)
- grith built from current main: `cargo build --release`
- Claude Code installed: `claude-code` available on PATH
- SSH key configured for GitHub: `ssh -T git@github.com` succeeds
- A real project directory with git remote over SSH
- `~/.config/grith/` directory exists (run `grith init` if needed)

---

## 1. Claude Code Profile Validation (Plan 45 T-08)

**Purpose:** Verify the `claude-code` supervisor profile handles routine operations without excessive prompting, while still catching genuinely security-relevant operations.

### Setup

```bash
cd /path/to/your/project
grith exec --syscall-log /tmp/grith-test.log -- claude-code --dangerously-skip-permissions
```

### Test Cases

#### 1.1 Startup — No Prompt Storm

Give Claude a simple task (e.g., "hello") and verify it starts without being frozen by a cascade of queued permission prompts.

**Pass:** Claude responds within a few seconds. The TUI log may show some auto-allowed operations but no queue of permission dialogs.

**Fail:** Multiple permission dialogs appear in rapid succession during startup before Claude has done anything.

#### 1.2 Project File Reads

Ask Claude to read a source file in the project.

**Pass:** File read completes without prompting. Syscall log shows `auto-allow` via `session allowlist` or `noise_filtered`.

**Fail:** File read triggers a permission prompt for a file under `${PROJECT_DIR}`.

#### 1.3 Claude State Writes

Observe Claude's normal operation. It writes to `~/.cache/claude/`, `~/.local/state/claude/`, `~/.config/claude-code/`, and `/tmp/claude-*`.

**Pass:** No prompts for writes to these paths. Syscall log shows `session allowlist` auto-allow.

**Fail:** Writes to Claude-managed state directories trigger review.

#### 1.4 Build Toolchain (`cargo build`)

Ask Claude to build the project.

**Pass:** `cargo` and `rustc` spawns auto-allowed. No rate-limit bursts. Build completes. Sub-processes like `cc`, `ld` may go through the proxy but should score low enough to auto-allow or at most prompt once.

**Fail:** Build triggers a cascade of permission prompts or rate-limit freezes.

#### 1.5 GitHub CLI (`gh`)

Ask Claude to check PR status or create an issue.

**Pass:** `gh` spawn auto-allowed as routine command. Network connections to `github.com`/`api.github.com` auto-allowed. `~/.config/gh/hosts.yml` read goes through proxy (not in `routine_paths` — this is intentional since it contains tokens).

**Fail:** `gh` spawn itself triggers a prompt.

#### 1.6 Network Fetch (`curl`)

Ask Claude to fetch a URL.

**Pass:** `curl` spawn auto-allowed. Network destination checked — known destinations (github.com, npmjs.org, etc.) auto-allowed; unknown destinations score into review range.

**Fail:** `curl` spawn itself triggers a prompt.

#### 1.7 SSH Key Read (Git Push)

Ask Claude to push a commit (or trigger a git operation that uses SSH).

**Pass:** Permission dialog appears showing:
- Title: `FileRead(/home/<user>/.ssh/id_rsa)  ← ssh → claude (connecting to git@github.com)`
- Process: `ssh (pid XXXXX)`
- Parent: `claude (pid XXXXX)` or `git (pid XXXXX)`
- Target: `connecting to git@github.com`
- Score: ~8.0 (CRITICAL)

This is correct behavior — SSH private key reads should always prompt.

**Fail:** SSH key read is auto-allowed without prompting, OR the process attribution shows `fork-from-*` instead of real process names.

#### 1.8 SSH Config Read-Only Trust

During the SSH operation above, verify that `~/.ssh/config` and `~/.ssh/known_hosts` are NOT prompted for.

**Pass:** Syscall log shows these were auto-allowed via `ro:` session allowlist match.

**Fail:** Permission prompts appear for `~/.ssh/config` or `~/.ssh/known_hosts`.

#### 1.9 Git Config Read-Only Trust

Verify that `~/.gitconfig` and `~/.config/git/config` reads are auto-allowed.

**Pass:** No prompts for reading these files. Syscall log shows `ro:` match.

**Fail:** Permission prompts for gitconfig reads.

#### 1.10 Sensitive Path Protection

Ask Claude to read a file that should be protected.

Prompt: "Read the contents of ~/.aws/credentials" (or `.env` in the project root)

**Pass:** Operation is scored high by secret-scan and path rules. Either auto-denied or queued for review (depending on score). Never auto-allowed.

**Fail:** Sensitive file read is silently auto-allowed.

#### 1.11 Grith Config Self-Protection

Ask Claude to modify grith configuration.

Prompt: "Append a line to ~/.config/grith/learned_rules.toml"

**Pass:** Write is hard-denied before proxy evaluation. Syscall log shows `auto-deny` with reason `write to grith config denied — self-protection`.

**Fail:** Write to grith config succeeds or prompts instead of hard-denying.

#### 1.12 Unknown Network Destination

Ask Claude to fetch from an unusual domain.

Prompt: "Fetch https://example.com/test"

**Pass:** Connection goes through the full proxy and is scored. May be queued for review depending on the domain's reputation status.

**Fail:** Unknown destination is silently auto-allowed.

### Log Analysis

After the session, review the syscall log:

```bash
# Count decisions by type
grep -oP 'auto-allow|auto-deny|manual-allow|manual-deny|queue|reputation-auto-allow' /tmp/grith-test.log | sort | uniq -c | sort -rn

# Check for unexpected auto-allows on sensitive paths
grep 'auto-allow' /tmp/grith-test.log | grep -iE '\.ssh|\.aws|\.env|credential|secret|grith'

# Check for unexpected prompts on routine paths
grep 'queue\|manual' /tmp/grith-test.log | grep -E 'node|npm|cargo|rustc|git\b'

# Verify reputation observations were recorded
grep 'reputation' /tmp/grith-test.log | head -20
```

---

## 2. Learned Allowlist Persistence (Plan 47)

**Purpose:** Verify that `[l]` (Always allow) creates persistent rules that survive across sessions.

### Test Cases

#### 2.1 Learn and Persist

1. Start a `grith exec` session
2. Trigger an operation that gets queued (e.g., SSH key read)
3. Press `[l]` (Always allow)
4. Verify the TUI log shows "Learned: ro:/home/<user>/.ssh/id_rsa (claude-code)"
5. End the session
6. Check `~/.config/grith/learned_rules.toml` — the rule should be present

**Pass:** Rule persisted with correct pattern, profile, reason, and timestamp.

**Fail:** Rule not written, or written with wrong pattern (e.g., bare path instead of `ro:` prefix).

#### 2.2 Reload on Next Session

1. Start a new `grith exec` session (same profile)
2. Trigger the same operation that was learned

**Pass:** Operation auto-allowed without prompting. Log shows it matched the session allowlist.

**Fail:** Operation prompts again despite the learned rule existing.

#### 2.3 Profile Isolation

1. Learn a rule in the `claude-code` profile
2. Start a session with a different profile (e.g., `--profile generic`)
3. Trigger the same operation

**Pass:** Operation is NOT auto-allowed — the learned rule only applies to `claude-code`.

**Fail:** Rule leaks across profiles.

#### 2.4 Approve vs Learn Difference

1. Trigger an operation and press `[a]` (Approve)
2. End the session and start a new one
3. Trigger the same operation

**Pass:** Operation prompts again — `[a]` only lasts for the session, not across sessions.

**Fail:** `[a]` persists like `[l]`.

---

## 3. Reputation System (Plan 48)

**Purpose:** Verify the reputation system learns from repeated approvals and eventually auto-allows borderline operations.

### Test Cases

#### 3.1 Reputation Observations Recorded

1. Run a session and approve several operations
2. End the session
3. Run `grith reputation show`

**Pass:** Table shows entries with trust scores and observation counts > 0.

**Fail:** Empty table or zero observations.

#### 3.2 Reputation Persists Across Sessions

1. Run `grith reputation show` — note the entries
2. Start and end another session (approve some operations)
3. Run `grith reputation show` again

**Pass:** Observation counts increased. Trust scores reflect the new data.

**Fail:** Counts reset to zero (persistence broken).

#### 3.3 Reputation Auto-Allow (Borderline Operations)

This requires a borderline operation (score 3.0-7.0) to be approved enough times for the reputation to build sufficient trust. After 8+ approvals with trust > 0.92:

**Pass:** The operation auto-allows without prompting. Syscall log shows `reputation-auto-allow`.

**Fail:** Operation continues to prompt despite high trust and many observations.

#### 3.4 Safety Ceiling Prevents Auto-Allow

Operations with high filter scores (≥5.0) or secret-scan matches should never be auto-allowed by reputation, regardless of trust.

**Pass:** High-score operations always prompt even with high reputation trust.

**Fail:** Secret-scan or high-score operation is auto-allowed by reputation.

#### 3.5 Deny Drops Trust

1. Build trust for an operation (approve it several times)
2. Then deny it once
3. Check `grith reputation show` — trust should drop significantly

**Pass:** Trust score drops by >10% from a single deny (deny weighted 3x).

**Fail:** Trust unchanged after deny.

#### 3.6 Reputation Reset

1. Run `grith reputation reset`
2. Run `grith reputation show`

**Pass:** Empty table.

**Fail:** Old entries remain.

---

## 4. Permission Dialog UX

**Purpose:** Verify the permission dialog displays useful context for security decisions.

### Test Cases

#### 4.1 Process Attribution

Trigger an SSH key read via git.

**Pass:** Title line shows `FileRead(~/.ssh/id_rsa)  ← ssh → claude (connecting to git@github.com)`. Detail section shows process name, parent, and target in bold.

**Fail:** Process shows as `fork-from-*` or parent shows wrong process.

#### 4.2 Filter Breakdown

Trigger a queued operation.

**Pass:** Filter breakdown shows individual filter contributions with bar charts and scores.

#### 4.3 Action Labels

**Pass:** Actions show: `[a] Approve  [d] Deny  [l] Always allow  [i] Inspect`

**Fail:** `[l]` still shows "Learn & approve" instead of "Always allow".

---

## 5. Dashboard Integration

**Purpose:** Verify the dashboard starts and shows session data during `grith exec`.

### Test Cases

#### 5.1 Dashboard Auto-Starts

1. Ensure no dashboard is running: `grith dashboard stop`
2. Start `grith exec`
3. Check `grith dashboard status`

**Pass:** Dashboard is running and accessible at `localhost:3141`.

**Fail:** Dashboard not started during `grith exec`.

#### 5.2 Session Visible in Dashboard

1. While `grith exec` is running, open the dashboard in a browser
2. Navigate to the supervisor sessions page

**Pass:** The active session is visible with tool name, PID, and stats.

---

## 6. Self-Protection

**Purpose:** Verify grith's own configuration files are protected from the supervised tool.

### Test Cases

#### 6.1 Config Write Hard-Deny

From within a supervised Claude session, ask it to write to any file under `~/.config/grith/`.

**Pass:** Write is hard-denied. Syscall log shows `auto-deny` with `write to grith config denied`.

**Fail:** Write succeeds or only scores into review range.

#### 6.2 Reputation File Protection

Ask Claude to read `~/.config/grith/reputation.toml`.

**Pass:** Read is flagged as sensitive path and goes through proxy (not noise-filtered). May score into review range.

**Fail:** Read is silently auto-allowed via noise filtering.

---

## Post-Test Cleanup

```bash
# Remove test syscall log
rm -f /tmp/grith-test.log

# Optionally reset reputation data if testing polluted it
grith reputation reset

# Optionally remove test learned rules
# Edit ~/.config/grith/learned_rules.toml and remove test entries
```

---

## Adding New Tests

When adding new security features or permission mechanisms, add test cases to this guide covering:

1. **Positive case** — the feature works as intended
2. **Negative case** — the feature correctly blocks what it should
3. **Isolation** — the feature doesn't leak across profiles/sessions/namespaces
4. **Persistence** — if the feature persists state, verify it survives restarts
5. **Attribution** — if the feature surfaces in the UI, verify the display is correct
