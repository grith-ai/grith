# Profile Audit Guide

The `grith profile audit` command analyzes forensic syscall traces to detect supervisor profile drift and classify findings for review.

## Capturing a Trace

Run a supervised tool with `--trace-syscalls-jsonl` to capture a forensic trace:

```bash
grith exec --trace-syscalls-jsonl /tmp/trace.jsonl -- claude-code "list files"
```

The trace captures every intercepted syscall with structured subject fields, event correlation by `event_id`, and multi-stage decision records.

## Running an Audit

```bash
grith profile audit --profile claude-code --trace /tmp/trace.jsonl
```

## Understanding the Output

The audit produces four sections:

### 1. Summary

```
Events analyzed: 1,247
  Approved: 1,180  Denied: 42  Other: 25
```

### 2. Remote Overlay Candidates

Findings that can be safely distributed via the OTA remote overlay system:

```
Remote Overlay Candidates (23):
  routine_destinations:
    + extensions.anthropic.com
    + sentry.io
  routine_paths:
    + ${HOME}/.claude/extensions/**
```

These are entries that pass the strict validation rules:
- Destinations: hostname only, no scheme/path/port/wildcard
- Commands: basename only, no path separator or arguments
- Routine paths: tool-scoped `${HOME}` subtrees, project subpaths, or tool-prefixed temp paths
- Read-only paths: exact paths only; patterns use a single-segment `*` wildcard under `${HOME}` or `${PROJECT_DIR}`

### 3. Bundled-Profile Changes Required

Findings that require editing `profiles.toml` and a binary release:

```
Bundled-Profile Changes Required (2):
  new exec root required for: /opt/custom-tool/bin/tool
  listener policy: 127.0.0.1:9222
```

These include:
- New `routine_exec_roots` entries
- New `routine_listen_addresses` entries
- `launch_contract` changes
- New profiles or structural changes

### 4. Manual Review Required

Suspicious or ambiguous findings that need human investigation:

```
Manual Review Required (5):
  IP-only connect: 192.168.1.100:443
  overbroad path: /
```

These include:
- IP-only connections (no hostname resolved)
- Overbroad path patterns
- Entries that fail validation rules

## Recommended Workloads

For automated audit capture:

| Profile | Mode | Minimal Workload |
|---------|------|-----------------|
| `claude-code` | automated | start, trivial command, exit |
| `codex` | automated | start, trivial command, exit |
| `aider` | automated | start, trivial command, exit |
| `goose` | automated | start, trivial command, exit |
| `copilot` | automated | one small explain/query invocation |
| `openclaw` | semi-automated | start, trivial command, exit |
| `cursor` / `cline` | manual capture | start, one simple action, exit |

## From Audit to PR

1. Run audit capture for the target profile.
2. Review the output.
3. If findings are OTA-eligible, add them to `config/supervisor/profiles.remote.toml`.
4. If findings require structural changes, edit `config/supervisor/profiles.toml`.
5. Open a PR. CI validates the actual `profiles.remote.toml` signing input automatically.
6. After merge, sign the remote overlay offline (see [PROFILE-SIGNING.md](PROFILE-SIGNING.md)).
7. Upload the signed manifest to the API endpoint.
