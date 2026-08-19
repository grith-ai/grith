# Changelog

All notable changes to the grith project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Conventional Commits](https://www.conventionalcommits.org/) and
will adopt [Semantic Versioning](https://semver.org/) starting at 1.0.0.

## [0.2.5] - 2026-08-19

### Changed

- **Supervision-escape enforcement is now ON by default.**
  `supervisor.enforce_authority_delegating_spawn` and
  `supervisor.enforce_control_socket_connect` both default to `true`. A
  security supervisor whose sharpest protections ship disabled is not one
  we would run, and the queue-noise groundwork landed first: a denied
  authority-delegating spawn is SIGKILLed rather than silently allowed
  (0.2.4), read-only subcommands (`docker ps`, `systemctl status`,
  `kubectl get`, ...) never prompt, and an exact-command approval sticks
  for the session (0.2.4). Enforcement escalates Allow→QUEUE, so
  interactive sessions see a prompt, not a breakage.

  **Behaviour change for non-interactive sessions:** a headless or CI
  session that legitimately delegates (e.g. `docker build` in a script
  under `grith exec`) now fails safe and DENIES instead of allowing.
  Opt-outs, most-targeted first: add the binary to the profile's
  `permit_authority_delegating` / `permit_control_sockets` list, set the
  config keys to `false`, or set `GRITH_ENFORCE_AUTHORITY_DELEGATING_SPAWN=0`
  / `GRITH_ENFORCE_CONTROL_SOCKET_CONNECT=0`.

### Fixed

- **`grith update` now replaces the binary you are actually running.** The
  updater ran the install script blindly, and the installer writes to its
  own destination - so a copy running from anywhere else got a *second*
  install elsewhere on `$PATH` while every launch kept starting the old
  binary and re-offering the same update. The updater now classifies the
  running binary's directory: `~/.local/bin` updates in place,
  `/usr/local/bin` passes `--global`, and anywhere else (a cargo build, a
  system package, a hand-placed copy) refuses with instructions instead of
  pretending to succeed. The install script is also fetched in-process with
  connect and read timeouts rather than through an unbounded `curl | sh`,
  so a stalled or failed download is detected instead of hanging.

- **Spawn-enforcement no longer hashes every delegating binary at session
  start.** Pinning the identity of the curated authority-delegating binaries
  read and SHA-256'd each match on `$PATH` before the event loop began -
  docker and kubectl are tens of megabytes each, so every supervised launch
  paid for them. Sizes (a stat) still resolve at session start; the content
  hashes are now built at most once per session and only when a spawn
  actually needs identity matching (a by-name delegating spawn, or a target
  whose size collides with a pinned binary). Verdicts are unchanged: the
  pinned set is only ever consulted as `contains(spawn_sha256)`, and a
  size miss already proves no hash can match. This affected anyone who had
  opted into `enforce_authority_delegating_spawn` before now; turning it on
  by default is what surfaced it.

  **Known gap, stated plainly:** control-socket enforcement does not yet
  match abstract-namespace unix sockets (`sun_path[0] == '\0'`), which
  standard X11 client libraries try first - a pathname-socket connect is
  enforced, an abstract one is not. The sockaddr rendering fix is tracked
  separately; the basename-keyed binary classifier caveat from 0.2.3 also
  still applies.

## [0.2.4] - 2026-08-18

### Security

- Session trust derived from the launch directory (`${PROJECT_DIR}/**` in
  profiles) no longer applies when `grith exec` is started from `/`, the
  home directory, or an ancestor of it — previously such sessions silently
  treated the entire tree, including `~/.ssh` and other credential
  directories, as routine project files. Even from a genuine project
  directory, launch-derived trust can no longer auto-allow reads or writes
  of credential stores (`.ssh`, `.aws`, `.gnupg`, `.kube`, system stores,
  grith's own config); explicitly listed profile paths are unaffected.
- The security proxy now evaluates a file rename's DESTINATION, not only its
  source — `mv ./benign ~/.ssh/authorized_keys` is scored on where the file
  lands, closing the `rename(2)` analogue of the symlink-into-a-sensitive-
  path hole.

### Added

- Linux aarch64 support: the CLI supervisor's ptrace + seccomp interception
  now runs natively on `aarch64-unknown-linux-{gnu,musl}` (kernel 5.3+).
  Release artifacts include a static `aarch64-unknown-linux-musl` binary and
  the installer maps Linux arm64 machines to it automatically.

## [0.2.3] - 2026-08-14

A supervision-escape hardening release.

### Added

- **Authority-delegating spawns can now be enforced, not just logged.**
  Spawning a binary whose real work runs in a privileged or unsupervised peer
  — `systemd-run`, `at`/`batch`, `docker`/`podman`/`nerdctl`, `kubectl`,
  `systemctl`, `machinectl`, `loginctl`, `dbus-send`/`gdbus`/`busctl`,
  `crontab`, `flatpak`, `nsenter`, `tmux`, `screen` — hands the command to a
  process outside the supervised tree, where none of its file, network, or
  secret access is intercepted or scored. This is the `systemd-run --user … --
  <cmd>` escape class. grith already detected these spawns but only recorded
  them (audit-only). The new `supervisor.enforce_authority_delegating_spawn`
  flag (default **off**, env override
  `GRITH_ENFORCE_AUTHORITY_DELEGATING_SPAWN`) escalates such a spawn
  Allow→QUEUE for review. A profile may allow specific binaries without a
  prompt via the new `permit_authority_delegating` list (e.g.
  `["systemd-run"]`). Escalation is QUEUE rather than deny, so an operator can
  approve legitimate use once (the session allowlist remembers it); a
  non-interactive session fails safe and denies.
- **Control-injection IPC socket connects can now be enforced.** A connect to
  a **pathname** session D-Bus (`unix:path=/run/user/<uid>/bus`), tmux, screen,
  or X11 socket can drive a more-privileged peer to run commands on the tool's
  behalf. The new `supervisor.enforce_control_socket_connect` flag (default
  **off**, env override `GRITH_ENFORCE_CONTROL_SOCKET_CONNECT`) routes such a
  connect to the proxy — instead of auto-allowing it as local IPC — and
  escalates it Allow→QUEUE unless the profile's new `permit_control_sockets`
  list authorises it. It is an independent knob from the spawn flag because
  desktop tooling touches the session bus routinely (higher false-positive
  surface). An authority-delegating spawn or control socket already on the
  session allowlist (e.g. a profile that lists `tmux`/`docker` as a routine
  command) is still escalated when enforcement is on — the session allowlist
  no longer short-circuits it; the explicit `permit_*` lists are the opt-out.

  Both detections remain audit-only with their flags off, so upgrading changes
  no behaviour until an operator opts in. Known limitations / follow-ups
  (documented in the `authority_delegation` module): (1) **abstract-namespace**
  unix sockets (`sun_path[0] == '\0'`) currently render as an empty `unix:`
  address, so an abstract-socket X11/D-Bus connect — which standard X11 client
  libraries attempt first — is not yet matched by control-socket enforcement;
  fixing the sockaddr rendering to `unix:@<name>` is tracked separately.
  (2) the binary classifier is basename-keyed, so canonical-path/content-hash
  hardening is needed to defeat a renamed copy. (3) proxy-side scoring would
  extend both detections to the built-in-agent (non-supervised) path.

## [0.2.2] - 2026-08-13

A security-hardening release. It closes the syscall-perimeter, audit-integrity,
and egress-inspection gaps found in pre-launch review, and adds cross-process
and kernel-surface coverage. Upgrading from 0.1.x is strongly recommended.

### Removed

- **Cold-start scoring removed entirely.** The proxy no longer widens its
  allow/deny thresholds for the first N calls of a session. Every tool call is
  now evaluated against the same fixed thresholds (`auto_allow_threshold`,
  `auto_deny_threshold`), so the first call in a session is filtered identically
  to the thousandth and an early destructive/exfiltrating operation is never
  under-scored. The `cold_start_calls`, `cold_start_escalation_low`, and
  `cold_start_escalation_high` config keys are gone (silently ignored if still
  present in a config file); the `proxy/status` and `proxy/test` dashboard API
  responses no longer carry `cold_start_remaining` / `cold_start`. The
  behavioural filter's own profiling-baseline period is unaffected (a separate
  mechanism). Operators who relied on cold-start widening should set the fixed
  thresholds to the values they want applied uniformly.

### Fixed

- **Supervised tools no longer crash from spurious foreign-ABI denials.**
  Ordinary syscalls could sporadically be misclassified as x32-ABI calls and
  hard-denied in the supervisor's syscall-stepping path; when the denied call
  was `futex(2)` or `restart_syscall(2)`, the injected `EPERM` made glibc abort
  and the whole supervised session died of `SIGABRT` shortly after start. Two
  compounding defects: the entry/exit bookkeeping could fall out of step with
  the kernel, and the ABI check then read the ptrace event message at a stop
  where the kernel stores its own syscall-stop codes — which numerically
  collide with grith's foreign-ABI markers, turning every such misread into an
  x32 verdict. The supervisor now takes entry-vs-exit and the ABI decision from
  the kernel's authoritative syscall record, and consults the event-message
  marker only where it is genuinely current (pre-5.3 seccomp stops). Real
  foreign-ABI enforcement (`int 0x80`, x32 numbers, forged filter markers) is
  unchanged and remains covered by the ptrace test suite.

- **Own-credential outbound false positive in taint scoring.**
  Reading a credential and then running an outbound-capable tool that uses it
  (`git push`, `aws s3 ls`, `npm publish`) no longer QUEUEs on its own. The
  data-flow taint rule's condition 4 (outbound-capable binary under taint) was a
  standalone trigger; it is now gated behind
  `proxy.spawn.taint_outbound_requires_data_flow` (default `true`), so an
  outbound binary under taint fires only when the spawn actually references the
  tainted data (argv path/env, pipe/redirect, or shell-pattern). Genuine exfil
  still fires — `aws s3 cp <tainted-file> s3://…` and `curl -d @<tainted>` are
  caught by conditions 1–3, and outbound-to-untrusted-destination is
  independently scored by the egress filter. Operators can set the flag `false`
  to restore the standalone fire.

- **Secret-scan false positives on benign token shapes.**
  The secret scanner now suppresses matches whose value is a provably-benign
  shape, so routine development no longer trips the 1,620-pattern corpus: bare
  git/SHA hex digests not in an assignment context (`git show <sha>`, file
  checksums), npm/yarn lockfile integrity hashes (`sha512-…`), JWTs (`eyJ…`),
  RFC-4122 UUIDs, and Stripe-style `_test_` placeholder keys. Implemented as a
  post-match layer (lazily compiling only patterns that actually fire, so
  startup is unchanged); every carve-out is paired with a guard ensuring real
  secrets in the same context still fire (a 40-hex value assigned to
  `aws_secret_access_key=` fires, `sk_live_`/real-shaped keys fire, a non-JWT
  base64 blob fires). AWS's documented example key (`AKIAIOSFODNN7EXAMPLE`) is
  intentionally still flagged — it is a real-format key, not an unambiguous test
  prefix. Additionally, reads of low-signal assets (under `node_modules`, or
  `.min.js`/`.min.css`/`.map` minified bundles) **down-weight** the generic
  keyword-assignment heuristics (`generic-*`) below the queue threshold so
  linting/reading minified code no longer escalates — while specific
  vendor/format keys (AWS, GitHub, Stripe, …) keep full weight, so a real
  credential embedded in a package still fires.

- **Egress false positive on cloud object-storage URIs.** The egress filter
  extracted any `scheme://…` token from a shell command as a network
  destination, so a routine `aws s3 rm s3://staging/obj` (or `gsutil ls
  gs://…`) parsed the *bucket name* as an unknown host and queued for review.
  Object-storage bucket URIs (`s3://`, `gs://`, `gcs://`, `wasb(s)://`,
  `abfs(s)://`, `adl(s)://`, `b2://`, `r2://`, `oss://`, `cos://`, `swift://`,
  `minio://`) are no longer treated as network destinations — they reference a
  bucket/object, and the real egress to the provider API is still
  policy-checked at connect time. Exfil to an attacker bucket via the provider
  endpoint (`https://bucket.s3.amazonaws.com/…`) continues to flag
  `unknown-destination` (regression-guarded).

### Security

- **Syscall interception hardened against evasion.** The supervisor now fails
  closed on foreign-architecture and 32-bit-compatibility syscalls (`x32`,
  `int 0x80`) instead of letting them pass, and resolves symlinks and `..`
  traversal to their real target *before* policy evaluation, so a symlinked or
  relative path can no longer launder access to a protected file. The
  `openat2`, hardlink, and rename/truncate syscall families — previously able
  to reach the filesystem uninspected — are now trapped and classified.

- **Expanded kernel-surface coverage.** New syscall classes are intercepted:
  kernel-module load/unload and `kexec` are hard-denied (no supervised tool has
  a legitimate reason to replace the running kernel); architecture-privileged
  operations (`reboot`, `swapon`, `sethostname`, direct I/O-port access) are
  hard-denied; filesystem-mount and namespace primitives (`mount`,
  `pivot_root`, `unshare`, `setns`) are covered, with a profile carve-out for
  declared sandbox binaries; and cross-process memory access (`ptrace`,
  `process_vm_readv` / `process_vm_writev`) is scored for review when it targets
  a process **outside** the supervised tool's own process tree — closing a path
  that could read secrets out of another application's memory without ever
  touching a file or a socket.

- **Connected-UDP egress is now inspected.** A datagram socket that connects to
  a destination and then sends via `write` / `send` (rather than `sendto`) is
  attributed to its real destination and scored — including across an `exec()`
  — closing a channel that previously bypassed network policy. DNS is inspected
  in-line at the syscall boundary; the earlier out-of-process DNS proxy is
  retired.

- **Wildcard-bind listener clamp.** When a supervised tool binds a listener to
  a wildcard address (`0.0.0.0` / `::`), the bind is rewritten to loopback
  according to the profile's listener policy, so a tool cannot inadvertently
  expose a local service to the network; an undeclared wildcard bind is
  surfaced for review.

- **A tracee can no longer blind the supervisor with its own seccomp filter.**
  Installing a user-notification "new listener" seccomp filter — which could
  otherwise out-rank grith's interception and hide subsequent syscalls — is
  denied.

- **Tamper-evident, single-writer audit chain.** The daemon is now the
  exclusive audit writer, enforced by a file lock; every record is covered by a
  versioned full-record hash (the hash covers all persisted fields, including
  its own version); concurrent writers can no longer fork the chain; archived
  segments are re-verified by recomputation rather than by trusting a stored
  hash; and a severed or discontinuous history is detected and classified. If
  the chain is quarantined after tamper detection, **every** write path —
  including the built-in agent (`grith run`) — refuses to append; and records
  dropped under sustained overload leave a visible gap marker (with a count) in
  the chain rather than vanishing silently. Each record now carries its decision
  reason and enforcement outcome.

- **Verifiable daemon identity + fail-closed session tracking.** Each daemon
  instance carries a verifiable identity, so a supervised session cannot be
  silently adopted by a different instance; a supervisor whose daemon stops
  tracking its session fails closed and terminates after a grace period; and
  session capacity is reserved before the target is spawned.

- **Licence-signing key rotated.** The licence-signing keypair was rotated as
  pre-launch security hygiene. A Pro user whose licence was issued before the
  rotation should sign in again to receive a licence signed with the new key.

- **IPC-delegated authority: control-socket + authority-delegating-spawn
  detection (audit-only).** Connects to control-injection
  IPC sockets (tmux/screen panes, X11, the session D-Bus bus) now emit
  `event = "control_socket_connect"`, and spawns of authority-delegating
  binaries (docker/podman/kubectl/tmux/screen/systemctl/systemd-run/dbus-send/
  gdbus/busctl/at/crontab/flatpak/nsenter/machinectl/loginctl) emit
  `event = "authority_delegating_spawn"`. Both are **audit-only** (the
  operation is still allowed) to measure the false-positive budget before
  enforcing; ssh-agent/gpg-agent sockets are already routed through the proxy
  separately. This completes the IPC-delegated-authority mitigations
  (disclosure, detection, and host-escalation scoring); enforce modes are
  documented follow-ups.

- **IPC-delegated authority: PTY-ownership detection.** A write
  to a `/dev/pts/N` that is not the supervised tool's own controlling terminal
  (the `echo cmd > /dev/pts/<sibling-pane>` injection vector) is now detected
  and forensically logged (`event = "foreign_pts_write"`). Default is
  **audit-only** (the write is still allowed) to measure the false-positive
  budget; setting `supervisor.pty_ownership_enforce = true` denies it. The
  tool's own terminal I/O is unaffected; reads and non-pts paths are not
  flagged; an unresolvable controlling terminal fails open (no flag).

- **IPC-delegated authority: disclosure + container-escalation scoring.**
  Documented the structural limit of process-tree-scoped
  supervision in `SECURITY.md` ("Known Limitations" → IPC-delegated authority):
  actions the supervised tool *delegates* to a more-privileged peer (docker
  daemon, `tmux send-keys`, ssh-agent, D-Bus, X11) execute outside the
  supervised tree. As the first mitigation, the destructive-action filter now
  scores `docker`/`podman run`/`create` invocations that escalate to host
  authority — a writable bind-mount of a sensitive host path (`-v /etc:…:rw`),
  the docker control socket, `--privileged`, or `--pid=host` — and freezes them
  for review (the public Codex `docker run -v /etc:/host-etc:rw` escape).
  Benign container use (read-only/named-volume mounts, `docker build`/`ps`) is
  unaffected. Control-socket gating and PTY-ownership enforcement for the tmux
  vector are tracked as follow-ups.

- **Destructive-action coverage.** A new default-on
  `destructive-action` proxy filter brings the shipped ruleset in line
  with the destructive-action threat model. It **hard-denies** catastrophic
  host/storage destruction (filesystem format, raw block-device overwrite,
  signature wipe, `rm --no-preserve-root`, recursive removal of a system root or
  database data directory) and **escalates destructive operations directed at
  production** — managed-DB endpoints (`*.rds.amazonaws.com`,
  `*.sql.googleapis.com`, `*.database.windows.net`, `*.documents.azure.com`,
  `*.cache.amazonaws.com`, `*.redshift.amazonaws.com`) and `prod`/`production`/
  `live`-tagged resources — from QUEUE to DENY. Non-production destructive
  operations queue for review; scoped development operations (`rm -rf` of project
  directories, single-object staging deletes, read-only queries) are not flagged.
  Configurable via `[proxy.destructive_action] enabled` (default `true`). The
  pipeline is now 18 filters.

- **Dashboard token handoff no longer prints the secret.** The dashboard token
  was rendered in the `grith exec` TUI header and `dashboard status`, leaking
  the bearer secret into screenshots, screen-shares, and scrollback. The token
  is now handed to the browser out-of-band:
  - `server.auto_open_dashboard` (default true; `GRITH_AUTO_OPEN_DASHBOARD`;
    auto-skipped on headless/SSH) opens the browser on startup with the handoff
    in the URL fragment — never printed.
  - The fragment now carries a **single-use pairing code**, not the raw token.
    The SPA exchanges it at the loopback `POST /api/dashboard/pair` for the
    real token; the code is consumed on first use, so a later screenshot of the
    URL is inert. `grith dashboard pair` mints a fresh code to (re-)authorise a
    browser (new browser, cleared storage, second machine).
  - The persistent dashboard token still survives restarts, so a once-paired
    browser needs no re-pairing on a daemon restart.

- **Dashboard localhost auth & CSRF hardening.** The embedded dashboard
  HTTP/WS API was previously gated only by the loopback bind — any local
  process or browser tab that could reach `127.0.0.1:3141` could read audit
  data and drive mutating endpoints (approve queued calls, lower proxy
  thresholds, kill supervisor sessions). Five layered controls now close that:
  - Browser-facing mutations require a non-simple `x-grith-csrf` header,
    forcing a CORS preflight the locked-origin layer rejects for drive-by
    pages (no-body POSTs included).
  - A per-server `dashboard.token` (`~/.config/grith/dashboard.token`, `0600`,
    distinct from the daemon IPC token) is minted on every launch and
    constant-time-verified on writes; the open `/api/events` injection route
    was removed.
  - WebSocket handshakes (`/ws/live`, `/ws/supervisor/:id`) are origin-vs-host
    checked and token-gated.
  - Sensitive reads (audit list/detail/export, digest, canaries, config,
    analytics, policies, inventory, listener-rewrites, supervisor session
    detail) are gated on the dashboard token when one is configured; low-
    sensitivity status (`/health`, `/tier`, `/proxy/status`, `/license/status`,
    `/sync/status`) stays open for zero-config dev.

### Changed

- **Documentation accuracy pass.** In-repo docs reconciled with the current
  daemon: filter counts corrected to 18 everywhere, the secret-pattern count
  standardised to 1,620, a README feature bullet added for destructive-action
  coverage, and "Compliance-ready" softened to "designed to support compliance"
  with an explicit note that grith is not certified against any framework.
  (Audit-record sync to grith servers, and the `audit_sync = false` local-only
  option, were already documented honestly.)

- **BREAKING (dashboard API): mutating dashboard endpoints now require the
  per-server dashboard token by default, and sensitive reads require it too.**
  The CLI flows the token automatically — `grith dashboard start` /
  `grith run` print a `#token=…` launch URL the SPA captures into
  `localStorage`, so the interactive experience is unchanged. **Scripts that
  PO/PUT/DELETE against the dashboard API, or scrape audit/digest/config, must
  now send `x-grith-csrf: <token>`.** Same-UID scripts can read the token from
  `~/.config/grith/dashboard.token` (written by the background dashboard
  server). This is a deliberate default flip from the previous open-on-loopback
  posture; pre-1.0 so no SemVer-major bump, but operators scripting the open
  API must adapt.

### Added

- **Audit maintenance commands.** `grith audit diagnose` inspects the audit
  chain — verification status, forks, gaps, and quarantine state — and runs even
  when the chain is quarantined. `grith audit compact` reclaims disk space after
  a large prune (operator-invoked; it never runs on a timer). Local audit
  storage now bounds its physical footprint, keeping a recent active window plus
  a compressed cold archive rather than growing without limit.

- **Exfil-shape egress scoring.** Outbound requests are scored on the *shape* of
  what they carry — high-entropy or base64 bodies, oversized payloads, and
  body-bearing HTTP methods weighted above reads — combined with destination
  reputation and data-flow taint, plus a DNS-tunnelling signal. Routine browser
  and developer-tool egress is quieted so the added scrutiny does not raise the
  false-positive budget.

- **Signed releases + SBOMs.** The release workflow now publishes four
  supply-chain artefacts alongside each archive:
  - `<archive>.cosign.bundle` — Sigstore signature, keyless, anchored
    in the Rekor transparency log; signing identity bound to the
    GitHub-hosted release workflow + tag.
  - `<archive>.cdx.json` — CycloneDX 1.5 SBOM listing every
    transitive Rust dependency resolved at build time.
  - `<archive>.cdx.json.cosign.bundle` — signature over the SBOM.
  - `<archive>.intoto.bundle` — a SLSA v1 build-provenance attestation
    binding the archive to the workflow, source commit, and builder that
    produced it, signed with cosign (keyless, Rekor-anchored) and
    verifiable with `cosign verify-blob-attestation`.
  Verification recipes are documented in `docs/RELEASE.md`.

### Known limitations

- **Linux x86_64 only.** The supervisor relies on `ptrace` + `seccomp` with
  x86_64 syscall-argument extraction; no other target is built for this release.
- **32-bit tools under supervision fail closed.** A 32-bit (i386 / x32) tracee's
  syscalls are denied rather than interpreted — safe, but such tools are
  effectively unusable under `grith exec`. Run 64-bit builds under supervision.
- **Documented perimeter edge cases (low severity, no authority gain).** On
  kernels older than 5.3 the seccomp return-data path falls back (irrelevant on
  5.3+); sibling-thread path resolution carries an inherent time-of-check window
  intrinsic to path-string interception; relative-symlink base resolution and
  `openat2` ignoring `O_NOFOLLOW` are false-positive-only. None of these let a
  supervised tool acquire authority it would otherwise be denied.

## [0.1.4] - 2026-05-18

### Fixed

- `agent::tool_execution::FileAppend` now explicitly flushes the file
  before reporting success. The previous code relied on implicit
  close-on-drop to flush `tokio::fs::File`'s internal buffer, which
  races a fast reader on a stressed runtime. The race manifested as
  an intermittent test failure on the public CI runner
  (`grith-ai/grith`) for
  `execute_operation_file_append_rename_delete_dir_create` — the
  assertion read back an empty file immediately after a successful
  append. Same source passed consistently on the private CI and
  locally; the public-mirror runner happened to hit the timing
  window. The explicit `flush()` closes the race for all callers,
  not just tests.

## [0.1.3] - 2026-05-14

### Fixed

- The React dashboard is now baked into the binary at build time via
  `include_dir!` (same pattern as the embedded `config/` tree from v0.1.1).
  Previously `static_files.rs` read the dashboard from a runtime filesystem
  path (`dashboard/dist/`), which doesn't exist on a machine that
  installed grith via `install.sh` — so opening `http://localhost:3141`
  just showed the "Dashboard has not been built yet" placeholder. Release
  binaries now ship with the dashboard embedded so it works out of the
  box. A `dashboard_dir` config pointing at an existing on-disk `dist/`
  still wins, so dashboard development with hot reload is unaffected. A
  `crates/grith-server/build.rs` step seeds a placeholder
  `dashboard/dist/index.html` so `cargo build` works on a fresh checkout
  without first running `npm run build`.

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
