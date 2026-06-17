# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in grith, please report it responsibly. **Do not open a public issue.**

### Preferred: GitHub Private Vulnerability Reporting

Use GitHub's built-in private vulnerability reporting:

1. Go to [github.com/grith-ai/grith/security/advisories](https://github.com/grith-ai/grith/security/advisories)
2. Click **"Report a vulnerability"**
3. Fill in the details and submit

This keeps the report private until a fix is available.

### Alternative: Email

Email **security@grith.ai** with:

- A description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (what an attacker could achieve)

Encrypt sensitive reports with our PGP key (available at [grith.ai/.well-known/security.txt](https://grith.ai/.well-known/security.txt)).

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Depends on severity (see below) |
| Public disclosure | Coordinated with reporter |

## Severity Classification

| Severity | Description | Fix target |
|----------|-------------|------------|
| **Critical** | Remote code execution, privilege escalation, supervisor bypass allowing unrestricted syscall access | 48 hours |
| **High** | Data exfiltration past proxy filters, audit log tampering, secret exposure in API responses | 5 business days |
| **Medium** | Denial of service, information disclosure (non-secret), filter bypass for specific patterns | 15 business days |
| **Low** | Minor information leakage, UI issues, documentation errors with security implications | Next scheduled release |

## Scope

The following are in scope for security reports:

- **grith daemon** (all crates in `crates/`)
- **Security proxy filters** — bypass, false negatives, scoring manipulation
- **Supervisor** — ptrace/seccomp escape, process tree evasion, io_uring bypass
- **Audit system** — log tampering, chain integrity bypass, data loss
- **Digest queue** — unauthorized approval/denial, queue manipulation
- **API server** — authentication bypass, unauthorized access, injection
- **Provider key encryption** — key exposure, weak cryptography, nonce reuse
- **Canary tokens** — value leakage, detection bypass
- **Configuration** — privilege escalation via config manipulation

The following are **out of scope**:

- The grith.ai website (report to security@grith.ai separately)
- Third-party dependencies (report to their maintainers; we track via Dependabot)
- Social engineering attacks
- Denial of service via resource exhaustion on localhost (the server is localhost-only by default)

## Security Design Principles

grith is built on these security principles:

- **Fail closed** — proxy errors result in DENY, not ALLOW
- **Defence in depth** — 18 independent filters across 3 phases
- **Minimal privilege** — supervisor profiles restrict operations to declared allowlists
- **Auditable** — every tool call produces a tamper-evident audit record
- **No ambient authority** — supervised tools receive only the capabilities their profile grants

## Known Limitations

grith's supervisor enforces at the **syscall boundary of the supervised
process tree** (the tool and its `fork`/`clone`/`exec` descendants). This is a
deliberate, well-understood scope — and it has a corresponding structural
limit you should know about before relying on grith as an isolation boundary:

### IPC-delegated authority

When the supervised tool does not perform a privileged action itself but
instead **sends a message to a separate, more-privileged process that already
holds the authority**, the privileged action executes outside the supervised
tree and is not intercepted per-operation. Known instances:

- **Container runtimes.** `docker run -v /etc:/host-etc:rw …` (or
  `--privileged`, `--pid=host`, mounting `docker.sock`) performs the host
  write inside the **docker daemon** (root, never a supervised descendant).
- **Terminal multiplexers.** `tmux send-keys` / `screen -X` injects commands
  into a **pre-existing, less-restricted pane** running as a sibling shell.
- **Agent/desktop sockets.** Commands sent to `ssh-agent`, the session D-Bus
  bus, or the X11/Wayland socket are actioned by those peers with their own
  authority.

These require **pre-existing conditions** (the operator is in the `docker`
group, an unrestricted `tmux`/`screen` session is already attached, etc.) — an
agent in a clean environment cannot create them. grith **mitigates the known
vectors** rather than claiming full closure: the container control sockets are
treated as sensitive (their `connect(2)` routes through the proxy), and
`docker`/`podman run` invocations with a writable sensitive bind-mount, the
docker socket, `--privileged`, or `--pid=host` are scored and frozen for
review. Additional control-socket gating (tmux/screen/ssh-agent/X11/D-Bus) and
PTY-ownership enforcement are tracked in
`work/futurework/ipc-delegated-authority-escape.md`.

If you run a fully untrusted agent, do not treat grith as a substitute for an
OS-level sandbox (container / VM) for this class — grith's model is
observe-score-mediate within your real environment, not wall-based isolation.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older | No |

## Recognition

We credit security researchers who responsibly disclose vulnerabilities in our release notes and CHANGELOG (unless they prefer to remain anonymous). We do not currently operate a bug bounty program.

## Contact

- **Security reports:** security@grith.ai or [GitHub private reporting](https://github.com/grith-ai/grith/security/advisories)
- **General questions:** [GitHub Discussions](https://github.com/grith-ai/grith/discussions)
