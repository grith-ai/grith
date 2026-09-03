// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Heuristic path-risk filter for sensitive filesystem locations.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};

/// Heuristic path-risk filter.
///
/// Unlike `path-match` (explicit TOML rules), this filter uses broad built-in
/// heuristics to catch common sensitive targets without requiring an exhaustive
/// list of patterns.
pub struct SensitivePathHeuristicFilter;

impl SensitivePathHeuristicFilter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SensitivePathHeuristicFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct HeuristicHit {
    rule_id: &'static str,
    score: f64,
    severity: Severity,
    message: String,
}

/// FP §5.6: the genuinely-secret `/etc` paths that stay at the high tier. The
/// rest of `/etc` is world-readable application config (nginx, docker,
/// postgres, pip.conf, …) and benign to read. This is the guard for the
/// two-tier split — password hashes, sudoers, private keys, and keytabs must
/// never drop to the low tier. `path` is expected pre-lowercased.
fn is_sensitive_etc_path(path_lc: &str) -> bool {
    path_lc.contains("shadow")                       // /etc/shadow, /etc/gshadow, *-
        || path_lc.contains("/sudoers")              // /etc/sudoers, /etc/sudoers.d/
        || path_lc.contains("/private/")             // TLS/PKI private-key dirs
        || path_lc.contains("/ssl/private")          // /etc/ssl/private (dir itself)
        || path_lc.contains("/krb5.keytab")          // kerberos keytab
        || path_lc.contains("/security/opasswd")     // PAM old-password store
        || (path_lc.contains("/ssh/")                // SSH host PRIVATE keys
            && path_lc.contains("ssh_host")
            && path_lc.ends_with("_key"))
        // FP §5.6 review hardening: secret-bearing app configs that are NOT
        // generic world-readable config — kubeconfigs with embedded client
        // certs/keys, wifi PSKs, and service admin credentials. Without these,
        // the two-tier split dropped real secrets to the +0.5 low tier.
        || path_lc.contains("/kubernetes/")          // admin.conf / *.conf / pki
        || path_lc.contains("/rancher/")             // k3s / rke2 kubeconfigs
        || path_lc.contains("/wpa_supplicant")       // wifi PSK plaintext
        || path_lc.contains("/networkmanager/system-connections") // wifi PSK
        || path_lc.contains("/grafana/")             // admin_password / SMTP creds
        || path_lc.contains("/gitlab/")              // gitlab-secrets.json
        || path_lc.contains("/libvirt/")             // VNC / SASL credentials
        || path_lc.ends_with("/debian.cnf") // mysql debian-sys-maint pw
}

/// FP §5.5: a curated set of system commands an attacker would shadow by
/// dropping a trojaned binary of the same name earlier in `$PATH` (a PATH-hijack
/// for persistence / credential capture). A WRITE to a PATH directory
/// (`/usr/local/bin`, `~/.local/bin`, …) is flagged ONLY when its basename is
/// one of these — package managers install NEW binaries (`black`, `ruff`,
/// `tsc`, …) here constantly, and only a write that *collides with an existing
/// system command* is suspicious. Legitimate command replacements use distinct
/// names (`bat`/`eza`/`rg`), so collisions are almost always a hijack.
///
/// Curated (deterministic, no filesystem probe) rather than exhaustive: it
/// targets the high-value shells / coreutils / security / dev-runtime / package-
/// manager / network commands. Shadowing an obscure command not listed here is a
/// residual (documented).
const SHADOWABLE_SYSTEM_COMMANDS: &[&str] = &[
    // shells & privilege
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "env",
    "sudo",
    "su",
    "doas",
    "pkexec",
    // coreutils / common
    "ls",
    "cat",
    "cp",
    "mv",
    "rm",
    "ln",
    "mkdir",
    "chmod",
    "chown",
    "touch",
    "echo",
    "find",
    "grep",
    "egrep",
    "sed",
    "awk",
    "sort",
    "head",
    "tail",
    "cut",
    "tr",
    "tee",
    "xargs",
    "tar",
    "gzip",
    "ps",
    "kill",
    "mount",
    "umount",
    "dd",
    "less",
    "more",
    // security / credential
    "git",
    "ssh",
    "scp",
    "sftp",
    "ssh-add",
    "ssh-agent",
    "ssh-keygen",
    "gpg",
    "gpg2",
    "openssl",
    "passwd",
    "login",
    "sshd",
    "keychain",
    // dev runtimes & toolchains
    "python",
    "python2",
    "python3",
    "node",
    "ruby",
    "perl",
    "php",
    "go",
    "rustc",
    "java",
    "gcc",
    "cc",
    "clang",
    "ld",
    "make",
    // package managers
    "pip",
    "pip3",
    "npm",
    "npx",
    "yarn",
    "pnpm",
    "gem",
    "cargo",
    "go",
    "apt",
    "apt-get",
    "dpkg",
    "yum",
    "dnf",
    "rpm",
    "brew",
    "snap",
    "pacman",
    "pipx",
    // network / transfer
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "rsync",
    "ftp",
    // orchestration / service
    "docker",
    "podman",
    "kubectl",
    "systemctl",
    "service",
    "crontab",
    "at",
    "launchctl",
];

/// True when `basename` (lowercased) collides with a curated system command —
/// i.e. writing it into a PATH directory would shadow a trusted command.
fn shadows_system_command(basename: &str) -> bool {
    SHADOWABLE_SYSTEM_COMMANDS.contains(&basename)
}

/// True when `path_lc` is inside a directory on the typical executable `$PATH`,
/// where a write installs/replaces a runnable command.
fn is_path_executable_dir(path_lc: &str) -> bool {
    path_lc.starts_with("/usr/bin/")
        || path_lc.starts_with("/bin/")
        || path_lc.starts_with("/usr/local/bin/")
        || path_lc.starts_with("/usr/sbin/")
        || path_lc.starts_with("/sbin/")
        || path_lc.starts_with("/usr/local/sbin/")
        || path_lc.contains("/.local/bin/")
}

/// Score for a WRITE/DELETE to the NSS shared cert store (A#4). Sub-threshold
/// (below 3.0 QUEUE) so a routine browser rewrite doesn't prompt, but non-zero
/// and `matched = true` so a CA-store change is recorded and nudges the
/// composite when other risk is present.
const NSS_CERT_STORE_CHANGE_SCORE: f64 = 1.5;

/// True for the NSS *shared* certificate DB (`~/.pki/nssdb/…`) — an app cert
/// store (chrome/curl/NSS), distinct from a user credential directory. Firefox's
/// per-profile `cert9.db`/`key4.db` live under `~/.mozilla/firefox/…`, not here,
/// so they are unaffected.
fn is_nss_shared_db_path(path_lc: &str) -> bool {
    path_lc.contains("/.pki/nssdb/")
}

/// True for another process's `environ`/`mem` under `/proc`
/// (`/proc/<numeric-pid>/{environ,mem}`). The caller's own `/proc/self/*` and
/// `/proc/thread-self/*` are benign. `path` is expected pre-lowercased.
fn proc_cross_process_secret(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/proc/") else {
        return false;
    };
    if rest.starts_with("self/") || rest.starts_with("thread-self/") {
        return false;
    }
    let mut parts = rest.splitn(2, '/');
    let pid = parts.next().unwrap_or("");
    let sub = parts.next().unwrap_or("");
    !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) && (sub == "environ" || sub == "mem")
}

#[async_trait::async_trait]
impl SecurityFilter for SensitivePathHeuristicFilter {
    fn name(&self) -> &str {
        "sensitive-path-heuristic"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        // Every path the call touches is judged, and the worst verdict wins.
        // Link creation carries two: the target it exposes (a read of that
        // data becomes possible) and the name being created (a write lands
        // there). Judging only the target would price
        // `ln -s ./mine ~/.ssh/authorized_keys` below the equivalent write,
        // making a link the cheap way to plant one.
        // This filter deliberately covers a narrower set of call types than
        // the rule-driven one; anything outside it is left alone.
        // A FilesystemMutation (mount/move_mount/...) only reaches the proxy
        // when the supervisor's `category2_proxy` coverage flag is enabled
        // (default OFF; event_handler's PR-6 category gate allow+returns it
        // otherwise). Under that opt-in, score the mount SOURCE through the
        // same rules a direct read would hit, so a bind whose source is a
        // credential directory (~/.ssh, ~/.aws, ~/.gnupg, ~/.config/grith)
        // escalates regardless of the benign target basename — closing the
        // bind-mount path-aliasing hole where later reads land on the
        // un-sensitive target path.
        if let ToolCallType::FilesystemMutation { source, target, .. } = &ctx.call_type {
            return Ok(self.evaluate_filesystem_mutation(source.as_deref(), target));
        }

        let handled = operation_for_call_type(&ctx.call_type).is_some()
            || matches!(ctx.call_type, ToolCallType::FileLink { .. });
        if !handled {
            return Ok(FilterResult::no_match(self.name()));
        }
        // Creating a directory grants no access to credential CONTENT — the
        // directory is empty, and whatever is written into it is scored on the
        // write. So the weakest rule, which keys purely on the name, has
        // nothing to say about a `mkdir`. Measured: `mkdir api/auth`,
        // `mkdir packages/auth-core`, `mkdir public/blog/codex-credential-
        // sweep-syscall-trace` were 39 of the 105 prompts that survived the
        // rest of work/83.
        //
        // A credential DIRECTORY is `credential-directory`'s job, not this
        // rule's, and that rule is unaffected here. Only `secretish-filename`
        // is dropped; every other rule still scores a `mkdir` normally.
        //
        // `dir_create` is also what separates the two halves of the generic
        // browser-name rule below (work/83 finding 4): `mkdir` needs location
        // evidence, a WRITE or DELETE of the same name does not.
        let dir_create = matches!(ctx.call_type, ToolCallType::DirCreate { .. });
        let suppress_name_token_rule = dir_create;

        let mut worst: Option<FilterResult> = None;
        for (path, op) in path_operations(&ctx.call_type) {
            let result = self.evaluate_path(path, op, dir_create);
            if suppress_name_token_rule && result.rule_id == "secretish-filename" {
                continue;
            }
            let better = match &worst {
                Some(current) => result.score > current.score,
                None => true,
            };
            if result.matched && better {
                worst = Some(result);
            }
        }
        Ok(worst.unwrap_or_else(|| FilterResult::no_match(self.name())))
    }
}

impl SensitivePathHeuristicFilter {
    fn evaluate_path(&self, path: &str, op: &'static str, dir_create: bool) -> FilterResult {
        let path_lc = normalize_path_for_match(path);
        let file_name_lc = normalized_file_name(&path_lc);
        // Case-preserving basename: `paths::name_has_sensitive_token` treats a
        // camelCase transition as a token boundary, which a lowercased name
        // cannot express (`AccessToken.bin` -> `access` + `token`). Borrowed,
        // not allocated — this runs on every scored file operation.
        let file_name = path.rsplit(['/', '\\']).next().unwrap_or(path);
        let destructive = matches!(op, "write" | "delete");
        // Enumerating a directory yields the NAMES it contains and nothing
        // else — the kernel will not read file content through a directory
        // fd. That is reconnaissance, not credential access, and the read of
        // any file the listing reveals is scored in full when it happens.
        let enumerate = op == "list";

        // A#4: `~/.pki/nssdb` is the NSS *shared* certificate DB — an app cert
        // store that chrome/curl/other NSS consumers read and atomically rewrite
        // (cert9.db / key4.db / pkcs11.txt(.txu)) on every launch. It is NOT a
        // user credential directory like `~/.ssh`. A READ is routine startup
        // noise and is not flagged. A WRITE/DELETE is routed to a dedicated,
        // sub-threshold CA-store-change signal: recorded and auditable (a write
        // could inject a trusted CA) but not a standalone QUEUE, because the
        // routine atomic rewrite is indistinguishable from injection by path
        // alone. This deliberately does NOT touch `~/.ssh`/`~/.aws`/`~/.gnupg`
        // (still full credential-directory) nor a Firefox-*profile* cert9.db/
        // key4.db (the password-manager key, still flagged via the browser path).
        if is_nss_shared_db_path(&path_lc) {
            if destructive {
                return FilterResult::matched(
                    "sensitive-path-heuristic",
                    "nss-cert-store-change",
                    NSS_CERT_STORE_CHANGE_SCORE,
                    Severity::Notice,
                    format!("{op} to the NSS shared certificate store (~/.pki/nssdb)"),
                );
            }
            return FilterResult::no_match("sensitive-path-heuristic");
        }

        let ssh_metadata_read = op == "read"
            && matches!(
                file_name_lc.as_str(),
                "config" | "known_hosts" | "known_hosts2"
            )
            && path_lc.contains("/.ssh/");

        let mut hits = Vec::new();

        // System configuration and kernel interfaces.
        //
        // FP §5.6: two-tier. Genuinely-secret /etc paths (password hashes,
        // sudoers, private keys, keytabs — `is_sensitive_etc_path`) keep the
        // original high score. Generic world-readable app-configs (/etc/nginx,
        // /etc/docker/daemon.json, /etc/postgresql, /etc/pip.conf, …) are benign
        // to READ — drop those to a low signal so routine service-config
        // inspection on the LLM path (which has no is_noise_path fast-path)
        // doesn't QUEUE. A WRITE to any /etc path is still a system modification
        // and stays elevated.
        if path_lc.starts_with("/etc/") {
            if is_sensitive_etc_path(&path_lc) {
                hits.push(HeuristicHit {
                    rule_id: "system-etc-path",
                    score: if destructive { 4.0 } else { 3.0 },
                    severity: if destructive {
                        Severity::Error
                    } else {
                        Severity::Warning
                    },
                    message: format!("{op} access to sensitive system config path"),
                });
            } else if destructive {
                hits.push(HeuristicHit {
                    rule_id: "system-etc-write",
                    score: 3.0,
                    severity: Severity::Warning,
                    message: format!("{op} modifies a system config path"),
                });
            } else {
                hits.push(HeuristicHit {
                    rule_id: "system-etc-config-read",
                    score: 0.5,
                    severity: Severity::Notice,
                    message: format!("{op} reads a system config path"),
                });
            }
        }

        if path_lc.contains("/windows/system32/config/sam")
            || path_lc.contains("/windows/system32/config/security")
            || path_lc.contains("/windows/system32/config/system")
            || path_lc.contains("/etc/krb5.keytab")
            || path_lc.contains("/var/lib/sss/")
            || path_lc.contains("/library/keychains/")
            || path_lc.contains("/system/library/keychains/")
            || path_lc.contains("/appdata/microsoft/credentials/")
            || path_lc.contains("/appdata/microsoft/crypto/rsa/")
        {
            hits.push(HeuristicHit {
                rule_id: "os-secret-store",
                score: if destructive { 5.0 } else { 4.2 },
                severity: Severity::Critical,
                message: format!("{op} access to OS credential store"),
            });
        }

        // Another process's environment/memory under /proc leaks that process's
        // secrets (env vars, in-memory keys). Score above QUEUE, distinct from a
        // generic kernel-interface path. (Research doc §5.1 #1.) The caller's
        // own /proc/self/* is benign and handled by the generic branch below.
        if proc_cross_process_secret(&path_lc) {
            hits.push(HeuristicHit {
                rule_id: "cross-process-memory",
                score: 4.5,
                severity: Severity::Error,
                message: format!("{op} access to another process's environment/memory"),
            });
        } else if path_lc.starts_with("/proc/") || path_lc.starts_with("/sys/") {
            hits.push(HeuristicHit {
                rule_id: "kernel-interface-path",
                score: if destructive { 4.0 } else { 2.5 },
                severity: Severity::Warning,
                message: format!("{op} access to kernel interface path"),
            });
        }

        // Credential-bearing directories.
        for marker in [
            "/.ssh/",
            "/.gnupg/",
            "/.pki/",
            "/.aws/",
            "/.azure/",
            "/.kube/",
            "/.docker/",
            "/.config/gcloud/",
            "/appdata/gcloud/",
            "/appdata/gnupg/",
            "/appdata/roaming/gnupg/",
        ] {
            if path_lc.contains(marker) {
                if marker == "/.ssh/" && ssh_metadata_read {
                    break;
                }
                // A listing is priced far below a read, and deliberately
                // below the escalation band, so it is recorded and can still
                // push a composite over the line alongside another signal
                // without ever prompting on its own.
                //
                // Measured 2026-09-02: `find /home/dan -type d -name sqlglot`
                // opened every credential directory on the machine. Each one
                // scored 4.0 here, queued, and froze the tracee for the full
                // 300s review timeout — 41 prompts in one session, every one
                // of them auto-denied on timeout, and the searches silently
                // returned incomplete results.
                let (score, severity) = if destructive {
                    (4.5, Severity::Error)
                } else if enumerate {
                    (0.5, Severity::Warning)
                } else {
                    (4.0, Severity::Error)
                };
                hits.push(HeuristicHit {
                    rule_id: if enumerate {
                        "credential-directory-listing"
                    } else {
                        "credential-directory"
                    },
                    score,
                    severity,
                    message: if enumerate {
                        "listed the names in a credential directory".to_string()
                    } else {
                        format!("{op} access to credential directory")
                    },
                });
                break;
            }
        }

        // grith's own state directory — config, learned rules, reputation, and
        // the daemon/dashboard IPC tokens + credentials all live under
        // ~/.config/grith. A SUPERVISED tool has no legitimate reason to read
        // or modify it; doing so would let it steal the IPC token (→ call any
        // daemon IPC endpoint, e.g. poison the reputation table) or read the
        // cloud credentials / licence. The daemon reads these from the untraced
        // parent process, so only a tracee is flagged here. Mirrors
        // grith_supervisor::syscall_map::is_sensitive_path, which already
        // exempts this path from read-only noise suppression so it reaches this
        // filter — this closes the scoring gap that let the read evaluate low.
        if path_lc.contains("/.config/grith/") || path_lc.contains("/config/grith/") {
            hits.push(HeuristicHit {
                rule_id: "grith-self-access",
                score: if destructive { 5.0 } else { 4.5 },
                severity: Severity::Error,
                message: format!("{op} access to grith's own state directory"),
            });
        }

        // Control / autostart paths: any file here is a persistence or control
        // entry regardless of name — always sensitive.
        if path_lc.contains("/var/run/docker.sock")
            || path_lc.contains("/etc/systemd/")
            || path_lc.starts_with("/boot/")
            // User-level persistence the /etc/systemd/ match missed (§5.1 #4):
            // user systemd units/timers, XDG autostart, and cron in any form.
            || path_lc.contains("/.config/systemd/")
            || path_lc.contains("/.config/autostart/")
            || path_lc.contains("/etc/cron")
            || path_lc.starts_with("/system/")
            || path_lc.contains("/library/launchdaemons/")
            || path_lc.contains("/programdata/microsoft/windows/start menu/programs/startup/")
        {
            hits.push(HeuristicHit {
                rule_id: "persistence-or-control-path",
                score: if destructive { 4.0 } else { 3.0 },
                severity: Severity::Warning,
                message: format!("{op} access to persistence/control path"),
            });
        }

        // PATH directories (/usr/bin, /usr/local/bin, ~/.local/bin, …): a WRITE
        // is a PATH-hijack ONLY when the basename SHADOWS an existing system
        // command (FP §5.5). Package managers install NEW binaries here
        // routinely (`pip install --user black`, `cargo install`, `npm i -g`),
        // and those must not be flagged — only a write colliding with a trusted
        // command name (`~/.local/bin/git`, `/usr/local/bin/curl`) is a hijack.
        if destructive && is_path_executable_dir(&path_lc) && shadows_system_command(&file_name_lc)
        {
            hits.push(HeuristicHit {
                rule_id: "path-shadow-write",
                score: 4.0,
                severity: Severity::Error,
                message: format!("{op} writes a binary shadowing system command '{file_name_lc}'"),
            });
        }

        // Browser profile directories — path match covers directory listings and
        // any file within the profile regardless of name.  Filename match below
        // catches the same high-value files even when accessed by absolute path
        // outside the expected directory (e.g., a copy or backup).
        let browser_profile_path = path_lc.contains("/google/chrome/user data/")
            || path_lc.contains("/microsoft/edge/user data/")
            || path_lc.contains("/mozilla/firefox/")
            // Linux Chromium-family browsers
            || path_lc.contains("/.config/chromium/")
            || path_lc.contains("/.config/google-chrome/")
            || path_lc.contains("/.config/microsoft-edge/")
            || path_lc.contains("/.config/brave/")
            || path_lc.contains("/.config/vivaldi/")
            || path_lc.contains("/.config/opera/")
            || path_lc.contains("/snap/chromium/")
            // macOS Chromium-family browsers
            || path_lc.contains("/library/application support/google/chrome/")
            || path_lc.contains("/library/application support/chromium/")
            || path_lc.contains("/library/application support/microsoft edge/")
            || path_lc.contains("/library/application support/brave browser/")
            || path_lc.contains("/library/application support/vivaldi/")
            // Windows Chromium paths (non-UWP)
            || path_lc.contains("/appdata/local/google/chrome/")
            || path_lc.contains("/appdata/local/microsoft/edge/");

        // DISTINCTIVE browser credential filenames: multi-word or
        // product-specific names that essentially never occur by accident.
        // These keep firing wherever they appear — a `Login Data` or `key4.db`
        // copied out of a profile into `~/Downloads` is exactly the shape this
        // rule exists to catch, and the copy is the interesting event.
        let distinctive_browser_credential_file = matches!(
            file_name_lc.as_str(),
            "login data"
                | "secure preferences" // security-sensitive Chrome prefs
                | "key4.db"            // Firefox password manager key
                | "cert9.db"           // Firefox/NSS cert store (incl. private keys)
                | "cert8.db"           // Older Firefox cert store
                | "logins.json"        // Firefox saved logins
                | "signons.sqlite"     // Very old Firefox passwords
                | "signedinusers.json" // Firefox Accounts session tokens
        );

        // GENERIC names (work/83 M8): each is an ordinary English word or word
        // pair that occurs constantly as a project or package directory. The
        // npm package `cookies` — a dependency of Koa, Next.js and much of the
        // Node ecosystem — made `mkdir node_modules/cookies` score +4.0
        // (destructive) and prompt. `wallet`, `web data`, `local state` and
        // `network persistent state` have the same problem.
        //
        // A READ or a `mkdir` requires LOCATION evidence: a known browser
        // profile root, or a sibling Chromium marker file in the same directory
        // (which is what a copied-out profile directory looks like).
        //
        // A WRITE or DELETE does not, and requiring it there was a regression
        // (work/83 finding 4). A freshly COPIED-OUT `Cookies` has neither a
        // profile path nor siblings yet — the copy IS the interesting event, and
        // it is the one that leaves no other trace: `is_sensitive_path` has
        // never covered browser profile paths, so the READ half of a copy-out
        // chain is noise-suppressed at the supervisor, and requiring context on
        // the write half left the whole chain producing zero scored events.
        // `mkdir` keeps the requirement because the recorded false positive was
        // `mkdir node_modules/cookies` (the npm package `cookies`, a Koa/Next
        // dependency), and an empty directory grants no access to content.
        //
        // Never inside a dependency tree or a generated-output tree, on any
        // operation.
        let copy_out_or_removal = destructive && !dir_create;
        let generic_browser_credential_file = matches!(
            file_name_lc.as_str(),
            "cookies" | "web data" | "local state" | "network persistent state" | "wallet"
        ) && !crate::paths::is_name_opaque_tree(path)
            && (browser_profile_path || copy_out_or_removal || has_sibling_chromium_marker(path));

        // A named credential file scores above the allow boundary; an ordinary
        // file that merely lives in a profile directory does not.
        //
        // `route_decision` routes on `score > allow_threshold` and `FileRead`
        // carries a 0.0 operation-risk baseline, so a read whose only signal
        // was this rule at 3.0 landed on exactly 3.0 and was ALLOWED — the
        // browser cookie jar and saved-password store, the classic
        // session-hijack targets, were readable without a prompt. Nothing
        // compensated: content scanning never sees file bytes on a read, only
        // syscall arguments.
        //
        // 3.5 is deliberately scoped to the credential FILES. Leaving the
        // plain profile-path hit at 3.0 keeps a tool that legitimately drives
        // a real Chrome profile (it reads hundreds of ordinary files there)
        // from being flooded.
        let credential_file_hit =
            distinctive_browser_credential_file || generic_browser_credential_file;
        if browser_profile_path || credential_file_hit {
            hits.push(HeuristicHit {
                rule_id: "browser-session-data",
                score: match (destructive, credential_file_hit) {
                    (true, _) => 4.0,
                    (false, true) => 3.5,
                    (false, false) => 3.0,
                },
                severity: Severity::Warning,
                message: format!("{op} access to browser session/credential data"),
            });
        }

        // Key/certificate-like filenames.
        //
        // work/83 F2.1 anchored `path_match`'s `*.pem` / `*.key` to the
        // BASENAME instead of a whole-path `contains`, which is correct — but
        // the loose form was the only thing scoring `server.pem.bak`, and this
        // rule's `ends_with` never covered it either. A backed-up or rotated
        // private key is the same private key, and nothing else scores it:
        // the taint filter's source list carries no `.pem`/`.key` entry, so a
        // read of one registers no taint. One CLOSED backup suffix is stripped
        // before the extension test (see `strip_backup_suffix`) so the
        // coverage the anchoring removed is restored precisely, without
        // reopening the `/p/.pem-notes/a.js` false positive that the anchoring
        // fixed.
        let key_name = crate::paths::strip_backup_suffix(&file_name_lc);
        if key_name.ends_with(".pem")
            || key_name.ends_with(".key")
            || key_name.ends_with(".p12")
            || key_name.ends_with(".pfx")
            || matches!(key_name, "id_rsa" | "id_ed25519" | "id_dsa" | "id_ecdsa")
        {
            hits.push(HeuristicHit {
                rule_id: "key-material-file",
                score: if destructive { 5.0 } else { 4.0 },
                severity: Severity::Error,
                message: format!("{op} access to key/certificate file"),
            });
        }

        // Common secret-bearing file names.
        //
        // FP §5.7: committed template scaffolding (`.env.example` / `.sample` /
        // `.template` / `.dist` / `.defaults`) holds placeholder values, not
        // secrets, and is read constantly during project setup. Carve those
        // suffixes out. Deliberately NOT carved (Open Question #7 guard):
        // `.env.local` / `.development` / `.production` / `.test` routinely hold
        // REAL secrets, so they stay sensitive — a broader template carveout
        // that swept them in would be a protection hole.
        const ENV_TEMPLATE_SUFFIXES: &[&str] =
            &["example", "sample", "template", "dist", "defaults"];
        let is_env_template = file_name_lc
            .strip_prefix(".env.")
            .is_some_and(|suffix| ENV_TEMPLATE_SUFFIXES.contains(&suffix));
        if (file_name_lc == ".env" || file_name_lc.starts_with(".env.")) && !is_env_template {
            hits.push(HeuristicHit {
                rule_id: "env-file-heuristic",
                score: if destructive { 3.5 } else { 3.0 },
                severity: Severity::Warning,
                message: format!("{op} access to environment file"),
            });
        }
        // A STRUCTURED credential file — the filename's whole shape is a
        // credential-store convention (`secrets.yaml`, `credentials.json`,
        // `service-account-credentials.json`), not an incidental word.
        //
        // This exists because the two de-weightings work/83 applied to the
        // weak filename signal COMPOSED: `path_match`'s `*secrets*` went
        // 3.0 -> 1.5 *and* a `-1.5` meta-rule subtracted again, landing a
        // READ of `/proj/deploy/secrets.yaml` on 2.80 — and `route_decision`
        // routes on `score > allow_threshold`, so 2.80 is ALLOWED. A
        // Kubernetes Secret manifest and a GCP service-account key were
        // readable with no prompt and nothing compensated: content scanning
        // never sees file bytes on a read, only syscall arguments.
        //
        // The fix separates the classes rather than re-tuning one weight.
        // `bin/with-secrets` (the recorded false positive) keeps the weak
        // 2.8 and stays allowed; a credential FILE gets its own hit here.
        // Because `evaluate_path` returns the MAXIMUM hit, this replaces
        // `secretish-filename` instead of summing with it — the duplicated
        // filename evidence is removed structurally, which is why the two
        // `*-filename-single-signal` meta-rules and the two weak
        // `path_match` globs could be deleted outright.
        //
        // Not gated by the dependency-tree / generated-output carveout, for
        // the same reason `.env` and `*.pem` are not: a real credential store
        // planted under `node_modules/` must still score. The cost is a
        // vendored test fixture literally named `credentials.json`.
        if crate::paths::is_structured_credential_filename(&file_name_lc) {
            hits.push(HeuristicHit {
                rule_id: "credential-file-shape",
                score: if destructive { 4.0 } else { 3.5 },
                severity: Severity::Error,
                message: format!("{op} access to a credential file"),
            });
        }

        // The weakest rule on the books: a filename that merely *looks*
        // credential-ish. work/83 M1 — it was a raw `contains` over
        // ["secret","credential","token","passwd","apikey","auth"], which
        // matched `authority`, `authorize`, `AUTHORS`, every documentation
        // page about tokens, and every rustc incremental hash that happened to
        // end in "auth" (`773v9mxq3ohs6twiwt1rzauth.o`). 831 of one morning's
        // 1,986 supervisor prompts came from this one rule.
        //
        // Four narrowings, each with its compensating control named:
        //
        //  1. WHOLE-TOKEN matching (`paths::name_has_sensitive_token`). The
        //     name is attacker-chosen and never load-bearing: a real
        //     credential store is identified by `credential-directory`,
        //     `key-material-file`, `env-file-heuristic`, `os-secret-store`,
        //     the path-match rules and `is_credential_store_path` — all
        //     path/extension-based, none of them relying on this rule.
        //  2. Source-code extensions (unchanged, PR 69): `AccessToken.php` is
        //     a class, not a credential.
        //  3. Documentation / assets / build artifacts
        //     (`is_non_credential_artifact_filename`) and numbered or
        //     migrations-rooted SQL (`is_migration_sql_filename`). A credential
        //     pasted into `notes.md` or an `.svg` is still caught by
        //     `secret_scan`'s 1,620 CONTENT patterns and by `dlp_gate` on
        //     egress — neither consults this rule.
        //  4. Dependency trees, widened from `node_modules/` to every vendored
        //     root (`paths::is_dependency_tree_path`). A package chooses its
        //     own filenames, so the name carries no authority there;
        //     content/flow/egress/destruction/volume filters are untouched
        //     inside a dependency tree.
        //
        // The SCORES are deliberately unchanged (read 2.8, write/delete 3.5).
        // work/83 F1.3 proposed dropping the write score to 2.5 so the rule
        // could not QUEUE alone; that is wrong, because `route_decision`
        // (scoring.rs) routes on `score > allow_threshold`, so a composite of
        // exactly 3.0 ALLOWS. At 2.5 a credential write lands on 2.5 + 0.5 =
        // 3.0 and is auto-allowed — silently demoting `auth.json`,
        // `secrets.yaml` and `service-account-credentials.json` writes from
        // QUEUE to ALLOW. The four carveouts above already remove every
        // recorded false positive without touching the score, so the drop
        // bought nothing and cost a real detection.
        //
        // `file_name` (case preserved) rather than `file_name_lc` is passed to
        // the token check: camelCase is a token boundary, so `AccessToken.bin`
        // still splits into `access` + `token`.
        //
        // Condition order is deliberate: the pure-string tests run first and
        // `is_dependency_tree_path` last, because that one can issue a
        // `realpath(3)` and every other condition is cheaper. During an
        // `npm install` burst almost every path is inside a dependency tree,
        // so testing it first would have paid for a syscall on every write.
        if crate::paths::name_has_sensitive_token(file_name)
            && !is_source_code_filename(&file_name_lc)
            && !crate::paths::is_non_credential_artifact_filename(&file_name_lc)
            && !crate::paths::is_migration_sql_filename(&file_name_lc, &path_lc)
            && !crate::paths::is_name_opaque_tree(path)
        {
            hits.push(HeuristicHit {
                rule_id: "secretish-filename",
                score: if destructive { 3.5 } else { 2.8 },
                severity: Severity::Warning,
                message: format!("{op} access to sensitive-looking filename"),
            });
        }

        let Some(best) = hits.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            return FilterResult::no_match(self.name());
        };

        FilterResult::matched(
            self.name(),
            best.rule_id,
            best.score,
            best.severity,
            best.message,
        )
    }

    /// Score a `FilesystemMutation` by its SOURCE (a bind re-exposes the source
    /// under the target) and its TARGET (a mount over a persistence/control
    /// path is itself suspicious). Worst verdict wins, mirroring `evaluate`'s
    /// multi-path handling.
    ///
    /// The source is judged twice: as written (so a file source like
    /// `~/.aws/credentials` trips the filename/key rules) and with a trailing
    /// `/` (so a *directory* source like `~/.ssh` — the usual bind shape, which
    /// canonicalises WITHOUT a trailing slash — matches the credential-DIRECTORY
    /// markers that key on `"/.ssh/"`). Appending the slash only for the mount
    /// source keeps this directory-aware match scoped to FilesystemMutation, so
    /// ordinary FileRead/DirList of a bare `~/.ssh` directory (default-path
    /// traffic) is UNAFFECTED.
    fn evaluate_filesystem_mutation(&self, source: Option<&str>, target: &str) -> FilterResult {
        let mut candidates: Vec<(String, &'static str)> = Vec::new();
        if let Some(src) = source {
            candidates.push((src.to_string(), "read"));
            if !src.ends_with('/') {
                candidates.push((format!("{src}/"), "read"));
            }
        }
        candidates.push((target.to_string(), "write"));

        let mut worst: Option<FilterResult> = None;
        for (path, op) in candidates {
            let result = self.evaluate_path(&path, op, false);
            let better = match &worst {
                Some(current) => result.score > current.score,
                None => true,
            };
            if result.matched && better {
                worst = Some(result);
            }
        }
        worst.unwrap_or_else(|| FilterResult::no_match(self.name()))
    }
}

fn normalize_path_for_match(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

/// True when `file_name_lc` (already lowercased) ends in a programming-language
/// source extension — a code module, not a credential file. Suppresses the
/// weakest substring-keyword rule (`secretish-filename`). Config / data / script
/// / key extensions are deliberately excluded — those genuinely hold secrets.
/// Kept in sync with `grith_supervisor::syscall_map::is_source_code_filename`.
fn is_source_code_filename(file_name_lc: &str) -> bool {
    const SOURCE_EXTS: &[&str] = &[
        ".php", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".py", ".pyi", ".rb", ".go",
        ".rs", ".java", ".kt", ".kts", ".scala", ".cs", ".fs", ".c", ".h", ".cc", ".cpp", ".cxx",
        ".hpp", ".hh", ".hxx", ".swift", ".m", ".mm", ".dart", ".lua", ".ex", ".exs", ".erl",
        ".clj", ".cljs", ".hs", ".ml", ".mli", ".pl", ".pm", ".groovy", ".jl", ".nim", ".zig",
        ".d", ".pas",
    ];
    SOURCE_EXTS.iter().any(|ext| file_name_lc.ends_with(ext))
}

/// work/83 F8: does the directory holding `path` look like a copied-out
/// Chromium profile?
///
/// The markers are files Chromium always writes into a profile directory and
/// that are NOT themselves in the generic-name list, so this can never be
/// circular. Probed only when a generic name matched outside a known profile
/// root — a rare path, so the filesystem hit is not on the hot path.
fn has_sibling_chromium_marker(path: &str) -> bool {
    const MARKERS: &[&str] = &[
        "Login Data",
        "Preferences",
        "Secure Preferences",
        "History",
        "Bookmarks",
        "Favicons",
        "Top Sites",
    ];
    let Some(dir) = std::path::Path::new(path).parent() else {
        return false;
    };
    MARKERS.iter().any(|m| dir.join(m).exists())
}

fn normalized_file_name(path_lc: &str) -> String {
    path_lc
        .split('/')
        .next_back()
        .unwrap_or_default()
        .to_string()
}

/// Every (path, operation) pair a call subjects to path policy.
///
/// Most calls have exactly one. Two calls create a NEW entry at a
/// destination and so must judge both ends, or the destination slips in
/// under the price of the (often benign) source:
///
/// - **Link creation** — the `target` becomes readable through a new name,
///   and a new entry is `written` at the `link_path`. Scoring only the
///   target would let `ln -s ./mine ~/.ssh/authorized_keys` through
///   (go-live review B2).
/// - **Rename** — the same shape via `rename(2)`: `mv ./mine
///   ~/.ssh/authorized_keys` plants a file at a sensitive destination while
///   the scored `old_path` is a harmless project file. Score the
///   destination as a write too.
pub(crate) fn path_operations(call_type: &ToolCallType) -> Vec<(&str, &'static str)> {
    match call_type {
        ToolCallType::FileLink {
            target, link_path, ..
        } => vec![(target.as_str(), "read"), (link_path.as_str(), "write")],
        ToolCallType::FileRename { old_path, new_path } => {
            vec![(old_path.as_str(), "write"), (new_path.as_str(), "write")]
        }
        other => match path_of(other) {
            Some(path) => vec![(
                path,
                crate::filters::path_match::operation_for_call_type(other),
            )],
            None => Vec::new(),
        },
    }
}

/// The single primary path of a non-link call.
fn path_of(call_type: &ToolCallType) -> Option<&str> {
    match call_type {
        ToolCallType::FileRead { path }
        | ToolCallType::FileWrite { path, .. }
        | ToolCallType::FileAppend { path }
        | ToolCallType::FileDelete { path }
        | ToolCallType::DirList { path }
        | ToolCallType::FileChmod { path, .. }
        | ToolCallType::DirCreate { path } => Some(path),
        ToolCallType::FileRename { old_path, .. } => Some(old_path),
        ToolCallType::OwnershipChange { target, .. }
        | ToolCallType::FilesystemMutation { target, .. } => Some(target),
        _ => None,
    }
}

fn operation_for_call_type(call_type: &ToolCallType) -> Option<&'static str> {
    match call_type {
        ToolCallType::FileRead { .. } => Some("read"),
        ToolCallType::FileWrite { .. } => Some("write"),
        ToolCallType::FileAppend { .. } => Some("write"),
        ToolCallType::FileDelete { .. } => Some("delete"),
        ToolCallType::DirList { .. } => Some("list"),
        ToolCallType::FileRename { .. } => Some("write"),
        ToolCallType::FileChmod { .. } => Some("write"),
        ToolCallType::DirCreate { .. } => Some("write"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    fn mount(source: Option<&str>, target: &str, fstype: Option<&str>) -> ToolCallType {
        ToolCallType::FilesystemMutation {
            op: "mount".into(),
            source: source.map(str::to_string),
            target: target.to_string(),
            fstype: fstype.map(str::to_string),
        }
    }

    /// fix #6: a bind of a bare ~/.ssh directory (canonicalises WITHOUT a
    /// trailing slash) over a benign target escalates via the trailing-slash
    /// source candidate — the credential-directory rule keys on "/.ssh/".
    #[tokio::test]
    async fn bind_mount_credential_dir_source_escalates() {
        let filter = SensitivePathHeuristicFilter::new();
        let result = filter
            .evaluate(&make_ctx(mount(Some("/home/dev/.ssh"), "/tmp/x", None)))
            .await
            .unwrap();
        assert!(result.matched, "credential-dir bind source should match");
        assert!(
            result.score >= 4.0,
            "score {} must be elevated",
            result.score
        );
    }

    /// Walking past a credential directory is not reading one.
    ///
    /// These are the exact paths that flooded a supervised session on
    /// 2026-09-02: `find /home/dan -type d -name sqlglot` opened each of them
    /// with `O_DIRECTORY`, every one scored 4.0, queued, and froze the tracee
    /// for the full 300s review timeout. Each must now sit below the
    /// 3.0 auto-allow threshold so a traversal never prompts.
    #[tokio::test]
    async fn listing_a_credential_directory_stays_below_the_escalation_band() {
        let filter = SensitivePathHeuristicFilter::new();
        for path in [
            "/home/dan/.gnupg/private-keys-v1.d",
            "/home/dan/.pki/nssdb",
            "/home/dan/.aws/login",
            "/home/dan/.ssh/config.d",
            "/home/dan/.docker/buildx",
        ] {
            let result = filter
                .evaluate(&make_ctx(ToolCallType::DirList {
                    path: path.to_string(),
                }))
                .await
                .unwrap();
            assert!(
                result.score < 3.0,
                "listing {path} scored {} — a traversal must not prompt",
                result.score
            );
            if result.matched {
                assert_eq!(result.rule_id, "credential-directory-listing");
            }
        }
    }

    /// The downgrade is scoped to enumeration. Reading a file that lives in
    /// the same directory is the act the rule exists for and is untouched.
    #[tokio::test]
    async fn reading_inside_a_credential_directory_is_unchanged() {
        let filter = SensitivePathHeuristicFilter::new();
        for path in [
            "/home/dan/.aws/credentials",
            "/home/dan/.gnupg/private-keys-v1.d/ABCDEF.key",
            "/home/dan/.docker/config.json",
        ] {
            let result = filter
                .evaluate(&make_ctx(ToolCallType::FileRead {
                    path: path.to_string(),
                }))
                .await
                .unwrap();
            assert!(
                result.matched && result.score >= 4.0,
                "reading {path} scored {} ({}) — a credential read must still escalate",
                result.score,
                result.rule_id
            );
        }
    }

    /// A listing is recorded rather than dropped, so it can still combine
    /// with other evidence and stays visible in the audit log.
    #[tokio::test]
    async fn a_credential_directory_listing_is_still_recorded() {
        let filter = SensitivePathHeuristicFilter::new();
        let result = filter
            .evaluate(&make_ctx(ToolCallType::DirList {
                path: "/home/dan/.gnupg/private-keys-v1.d".to_string(),
            }))
            .await
            .unwrap();
        assert!(result.matched, "the listing must not be silently dropped");
        assert!(result.score > 0.0, "a dropped signal cannot combine");
    }

    /// Deleting inside a credential directory is destructive, not a listing,
    /// and keeps the higher score.
    #[tokio::test]
    async fn deleting_in_a_credential_directory_is_unchanged() {
        let filter = SensitivePathHeuristicFilter::new();
        let result = filter
            .evaluate(&make_ctx(ToolCallType::FileDelete {
                path: "/home/dan/.ssh/id_rsa".to_string(),
            }))
            .await
            .unwrap();
        assert!(result.matched && result.score >= 4.5, "{result:?}");
    }

    /// A file-shaped credential source is scored via the as-written candidate.
    #[tokio::test]
    async fn bind_mount_credential_file_source_matches() {
        let filter = SensitivePathHeuristicFilter::new();
        let result = filter
            .evaluate(&make_ctx(mount(
                Some("/home/dev/.aws/credentials"),
                "/mnt/x",
                None,
            )))
            .await
            .unwrap();
        assert!(result.matched);
    }

    /// A benign source and a source-less tmpfs mount add nothing (stay at
    /// operation_risk's flat +5.0) — no NEW false positive in the opt-in path.
    #[tokio::test]
    async fn benign_mount_source_and_tmpfs_do_not_match() {
        let filter = SensitivePathHeuristicFilter::new();
        assert!(
            !filter
                .evaluate(&make_ctx(mount(Some("/data/project"), "/mnt/x", None)))
                .await
                .unwrap()
                .matched
        );
        assert!(
            !filter
                .evaluate(&make_ctx(mount(None, "/tmp/build", Some("tmpfs"))))
                .await
                .unwrap()
                .matched
        );
    }

    // FP §5.6: two-tier /etc. A generic world-readable app-config READ is a
    // low signal (well below QUEUE); a genuinely-secret /etc path stays high;
    // a WRITE to any /etc path stays elevated.
    #[tokio::test]
    async fn etc_generic_read_is_low_tier_secret_stays_high_write_elevated() {
        let filter = SensitivePathHeuristicFilter::new();

        // Generic world-readable config read → low tier, below QUEUE (3.0).
        for p in ["/etc/hosts", "/etc/nginx/nginx.conf", "/etc/pip.conf"] {
            let result = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: p.into() }))
                .await
                .unwrap();
            assert_eq!(result.rule_id, "system-etc-config-read", "{p}");
            assert!(
                result.score < 3.0,
                "{p} score {} must be < QUEUE",
                result.score
            );
        }

        // Guard: shadow/sudoers/host-private-key stay on the high /etc tier
        // (these paths are owned by the system-etc-path rule).
        for p in [
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/ssh_host_ed25519_key",
        ] {
            let result = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: p.into() }))
                .await
                .unwrap();
            assert_eq!(result.rule_id, "system-etc-path", "{p} must stay high tier");
            assert!(
                result.score >= 3.0,
                "{p} score {} must stay >= QUEUE",
                result.score
            );
        }

        // Guard: a TLS private key under /etc stays high even though a
        // more-specific rule (key-material-file) claims it — the invariant is
        // "still >= QUEUE", not which rule fires.
        let result = filter
            .evaluate(&make_ctx(ToolCallType::FileRead {
                path: "/etc/ssl/private/server.key".into(),
            }))
            .await
            .unwrap();
        assert!(
            result.score >= 3.0,
            "/etc/ssl/private/server.key score {} must stay >= QUEUE (rule {})",
            result.score,
            result.rule_id
        );

        // Guard: a WRITE to a generic /etc config is a system modification and
        // stays elevated (the FP fix is read-only).
        let result = filter
            .evaluate(&make_ctx(ToolCallType::FileWrite {
                path: "/etc/nginx/nginx.conf".into(),
                content_hash: String::new(),
            }))
            .await
            .unwrap();
        assert_eq!(result.rule_id, "system-etc-write");
        assert!(result.score >= 3.0);
    }

    #[tokio::test]
    async fn test_ssh_key_is_high_risk() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dev/.ssh/id_rsa".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(result.score >= 4.0);
    }

    /// A rename must judge its DESTINATION, not only the source: `mv
    /// ./benign ~/.ssh/authorized_keys` plants an SSH key while `old_path`
    /// is a harmless project file. The rename twin of the `ln -s ... ~/.ssh`
    /// hole (work/80 scenario D, surfaced on a real box).
    #[tokio::test]
    async fn test_rename_into_credential_dir_scores_destination() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRename {
            old_path: "/home/dev/project/payload".into(),
            new_path: "/home/dev/.ssh/authorized_keys".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            result.matched && result.score >= 3.0,
            "rename into ~/.ssh must escalate on the destination (score {}, rule {})",
            result.score,
            result.rule_id
        );
    }

    /// The control: an ordinary rename between two benign paths stays quiet.
    #[tokio::test]
    async fn test_rename_between_benign_paths_no_match() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRename {
            old_path: "/home/dev/project/a.txt".into(),
            new_path: "/home/dev/project/b.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched,
            "benign rename must not flag (rule {})",
            result.rule_id
        );
    }

    #[tokio::test]
    async fn test_grith_own_state_dir_is_high_risk() {
        // A supervised tool reading grith's own IPC token would let it call any
        // daemon IPC endpoint (e.g. poison the reputation table). Must QUEUE.
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dev/.config/grith/daemon.token".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(
            result.score >= 3.0,
            "grith token read score {} must reach QUEUE (rule {})",
            result.score,
            result.rule_id
        );
    }

    #[tokio::test]
    async fn test_ssh_config_read_is_not_flagged_by_heuristic() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dev/.ssh/config".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_known_hosts_read_is_not_flagged_by_heuristic() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dev/.ssh/known_hosts".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_env_file_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/workspace/app/.env.production".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "env-file-heuristic");
        assert!((result.score - 3.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_non_sensitive_path_no_match() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/workspace/src/main.rs".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    #[tokio::test]
    async fn test_windows_path_normalization_and_ssh_match() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: r"C:\Users\dan\.ssh\id_ed25519".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(result.score >= 4.0);
    }

    #[tokio::test]
    async fn test_macos_keychain_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/Users/dan/Library/Keychains/login.keychain-db".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "os-secret-store");
    }

    #[tokio::test]
    async fn test_windows_sam_hive_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: r"C:\Windows\System32\config\SAM".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "os-secret-store");
        assert!(result.score >= 4.0);
    }

    /// PR 69 Change 5: substring-token rule must not fire on legitimate
    /// npm dependency filenames. These two paths were the exact files
    /// queued during the codex audit (session 7f256630-…, 2026-05-25).
    #[tokio::test]
    async fn test_node_modules_tokenize_js_does_not_fire_secretish_filename() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/u/.nvm/versions/node/v22.22.2/lib/node_modules/npm/\
                   node_modules/postcss-selector-parser/dist/tokenize.js"
                .into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(
            !result.matched,
            "node_modules tokenize.js must not trip secretish-filename"
        );
    }

    #[tokio::test]
    async fn test_node_modules_token_types_does_not_fire_secretish_filename() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/u/proj/node_modules/some-lib/dist/tokenTypes.js".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
    }

    /// Source files whose name contains a credential word (`AccessToken.php`,
    /// `OAuth2Client.ts`) are code, not credential stores — the secretish-
    /// filename rule must not fire. Mirrors the supervisor's
    /// `is_sensitive_path` source-extension carveout.
    #[tokio::test]
    async fn test_source_files_with_credential_words_do_not_fire_secretish() {
        let filter = SensitivePathHeuristicFilter::new();
        for path in [
            "/proj/vendor/league/oauth2-client/src/Token/AccessToken.php",
            "/proj/src/auth/OAuth2Client.ts",
            "/proj/internal/token/Token.go",
        ] {
            let ctx = make_ctx(ToolCallType::FileRead { path: path.into() });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(
                !result.matched,
                "source file must not trip secretish: {path}"
            );
        }
    }

    /// The carveout is extension-scoped: a credential-ish NON-source filename
    /// still trips the rule.
    #[tokio::test]
    async fn test_non_source_secretish_filename_still_fires() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/proj/config/api_token.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "secretish-filename");
    }

    /// PR 69 Change 5: other sensitive rules still fire on files inside
    /// `node_modules/`. Only the substring-token rule is suppressed.
    #[tokio::test]
    async fn test_node_modules_env_file_still_fires() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/u/proj/node_modules/some-lib/.env".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched, ".env inside node_modules still flagged");
        assert_eq!(result.rule_id, "env-file-heuristic");
    }

    #[tokio::test]
    async fn test_node_modules_key_file_still_fires() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/u/proj/node_modules/some-lib/id_rsa".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched, "id_rsa inside node_modules still flagged");
    }

    /// PR 69 Change 5: decoy substring `node_modules_*` (not a real
    /// path component) does not inherit the carveout.
    #[tokio::test]
    async fn test_node_modules_decoy_substring_does_not_grant_carveout() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/u/proj/node_modules_decoy/auth.txt".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "secretish-filename");
    }

    #[tokio::test]
    async fn test_browser_cookie_store_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.config/google-chrome/Default/Cookies".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_linux_brave_profile_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.config/brave/Default/Login Data".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_linux_chromium_snap_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/snap/chromium/current/.config/chromium/Default/Cookies".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    // ---- A#4: NSS shared cert store (~/.pki/nssdb) ----

    /// A READ of the browser's own NSS shared cert store is routine startup
    /// noise — not flagged (was previously credential-directory / browser data).
    #[tokio::test]
    async fn test_nssdb_read_is_noise() {
        let filter = SensitivePathHeuristicFilter::new();
        for name in ["cert9.db", "key4.db", "pkcs11.txt", "pkcs11.txu"] {
            let ctx = make_ctx(ToolCallType::FileRead {
                path: format!("/home/dan/.pki/nssdb/{name}"),
            });
            let result = filter.evaluate(&ctx).await.unwrap();
            assert!(
                !result.matched,
                "nssdb read of {name} should be noise, got {}",
                result.rule_id
            );
        }
    }

    /// A WRITE/DELETE to the NSS store routes to a dedicated, sub-threshold
    /// CA-store-change signal: recorded but not a standalone QUEUE.
    #[tokio::test]
    async fn test_nssdb_write_is_sub_threshold_ca_change() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileWrite {
            path: "/home/dan/.pki/nssdb/cert9.db".into(),
            content_hash: "abc".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "nss-cert-store-change");
        assert!(
            result.score < 3.0,
            "must not QUEUE alone, got {}",
            result.score
        );

        let del = make_ctx(ToolCallType::FileDelete {
            path: "/home/dan/.pki/nssdb/pkcs11.txt".into(),
        });
        let r2 = filter.evaluate(&del).await.unwrap();
        assert_eq!(r2.rule_id, "nss-cert-store-change");
    }

    /// A Firefox *profile* cert9.db (the password-manager key) is NOT under
    /// ~/.pki/nssdb and stays flagged as browser session/credential data.
    #[tokio::test]
    async fn test_firefox_profile_cert9_still_flagged() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.mozilla/firefox/abc123.default/cert9.db".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    /// The carve-out is nssdb-specific: ~/.ssh is still a full credential dir.
    #[tokio::test]
    async fn test_ssh_dir_unaffected_by_nssdb_carveout() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.ssh/id_rsa".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert!(result.score >= 3.0);
    }

    #[tokio::test]
    async fn test_macos_chrome_profile_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/Users/dan/Library/Application Support/Google/Chrome/Default/Cookies".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_firefox_logins_json_detected() {
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.mozilla/firefox/abc123.default/logins.json".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_firefox_key4_db_detected_by_filename() {
        // key4.db is high-value wherever it appears, not just in profile dirs.
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/tmp/backup/key4.db".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }

    /// work/83 M1: the recorded false positives. Each of these produced a
    /// modal prompt from `secretish-filename` alone.
    #[tokio::test]
    async fn recorded_keyword_false_positives_no_longer_fire() {
        let filter = SensitivePathHeuristicFilter::new();
        let cases = [
            // Token boundaries: "authority" / "authorize" / a base36 hash.
            ToolCallType::FileWrite {
                path: "/p/web/public/hero-zero-ambient-authority-1600x900.svg".into(),
                content_hash: String::new(),
            },
            ToolCallType::FileRead {
                path: "/p/src/app/api/device/authorize/route.ts".into(),
            },
            ToolCallType::FileRead {
                path: "/p/target/debug/incremental/773v9mxq3ohs6twiwt1rzauth.o".into(),
            },
            ToolCallType::FileRead {
                path: "/p/target/debug/incremental/debug_secretscan-32x74bbezc6gl".into(),
            },
            // Documentation carveout.
            ToolCallType::FileWrite {
                path: "/p/docs/concepts/canary-tokens.mdx".into(),
                content_hash: String::new(),
            },
            ToolCallType::FileWrite {
                path: "/p/docs/pro/authentication.mdx".into(),
                content_hash: String::new(),
            },
            // Numbered schema migration.
            ToolCallType::FileWrite {
                path: "/p/packages/db/migrations/0016_better_auth_admin_two_factor.sql".into(),
                content_hash: String::new(),
            },
            // Dependency tree, widened past node_modules/.
            ToolCallType::FileWrite {
                path: "/p/node_modules/aws-sdk/lib/credentials/sso_credentials.js".into(),
                content_hash: String::new(),
            },
            ToolCallType::FileWrite {
                path: "/p/vendor/github.com/aws/credentials/provider.go".into(),
                content_hash: String::new(),
            },
        ];
        for call in cases {
            let result = filter.evaluate(&make_ctx(call.clone())).await.unwrap();
            assert!(
                !result.matched || result.rule_id != "secretish-filename",
                "{call:?} must not fire secretish-filename (got {})",
                result.rule_id
            );
        }
    }

    /// The rule must still fire on the shapes it exists for, at the scores it
    /// has always had. A WRITE must stay ABOVE the 3.0 allow boundary on its
    /// own: `route_decision` routes on `score > allow_threshold`, so 3.5 + the
    /// +0.5 write baseline = 4.0 QUEUEs, while the 2.5 that work/83 F1.3
    /// proposed would have landed on exactly 3.0 and been ALLOWED.
    #[tokio::test]
    async fn secretish_filename_still_fires_and_a_credential_write_still_queues() {
        let filter = SensitivePathHeuristicFilter::new();
        for path in [
            "/p/config/api_token.txt",
            "/p/auth.json",
            "/p/bin/with-secrets",
            "/p/downloads/AccessToken.bin",
            "/p/backups/secrets_dump.sql",
        ] {
            let read = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: path.into() }))
                .await
                .unwrap();
            assert!(read.matched, "{path} must still fire on read");
            assert_eq!(read.rule_id, "secretish-filename", "{path}");
            assert_eq!(read.score, 2.8, "{path} read score");

            let write = filter
                .evaluate(&make_ctx(ToolCallType::FileWrite {
                    path: path.into(),
                    content_hash: String::new(),
                }))
                .await
                .unwrap();
            assert_eq!(write.rule_id, "secretish-filename", "{path}");
            assert_eq!(write.score, 3.5, "{path} write score");
            assert!(
                write.score + 0.5 > 3.0,
                "{path}: rule score plus the +0.5 write baseline must exceed the \
                 allow boundary — routing is `> allow_threshold`, so exactly 3.0 allows"
            );
        }
    }

    /// work/83 finding 1: a STRUCTURED credential filename is a different,
    /// stronger class than an incidental credential-ish word, and it is priced
    /// exactly once.
    ///
    /// The regression this pins: `path_match`'s weak `*secrets*` glob was
    /// de-weighted 3.0 -> 1.5 AND a `-1.5` meta-rule subtracted again, so a
    /// READ of `secrets.yaml` composed to 2.80 — and `route_decision` routes on
    /// `score > allow_threshold`, so 2.80 ALLOWS. Nothing compensated: content
    /// scanning never sees file bytes on a read, only syscall arguments.
    #[tokio::test]
    async fn structured_credential_filenames_outrank_the_weak_name_rule() {
        let filter = SensitivePathHeuristicFilter::new();
        for path in [
            "/p/deploy/secrets.yaml",
            "/p/deploy/secrets.yml",
            "/p/deploy/secrets.json",
            "/p/config/credentials.json",
            "/p/service-account-credentials.json",
            "/p/gcp_credentials.json",
        ] {
            let read = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: path.into() }))
                .await
                .unwrap();
            assert_eq!(read.rule_id, "credential-file-shape", "{path}");
            // A READ carries a 0.0 operation-risk baseline, so this rule alone
            // has to clear the boundary — and `> 3.0` is the real bar.
            assert!(read.score > 3.0, "{path}: read score {}", read.score);

            let write = filter
                .evaluate(&make_ctx(ToolCallType::FileWrite {
                    path: path.into(),
                    content_hash: String::new(),
                }))
                .await
                .unwrap();
            assert_eq!(write.rule_id, "credential-file-shape", "{path}");
            assert!(write.score > 3.0, "{path}: write score {}", write.score);
        }

        // Incidental names keep the weak rule and stay below the boundary on a
        // read — `bin/with-secrets` is the recorded false positive and must not
        // come back.
        for path in ["/p/apps/web/bin/with-secrets", "/p/my-secrets.txt"] {
            let read = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: path.into() }))
                .await
                .unwrap();
            assert_eq!(read.rule_id, "secretish-filename", "{path}");
            assert!(read.score <= 3.0, "{path}: read score {}", read.score);
        }
    }

    /// work/83 M8: `mkdir node_modules/cookies` (the npm package `cookies`, a
    /// Koa/Next dependency) scored +4.0 and prompted. Generic browser names
    /// need location evidence on a READ or a `mkdir`; distinctive ones still
    /// fire anywhere.
    #[tokio::test]
    async fn generic_browser_names_need_location_evidence() {
        let filter = SensitivePathHeuristicFilter::new();
        for path in [
            "/p/node_modules/cookies",
            "/p/src/wallet",
            "/p/build/local state",
        ] {
            let result = filter
                .evaluate(&make_ctx(ToolCallType::DirCreate { path: path.into() }))
                .await
                .unwrap();
            assert!(
                !result.matched || result.rule_id != "browser-session-data",
                "{path} must not fire browser-session-data"
            );
        }

        // work/83 finding 4: a freshly COPIED-OUT generic name has neither a
        // profile path nor Chromium siblings yet, so requiring location
        // evidence on a WRITE or DELETE silenced the whole copy-out chain —
        // `is_sensitive_path` has never covered browser profile paths, so the
        // READ half is already noise-suppressed at the supervisor.
        for path in [
            "/home/dan/Downloads/Cookies",
            "/home/dan/Downloads/Web Data",
            "/home/dan/wallet",
        ] {
            for call in [
                ToolCallType::FileWrite {
                    path: path.into(),
                    content_hash: String::new(),
                },
                ToolCallType::FileDelete { path: path.into() },
            ] {
                let result = filter.evaluate(&make_ctx(call)).await.unwrap();
                assert_eq!(result.rule_id, "browser-session-data", "{path}");
                assert!(result.score >= 4.0, "{path}: score {}", result.score);
            }
            // The read half keeps the location requirement.
            let read = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: path.into() }))
                .await
                .unwrap();
            assert!(
                !read.matched || read.rule_id != "browser-session-data",
                "{path}: a READ still needs location evidence"
            );
        }
        // The dependency / generated-output carveout still holds on a write —
        // npm unpacking `node_modules/koa/lib/cookies` must stay silent.
        for path in ["/p/node_modules/koa/lib/cookies", "/p/dist/wallet"] {
            let result = filter
                .evaluate(&make_ctx(ToolCallType::FileWrite {
                    path: path.into(),
                    content_hash: String::new(),
                }))
                .await
                .unwrap();
            assert!(
                !result.matched || result.rule_id != "browser-session-data",
                "{path} must stay carved on a write"
            );
        }

        // Distinctive names keep firing outside a profile — a `Login Data` or
        // `key4.db` sitting in ~/Downloads is a copied credential store.
        for path in [
            "/home/dan/Downloads/Login Data",
            "/home/dan/Downloads/key4.db",
            "/home/dan/Downloads/logins.json",
        ] {
            let result = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: path.into() }))
                .await
                .unwrap();
            assert!(result.matched, "{path} must fire");
            assert_eq!(result.rule_id, "browser-session-data", "{path}");
        }
    }

    /// work/83 F2.1 fallout: anchoring `path_match`'s `*.pem` / `*.key` to the
    /// basename removed the only rule that scored a backed-up private key.
    /// `key-material-file` now strips one closed backup suffix, so the
    /// coverage is restored here rather than by re-loosening the glob.
    #[tokio::test]
    async fn backed_up_key_material_is_still_key_material() {
        let filter = SensitivePathHeuristicFilter::new();
        for path in [
            "/p/certs/server.pem.bak",
            "/p/certs/tls.key.old",
            "/p/certs/server.pem~",
            "/p/certs/store.p12.save",
            "/p/keys/id_rsa.orig",
        ] {
            let read = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: path.into() }))
                .await
                .unwrap();
            assert!(read.matched, "{path} must still be key material");
            assert_eq!(read.rule_id, "key-material-file", "{path}");
            assert_eq!(read.score, 4.0, "{path}");
        }
        // The suffix list is closed: an ordinary compound source name whose
        // last suffix is NOT a backup marker keeps scoring nothing, which is
        // what stops this from re-opening the false positive the anchoring
        // fixed.
        for path in ["/p/src/i18n.key.ts", "/p/src/schema.pem.rs", "/p/notes.bak"] {
            let read = filter
                .evaluate(&make_ctx(ToolCallType::FileRead { path: path.into() }))
                .await
                .unwrap();
            assert!(
                !read.matched || read.rule_id != "key-material-file",
                "{path} must not be key material (got {})",
                read.rule_id
            );
        }
    }

    /// A generic name recovers its score when the directory looks like a
    /// copied-out Chromium profile (a sibling marker file is present).
    #[tokio::test]
    async fn generic_browser_name_fires_next_to_a_chromium_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cookies = dir.path().join("Cookies");
        std::fs::write(&cookies, b"x").expect("write Cookies");

        let filter = SensitivePathHeuristicFilter::new();
        let call = |p: &std::path::Path| {
            make_ctx(ToolCallType::FileRead {
                path: p.to_string_lossy().into_owned(),
            })
        };

        // No marker yet: not enough evidence.
        let before = filter.evaluate(&call(&cookies)).await.unwrap();
        assert!(
            !before.matched || before.rule_id != "browser-session-data",
            "a lone Cookies file is not enough evidence"
        );

        std::fs::write(dir.path().join("Login Data"), b"x").expect("write marker");
        let after = filter.evaluate(&call(&cookies)).await.unwrap();
        assert!(
            after.matched,
            "sibling Chromium marker must restore the rule"
        );
        assert_eq!(after.rule_id, "browser-session-data");
    }

    #[tokio::test]
    async fn test_chrome_local_state_detected_by_filename() {
        // "local state" contains the master key for decrypting saved passwords.
        let filter = SensitivePathHeuristicFilter::new();
        let ctx = make_ctx(ToolCallType::FileRead {
            path: "/home/dan/.config/google-chrome/Local State".into(),
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(result.matched);
        assert_eq!(result.rule_id, "browser-session-data");
    }
}
