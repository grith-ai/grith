// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Heuristic path-risk filter for sensitive filesystem locations.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};

/// Heuristic path-risk filter.
///
/// Unlike `path_match` (explicit TOML rules), this filter uses broad built-in
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
        "sensitive_path_heuristic"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Static
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        let path = match ctx.path() {
            Some(p) => p,
            None => return Ok(FilterResult::no_match(self.name())),
        };
        let op = match operation_for_call_type(&ctx.call_type) {
            Some(op) => op,
            None => return Ok(FilterResult::no_match(self.name())),
        };

        let path_lc = normalize_path_for_match(path);
        let file_name_lc = normalized_file_name(&path_lc);
        let destructive = matches!(op, "write" | "delete");
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
                hits.push(HeuristicHit {
                    rule_id: "credential-directory",
                    score: if destructive { 4.5 } else { 4.0 },
                    severity: Severity::Error,
                    message: format!("{op} access to credential directory"),
                });
                break;
            }
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

        // High-value browser credential and session filenames.  These are
        // meaningful wherever they appear, not just inside a browser profile.
        let browser_credential_file = matches!(
            file_name_lc.as_str(),
            // Chromium session and auth tokens
            "cookies"
            | "login data"
            | "web data"           // autofill + saved payment methods
            | "local state"        // master key used to decrypt saved passwords
            | "secure preferences" // security-sensitive Chrome prefs
            | "network persistent state"
            | "wallet"             // Chrome Web3 wallet
            // Firefox credential stores
            | "key4.db"            // Firefox password manager key
            | "cert9.db"           // Firefox/NSS certificate store (incl. private keys)
            | "cert8.db"           // Older Firefox cert store
            | "logins.json"        // Firefox saved logins
            | "signons.sqlite"     // Very old Firefox passwords
            | "signedinusers.json" // Firefox Accounts session tokens
        );

        if browser_profile_path || browser_credential_file {
            hits.push(HeuristicHit {
                rule_id: "browser-session-data",
                score: if destructive { 4.0 } else { 3.0 },
                severity: Severity::Warning,
                message: format!("{op} access to browser session/credential data"),
            });
        }

        // Key/certificate-like filenames.
        if file_name_lc.ends_with(".pem")
            || file_name_lc.ends_with(".key")
            || file_name_lc.ends_with(".p12")
            || file_name_lc.ends_with(".pfx")
            || matches!(
                file_name_lc.as_str(),
                "id_rsa" | "id_ed25519" | "id_dsa" | "id_ecdsa"
            )
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
        // PR 69 Change 5: the substring-token rule is the broadest
        // heuristic on the books — it catches any filename containing
        // "secret"/"credential"/"token"/"passwd"/"apikey"/"auth". Inside
        // a public npm dependency tree (`node_modules/`) those words
        // appear in legitimate library filenames (`tokenize.js`,
        // `tokenTypes.js`, etc.) and the heuristic mass-misfires.
        //
        // Carveout: suppress ONLY this rule when the path resolves to
        // something inside a `/node_modules/` component. Every other
        // rule above (.env, key/cert files, browser credential files,
        // OS secret stores, credential directories) is unaffected.
        //
        // Canonicalisation defeats the symlink-evasion
        // `~/.ssh/x → /tmp/proj/node_modules/x` because the canonical
        // destination of such a symlink is *outside* `node_modules/`,
        // so the matching key/cert / credential-dir rules still fire.
        // When canonicalisation fails (path doesn't exist yet) we fall
        // back to matching the raw normalized path — this is fail-safe
        // because the only thing the carveout does is suppress a score.
        // Carveouts (mirror `grith_supervisor::syscall_map::is_sensitive_path`):
        // suppress this weakest substring rule inside a dependency tree
        // (`node_modules/`) or for a programming-language source file — a class
        // named `AccessToken.php` / `OAuth2Client.ts` is code, not a credential.
        // The strong rules above (.env, key/cert files, credential dirs) are
        // unaffected and still fire regardless of extension.
        let in_node_modules = path_contains_node_modules(path);
        if !in_node_modules
            && !is_source_code_filename(&file_name_lc)
            && ["secret", "credential", "token", "passwd", "apikey", "auth"]
                .iter()
                .any(|kw| file_name_lc.contains(kw))
        {
            hits.push(HeuristicHit {
                rule_id: "secretish-filename",
                score: if destructive { 3.5 } else { 2.8 },
                severity: Severity::Warning,
                message: format!("{op} access to sensitive-looking filename"),
            });
        }

        let Some(best) = hits.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            return Ok(FilterResult::no_match(self.name()));
        };

        Ok(FilterResult::matched(
            self.name(),
            best.rule_id,
            best.score,
            best.severity,
            best.message,
        ))
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

/// PR 69 Change 5: returns true if the symlink-resolved canonical path
/// contains `/node_modules/` as a path component. Falls back to the raw
/// normalized path when canonicalisation fails (path doesn't exist yet),
/// which is fail-safe because the only effect is suppressing a heuristic
/// score; the other sensitive-path rules above still fire.
fn path_contains_node_modules(path: &str) -> bool {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        if let Some(s) = canonical.to_str() {
            return s.replace('\\', "/").contains("/node_modules/");
        }
    }
    normalize_path_for_match(path).contains("/node_modules/")
}

fn normalized_file_name(path_lc: &str) -> String {
    path_lc
        .split('/')
        .next_back()
        .unwrap_or_default()
        .to_string()
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
