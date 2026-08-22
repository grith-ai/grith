// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Command-family identity for authority-delegating spawn approvals.
//!
//! An approved delegating spawn sticks for the session under its **exact**
//! argv (`delegating_approval_key`), so `flatpak run foo` never covers
//! `flatpak run bar`. That is the right default — but for docker it produced
//! a measured prompt flood: one session on 2026-08-21 answered 14 prompts
//! for the same `docker compose exec -T web php -r '…'` differing only in
//! the PHP payload, and two more for `logs --tail=8` vs `--tail=25`. The
//! argv varies; the *authority* does not.
//!
//! This module derives a **family key** for the curated argv shapes where
//! "the same authority" can be stated precisely, so one approval covers the
//! family for the session:
//!
//!   * an in-container `exec` is keyed on the service/container name and the
//!     flags that change what the payload may do (`--user`, `--privileged`),
//!     with the payload itself wildcarded — the container boundary, not the
//!     argv, is what bounds a payload's host authority;
//!   * read-only observers (`ps`, `logs`, `version`, …) are keyed on their
//!     positionals with display flags dropped;
//!   * compose lifecycle verbs (`up`, `restart`, …) are keyed on the target
//!     services with orchestration flags dropped — their authority is the
//!     project's compose file either way.
//!
//! # Curation policy (security-team review required)
//!
//! Every rule here trades one prompt for a session-wide grant, so the table
//! errs closed at every layer:
//!
//!   * an unrecognised binary, subcommand, or **flag** yields `None` — the
//!     approval falls back to exact-argv matching, never to a guess. A flag
//!     we have not classified might carry authority (`docker compose exec
//!     --privileged` would, had it not been keep-listed), so unknown flags
//!     do not get dropped, they get the whole call exact-matched;
//!   * `docker run` / `create` / `cp` / `buildx` and everything else that
//!     mints new authority through its flags (mounts, privilege, host file
//!     transfer) is deliberately absent: for those the flags ARE the
//!     identity, and exact matching is the only honest key;
//!   * flags that select *which daemon or project* is being driven
//!     (`--host`, `--context`, compose `--file`/`--project-name`/…) are part
//!     of the family key, value included — the same verb against a different
//!     daemon is a different authority;
//!   * family keys are only ever consulted for calls the delegating
//!     enforcement already queued once: this narrows re-prompting, it never
//!     bypasses the first human decision.

/// A derived command family: the session key and the operator-facing label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SpawnFamily {
    /// Stable identity token, unique per (binary, daemon/project selectors,
    /// subcommand, authority flags, positional targets).
    pub key: String,
    /// Human-readable coverage statement for the approval prompt.
    pub label: String,
}

/// What a recognised flag does to the family identity.
#[derive(Clone, Copy)]
enum FlagRule {
    /// Identity-bearing: kept in the key, value included.
    KeepWithValue,
    /// Identity-bearing boolean: kept in the key.
    Keep,
    /// Volatile display/orchestration parameter with a value: dropped.
    DropWithValue,
    /// Volatile boolean: dropped.
    Drop,
}

/// Look up `flag` (already stripped of any `=value` suffix) in a curated
/// table. Returns the flag's CANONICAL spelling (the first alias) plus its
/// rule, so `-u root` and `--user root` key identically. `None` means
/// unclassified — the caller must give up on the family.
fn classify<'t>(table: &[(&'t [&'t str], FlagRule)], flag: &str) -> Option<(&'t str, FlagRule)> {
    table
        .iter()
        .find(|(aliases, _)| aliases.contains(&flag))
        .map(|(aliases, rule)| (aliases[0], *rule))
}

/// Derive the command family for an authority-delegating spawn, if the argv
/// matches a curated shape. `args` is the raw argv (argv0 included when the
/// tracee passed one).
pub(super) fn spawn_family(command: &str, args: &[String]) -> Option<SpawnFamily> {
    let bin = basename(command);
    // Skip argv0 when it restates the binary (the common execve shape).
    let rest = args
        .first()
        .filter(|a| basename(a) == bin)
        .map_or(args, |_| &args[1..]);

    match bin {
        "docker" => docker_family(rest),
        // The compose CLI plugin execs as its own binary with `compose`
        // restated as the first real token. Same daemon, same compose
        // project, same grammar — so it shares `docker compose` keys, and an
        // approval covers the verb however docker chose to invoke it.
        "docker-compose" => {
            let rest = rest
                .first()
                .filter(|a| a.as_str() == "compose")
                .map_or(rest, |_| &rest[1..]);
            let inner = compose_family(rest)?;
            Some(SpawnFamily {
                key: format!("docker {}", inner.key),
                label: inner.label,
            })
        }
        _ => None,
    }
}

/// `docker [global flags] <subcommand …>`.
fn docker_family(args: &[String]) -> Option<SpawnFamily> {
    // Global docker flags. Daemon selection is identity; verbosity is not.
    const GLOBALS: &[(&[&str], FlagRule)] = &[
        (&["--host", "-H"], FlagRule::KeepWithValue),
        (&["--context"], FlagRule::KeepWithValue),
        (&["--config"], FlagRule::KeepWithValue),
        (&["--log-level", "-l"], FlagRule::DropWithValue),
        (&["--debug", "-D"], FlagRule::Drop),
    ];
    let (mut kept, rest) = take_flags(args, GLOBALS)?;
    let (sub, rest) = rest.split_first()?;
    match sub.as_str() {
        "compose" => {
            let inner = compose_family(rest)?;
            let selectors = if kept.is_empty() {
                String::new()
            } else {
                format!(" {}", kept.join(" "))
            };
            Some(SpawnFamily {
                key: format!("docker{selectors} {}", inner.key),
                label: inner.label,
            })
        }
        // Plain-docker observers and the container-scoped exec share the
        // compose grammar closely enough to reuse its verb table.
        "exec" => exec_family("docker exec", "container", &mut kept, rest),
        "ps" | "version" | "info" | "images" | "top" | "port" | "stats" | "logs" | "context" => {
            observer_family("docker", sub, &kept, rest)
        }
        _ => None,
    }
}

/// `compose [compose flags] <verb …>` — with the leading `docker` (and any
/// kept global selectors) added by the caller.
fn compose_family(args: &[String]) -> Option<SpawnFamily> {
    // Compose project selection is identity: the same verb against another
    // compose file is another authority.
    const COMPOSE_GLOBALS: &[(&[&str], FlagRule)] = &[
        (&["--file", "-f"], FlagRule::KeepWithValue),
        (&["--project-name", "-p"], FlagRule::KeepWithValue),
        (&["--project-directory"], FlagRule::KeepWithValue),
        (&["--env-file"], FlagRule::KeepWithValue),
        (&["--profile"], FlagRule::KeepWithValue),
        (&["--progress"], FlagRule::DropWithValue),
        (&["--ansi"], FlagRule::DropWithValue),
    ];
    let (mut kept, rest) = take_flags(args, COMPOSE_GLOBALS)?;
    let (verb, rest) = rest.split_first()?;
    match verb.as_str() {
        "exec" => exec_family("compose exec", "service", &mut kept, rest),
        // Observers: read-only against the daemon; display flags dropped.
        "ps" | "logs" | "version" | "config" | "top" | "images" | "ls" | "port" | "events" => {
            observer_family("compose", verb, &kept, rest)
        }
        // Lifecycle: bounded by the project's compose file; orchestration
        // flags dropped, target services kept.
        "up" | "down" | "start" | "stop" | "restart" | "build" | "pull" | "create" | "kill"
        | "pause" | "unpause" | "wait" => lifecycle_family(verb, &kept, rest),
        _ => None,
    }
}

/// `exec [flags] <target> <payload …>` — key on the target plus authority
/// flags, wildcard the payload.
fn exec_family(
    prefix: &str,
    target_kind: &str,
    kept_globals: &mut Vec<String>,
    args: &[String],
) -> Option<SpawnFamily> {
    const EXEC_FLAGS: &[(&[&str], FlagRule)] = &[
        // Authority-bearing: who the payload runs as, and with what caps.
        (&["--user", "-u"], FlagRule::KeepWithValue),
        (&["--privileged"], FlagRule::Keep),
        // In-container plumbing: shapes the payload's stdio/env/cwd inside
        // the container, not its host authority.
        (&["-T", "--no-TTY"], FlagRule::Drop),
        (&["--interactive", "-i"], FlagRule::Drop),
        (&["--tty", "-t"], FlagRule::Drop),
        (&["--detach", "-d"], FlagRule::Drop),
        (&["--env", "-e"], FlagRule::DropWithValue),
        (&["--workdir", "-w"], FlagRule::DropWithValue),
        (&["--index"], FlagRule::DropWithValue),
    ];
    let (kept, rest) = take_flags(args, EXEC_FLAGS)?;
    // The first positional is the service/container; everything after it is
    // the payload. No target, no family.
    let (target, payload) = rest.split_first()?;
    if payload.is_empty() {
        // `exec web` alone starts an interactive shell only with a payload on
        // real invocations; without one there is nothing to wildcard and the
        // exact key is fine.
        return None;
    }
    let mut key_parts: Vec<String> = vec![prefix.to_string()];
    key_parts.append(kept_globals);
    key_parts.extend(kept.clone());
    key_parts.push(target.clone());
    key_parts.push("*".to_string());
    let qualifiers = if kept.is_empty() {
        String::new()
    } else {
        format!(" ({})", kept.join(" "))
    };
    Some(SpawnFamily {
        key: key_parts.join(" "),
        label: format!(
            "any command in {target_kind} `{target}`{qualifiers} via `{prefix}`, this session"
        ),
    })
}

/// Read-only verbs: drop every classified display flag, keep positionals.
fn observer_family(
    prefix: &str,
    verb: &str,
    kept_globals: &[String],
    args: &[String],
) -> Option<SpawnFamily> {
    const OBSERVER_FLAGS: &[(&[&str], FlagRule)] = &[
        (&["--tail", "-n"], FlagRule::DropWithValue),
        (&["--since"], FlagRule::DropWithValue),
        (&["--until"], FlagRule::DropWithValue),
        (&["--follow", "-f"], FlagRule::Drop),
        (&["--timestamps", "-t"], FlagRule::Drop),
        (&["--no-color"], FlagRule::Drop),
        (&["--no-log-prefix"], FlagRule::Drop),
        (&["--format"], FlagRule::DropWithValue),
        (&["--quiet", "-q"], FlagRule::Drop),
        (&["--all", "-a"], FlagRule::Drop),
        (&["--services"], FlagRule::Drop),
        (&["--filter"], FlagRule::DropWithValue),
        (&["--no-trunc"], FlagRule::Drop),
    ];
    let (_, rest) = take_flags(args, OBSERVER_FLAGS)?;
    let mut key_parts: Vec<String> = vec![prefix.to_string()];
    key_parts.extend(kept_globals.iter().cloned());
    key_parts.push(verb.to_string());
    key_parts.extend(rest.iter().cloned());
    let targets = if rest.is_empty() {
        String::new()
    } else {
        format!(" {}", rest.join(" "))
    };
    Some(SpawnFamily {
        key: key_parts.join(" "),
        label: format!("`{prefix} {verb}{targets}` with any display flags, this session"),
    })
}

/// Lifecycle verbs: drop classified orchestration flags, keep target services.
fn lifecycle_family(verb: &str, kept_globals: &[String], args: &[String]) -> Option<SpawnFamily> {
    const LIFECYCLE_FLAGS: &[(&[&str], FlagRule)] = &[
        (&["--detach", "-d"], FlagRule::Drop),
        (&["--build"], FlagRule::Drop),
        (&["--no-build"], FlagRule::Drop),
        (&["--force-recreate"], FlagRule::Drop),
        (&["--no-recreate"], FlagRule::Drop),
        (&["--no-deps"], FlagRule::Drop),
        (&["--remove-orphans"], FlagRule::Drop),
        (&["--wait"], FlagRule::Drop),
        (&["--quiet-pull"], FlagRule::Drop),
        (&["--no-color"], FlagRule::Drop),
        (&["--timeout", "-t"], FlagRule::DropWithValue),
        (&["--pull"], FlagRule::DropWithValue),
        (&["--no-cache"], FlagRule::Drop),
    ];
    let (_, rest) = take_flags(args, LIFECYCLE_FLAGS)?;
    let mut key_parts: Vec<String> = vec!["compose".to_string()];
    key_parts.extend(kept_globals.iter().cloned());
    key_parts.push(verb.to_string());
    key_parts.extend(rest.iter().cloned());
    let targets = if rest.is_empty() {
        String::new()
    } else {
        format!(" {}", rest.join(" "))
    };
    Some(SpawnFamily {
        key: key_parts.join(" "),
        label: format!(
            "`docker compose {verb}{targets}` with any orchestration flags, this session"
        ),
    })
}

/// Consume leading flags according to `table`. Returns the kept
/// (identity-bearing) flags in canonical `--flag=value` form plus the
/// remaining args. `None` when an unclassified flag is met — the fail-safe
/// that turns the whole call back into exact matching.
fn take_flags<'a>(
    args: &'a [String],
    table: &[(&[&str], FlagRule)],
) -> Option<(Vec<String>, &'a [String])> {
    let mut kept = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let token = &args[i];
        if !token.starts_with('-') || token == "-" || token == "--" {
            break;
        }
        let (flag, inline_value) = match token.split_once('=') {
            Some((flag, value)) => (flag, Some(value)),
            None => (token.as_str(), None),
        };
        let (canonical, rule) = classify(table, flag)?;
        match rule {
            FlagRule::KeepWithValue => {
                let value = match inline_value {
                    Some(v) => v.to_string(),
                    None => {
                        i += 1;
                        args.get(i)?.clone()
                    }
                };
                kept.push(format!("{canonical}={value}"));
            }
            FlagRule::Keep => kept.push(canonical.to_string()),
            FlagRule::DropWithValue => {
                if inline_value.is_none() {
                    i += 1;
                    args.get(i)?;
                }
            }
            FlagRule::Drop => {}
        }
        i += 1;
    }
    Some((kept, &args[i..]))
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// The measured flood: 14 approvals for payload-only variance.
    #[test]
    fn exec_payload_variants_share_one_family() {
        let a = spawn_family(
            "/usr/bin/docker",
            &argv(&[
                "docker", "compose", "exec", "-T", "web", "php", "-r", "echo 1;",
            ]),
        )
        .unwrap();
        let b = spawn_family(
            "/usr/bin/docker",
            &argv(&[
                "docker", "compose", "exec", "-T", "web", "php", "-r", "echo 2;",
            ]),
        )
        .unwrap();
        let c = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "exec", "web", "mysql", "-uportal"]),
        )
        .unwrap();
        assert_eq!(a.key, b.key);
        assert_eq!(a.key, c.key, "-T is in-container plumbing, not identity");
        assert!(a.label.contains("web"), "label must name the service");
    }

    /// A different service, user, or privilege level is a different family.
    #[test]
    fn exec_authority_changes_change_the_family() {
        let base = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "exec", "web", "php", "-v"]),
        )
        .unwrap();
        let other_service = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "exec", "portal-db", "php", "-v"]),
        )
        .unwrap();
        let as_root = spawn_family(
            "/usr/bin/docker",
            &argv(&[
                "docker", "compose", "exec", "-u", "root", "web", "php", "-v",
            ]),
        )
        .unwrap();
        let privileged = spawn_family(
            "/usr/bin/docker",
            &argv(&[
                "docker",
                "compose",
                "exec",
                "--privileged",
                "web",
                "php",
                "-v",
            ]),
        )
        .unwrap();
        assert_ne!(base.key, other_service.key);
        assert_ne!(base.key, as_root.key);
        assert_ne!(base.key, privileged.key);
        assert!(as_root.label.contains("--user=root"));
    }

    /// The logs case: --tail values must not fragment the family.
    #[test]
    fn observer_display_flags_are_dropped() {
        let a = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "logs", "--tail=8", "web"]),
        )
        .unwrap();
        let b = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "logs", "--tail=25", "web"]),
        )
        .unwrap();
        let c = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "logs", "--tail", "50", "web"]),
        )
        .unwrap();
        let db = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "logs", "portal-db"]),
        )
        .unwrap();
        assert_eq!(a.key, b.key);
        assert_eq!(a.key, c.key, "space-separated flag values must be consumed");
        assert_ne!(a.key, db.key, "the target service is identity");
    }

    #[test]
    fn lifecycle_orchestration_flags_are_dropped() {
        let a = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "up", "-d", "--build", "web"]),
        )
        .unwrap();
        let b = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "up", "-d", "--force-recreate", "web"]),
        )
        .unwrap();
        assert_eq!(a.key, b.key);
    }

    /// Authority-minting verbs and unknown flags must fall back to exact.
    #[test]
    fn unsafe_shapes_get_no_family() {
        // `docker run` mints authority through its flags.
        assert!(spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "run", "-v", "/:/host", "alpine", "sh"]),
        )
        .is_none());
        // Unknown flag on a family verb: unclassified could mean authority.
        assert!(spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "exec", "--detach-keys=x", "web", "sh"]),
        )
        .is_none());
        // A different compose file is kept as identity, not dropped.
        let other_file = spawn_family(
            "/usr/bin/docker",
            &argv(&[
                "docker",
                "compose",
                "-f",
                "other.yml",
                "exec",
                "web",
                "sh",
                "-c",
                "id",
            ]),
        )
        .unwrap();
        let default_file = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "exec", "web", "sh", "-c", "id"]),
        )
        .unwrap();
        assert_ne!(other_file.key, default_file.key);
        // Non-docker delegating binaries stay exact.
        assert!(spawn_family("/usr/bin/systemd-run", &argv(&["systemd-run", "id"])).is_none());
        // exec with no payload has nothing to wildcard.
        assert!(spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "exec", "web"]),
        )
        .is_none());
    }

    /// `-u root` and `--user root` are one authority; the key must agree.
    #[test]
    fn flag_aliases_share_a_canonical_key() {
        let short = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "exec", "-u", "root", "web", "id"]),
        )
        .unwrap();
        let long = spawn_family(
            "/usr/bin/docker",
            &argv(&["docker", "compose", "exec", "--user=root", "web", "id"]),
        )
        .unwrap();
        assert_eq!(short.key, long.key);
    }

    /// The compose CLI plugin invokes as its own binary.
    #[test]
    fn compose_plugin_binary_maps_to_the_same_grammar() {
        let plugin = spawn_family(
            "/usr/libexec/docker/cli-plugins/docker-compose",
            &argv(&[
                "/usr/libexec/docker/cli-plugins/docker-compose",
                "compose",
                "ps",
            ]),
        );
        assert!(plugin.is_some());
    }
}
