// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Destructive-action coverage filter (work item 68).
//!
//! Brings default coverage in line with the destructive-action threat model
//! grith describes publicly. Two outcomes matter:
//!
//! - **Catastrophic host/storage destruction** (filesystem format, raw
//!   block-device overwrite, signature wipe, `rm --no-preserve-root`,
//!   recursive removal of a system root or a database data directory) is
//!   **hard-denied** — these have no legitimate use inside a supervised AI
//!   agent and are unrecoverable.
//! - **Destructive operations directed at production** (a prod DB endpoint,
//!   or a `prod`/`production`/`live`-tagged resource) escalate from QUEUE to
//!   **DENY**. The same operation against a non-production target QUEUEs;
//!   scoped or recoverable operations (single-object staging deletes,
//!   `rm -rf ./node_modules`, read-only DB queries) score nothing.
//!
//! This filter is the single authority for destructive-action scoring. It
//! inspects both the reconstructed shell command (`ShellExec`/`ProcessSpawn`)
//! and file-operation path targets (`FileWrite`/`FileDelete`/`FileRename`/…),
//! emitting a composite-aware score directly rather than relying on
//! cross-filter composition — a single `ShellExec` exposes no `path()` to the
//! sensitive-path heuristic, so command and path signals never co-occur in one
//! evaluation. Emitting `DENY_SCORE` (> the 8.0 deny threshold) or a queue-band
//! score keeps calibration local and testable.
//!
//! ## Curation policy
//!
//! The destructive verb/target taxonomy and the production-signal heuristics
//! below are security-relevant. Score calibration is anchored to the proxy
//! thresholds (`SCORE_QUEUE_THRESHOLD` = 3.0, `SCORE_DENY_THRESHOLD` = 8.0).
//! Changes must preserve the ALLOW guardrails exercised by the unit tests —
//! over-blocking ordinary development workflows (`rm -rf` of project dirs,
//! single-object deletes, read-only queries, `helm list`, `kubectl get`) makes
//! the supervisor unusable. New cloud-CLI verbs follow the same
//! prod-gated pattern.

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, Severity, ToolCallContext, ToolCallType};

/// Score for a hard DENY. Strictly above `SCORE_DENY_THRESHOLD` (8.0) with
/// margin so an additive contribution from another filter (e.g. the
/// `ProcessSpawn` +1.0 baseline) cannot pull it back under the threshold.
const DENY_SCORE: f64 = 9.0;

/// Production markers recognised as a path/argument segment (boundary-matched,
/// so `product`/`reproduce`/`productivity` do NOT match).
fn is_prod_segment(seg: &str) -> bool {
    matches!(seg, "prod" | "production" | "prd" | "live" | "mainnet")
}

/// True when any alphanumeric-delimited segment of `text_lc` is a production
/// marker. Splitting on every non-alphanumeric char means `s3://prod-backups`,
/// `/srv/prod/infra`, and `drop database prod` all surface the `prod` segment,
/// while `staging-builds`, `product-catalog`, and `reproduce.sh` do not.
fn has_prod_lexical(text_lc: &str) -> bool {
    text_lc
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(is_prod_segment)
}

/// Hostname suffixes for managed production database / cache / warehouse
/// endpoints. A destructive verb directed at one of these is production by
/// definition. Aurora cluster endpoints
/// (`name.cluster-xxxx.<region>.rds.amazonaws.com`) contain `.rds.amazonaws.com`.
const PROD_DB_ENDPOINT_MARKERS: &[&str] = &[
    ".rds.amazonaws.com",      // RDS / Aurora (Postgres, MySQL, …)
    ".redshift.amazonaws.com", // Redshift
    ".cache.amazonaws.com",    // ElastiCache
    ".sql.googleapis.com",     // Cloud SQL
    ".database.windows.net",   // Azure SQL
    ".documents.azure.com",    // Cosmos DB
];

fn has_prod_db_endpoint(text_lc: &str) -> bool {
    PROD_DB_ENDPOINT_MARKERS.iter().any(|m| text_lc.contains(m))
}

/// A single destructive-action verdict.
struct Hit {
    rule_id: &'static str,
    score: f64,
    severity: Severity,
    message: String,
}

impl Hit {
    fn deny(rule_id: &'static str, message: impl Into<String>) -> Self {
        Self {
            rule_id,
            score: DENY_SCORE,
            severity: Severity::Critical,
            message: message.into(),
        }
    }

    fn queue(
        rule_id: &'static str,
        score: f64,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule_id,
            score,
            severity,
            message: message.into(),
        }
    }
}

/// Resolve a destructive verb against a non-production vs production target to
/// either a queue-band hit or a DENY.
fn prod_gated(
    prod: bool,
    rule_id: &'static str,
    queue_score: f64,
    queue_severity: Severity,
    message: &str,
) -> Hit {
    if prod {
        Hit::deny(rule_id, format!("{message} (production target)"))
    } else {
        Hit::queue(rule_id, queue_score, queue_severity, message.to_string())
    }
}

/// Heuristic path-target classes shared by command-recursive-delete targets and
/// destructive file operations.
enum PathClass {
    /// Unrecoverable / never-legitimate target → DENY.
    Catastrophic(&'static str, &'static str),
    /// Serious but recoverable / sometimes-legitimate → QUEUE.
    Queue(&'static str, f64, &'static str),
}

/// Database server data directories: a write/delete here by a supervised agent
/// (which is never the database server itself) destroys primary state.
fn is_database_data_dir(path_lc: &str) -> bool {
    const DB_DATA_DIRS: &[&str] = &[
        "/var/lib/postgresql",
        "/var/lib/mysql",
        "/var/lib/mariadb",
        "/var/lib/mongodb",
        "/var/lib/redis",
        "/var/lib/cassandra",
        "/var/lib/elasticsearch",
        "/var/lib/clickhouse",
        "/var/lib/influxdb",
        "/var/lib/neo4j",
        "/var/lib/couchdb",
    ];
    DB_DATA_DIRS
        .iter()
        .any(|d| path_lc == *d || path_lc.starts_with(&format!("{d}/")))
}

/// Backup conventions — deleting these removes the recovery path.
fn is_backup_location(path_lc: &str) -> bool {
    path_lc.contains("/backup")
}

/// Generic primary-data mounts.
fn is_data_mount(path_lc: &str) -> bool {
    const DATA_MOUNTS: &[&str] = &["/data", "/srv/data", "/var/data"];
    DATA_MOUNTS
        .iter()
        .any(|d| path_lc == *d || path_lc.starts_with(&format!("{d}/")))
}

/// System roots whose recursive removal cripples the host.
fn is_system_critical_dir(path_lc: &str) -> bool {
    let p = path_lc.trim_end_matches('/');
    if p.is_empty() {
        // bare "/" trimmed to ""
        return true;
    }
    const SYSTEM_DIRS: &[&str] = &[
        "/boot", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/etc", "/var", "/var/lib", "/sys",
        "/proc", "/dev", "/root", "/home",
    ];
    SYSTEM_DIRS.contains(&p)
}

/// Classify a recursive-removal target (`rm -rf <target>`). System roots and
/// DB data directories are catastrophic; backups and data mounts queue;
/// ordinary project/scratch paths return `None` (ALLOW).
fn classify_rm_target(target: &str) -> Option<PathClass> {
    let path_lc = target.to_lowercase();
    let p = path_lc.trim_end_matches('/');
    if p.is_empty() || p == "/*" || p == "/.*" {
        return Some(PathClass::Catastrophic(
            "rm-filesystem-root",
            "recursive delete of the filesystem root",
        ));
    }
    if is_system_critical_dir(&path_lc) {
        return Some(PathClass::Catastrophic(
            "rm-system-directory",
            "recursive delete of a system directory",
        ));
    }
    if is_database_data_dir(&path_lc) {
        return Some(PathClass::Catastrophic(
            "rm-database-data-directory",
            "recursive delete of a database data directory",
        ));
    }
    if is_backup_location(&path_lc) {
        return Some(PathClass::Queue(
            "rm-backup-location",
            4.5,
            "recursive delete of a backup location",
        ));
    }
    if is_data_mount(&path_lc) {
        return Some(PathClass::Queue(
            "rm-data-mount",
            4.0,
            "recursive delete of a data mount",
        ));
    }
    None
}

/// Classify a destructive single file operation target (write/delete/rename).
/// Unlike [`classify_rm_target`], this does NOT treat a write under a system
/// directory as catastrophic — an individual `/etc/...` write is handled by the
/// sensitive-path heuristic. Only DB data dirs / backups / data mounts (which
/// no other filter covers) are classified here.
fn classify_fileop_target(path_lc: &str) -> Option<PathClass> {
    if is_database_data_dir(path_lc) {
        return Some(PathClass::Catastrophic(
            "destructive-write-database-data-directory",
            "destructive operation on a database data directory",
        ));
    }
    if is_backup_location(path_lc) {
        return Some(PathClass::Queue(
            "destructive-write-backup-location",
            4.5,
            "destructive operation on a backup location",
        ));
    }
    if is_data_mount(path_lc) {
        return Some(PathClass::Queue(
            "destructive-write-data-mount",
            4.0,
            "destructive operation on a data mount",
        ));
    }
    None
}

fn path_class_to_hit(class: PathClass) -> Hit {
    match class {
        PathClass::Catastrophic(rule, msg) => Hit::deny(rule, msg),
        PathClass::Queue(rule, score, msg) => Hit::queue(rule, score, Severity::Error, msg),
    }
}

/// Benign character / pseudo devices that are safe `dd of=` / `shred` targets.
fn is_raw_block_device(dev_lc: &str) -> bool {
    let Some(rest) = dev_lc.strip_prefix("/dev/") else {
        return false;
    };
    const BENIGN: &[&str] = &[
        "null", "zero", "full", "random", "urandom", "console", "stdin", "stdout", "stderr",
    ];
    if BENIGN.contains(&rest) {
        return false;
    }
    if rest.starts_with("tty") || rest.starts_with("pts/") || rest.starts_with("fd/") {
        return false;
    }
    // Anything else under /dev/ (sd*, nvme*, vd*, hd*, mmcblk*, xvd*, loop*,
    // sr*, mapper/*, dm-*, disk*) is a block/raw device we would never write a
    // raw image to in a supervised agent.
    true
}

/// Basename of a command token, handling absolute paths (`/usr/bin/dd` → `dd`).
fn basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// True if any token is (an absolute path to) the named binary.
fn has_command(tokens: &[&str], name: &str) -> bool {
    tokens.iter().any(|t| basename(t) == name)
}

/// Recursive flag present among `rm`/`gsutil` argv flags (`-r`, `-R`,
/// `--recursive`, or a combined short flag containing `r`/`R` such as `-rf`).
fn has_recursive_flag(tokens: &[&str]) -> bool {
    tokens.iter().any(|t| {
        if *t == "--recursive" {
            return true;
        }
        if let Some(short) = t.strip_prefix('-') {
            if !short.starts_with('-') {
                return short.chars().any(|c| c == 'r' || c == 'R');
            }
        }
        false
    })
}

/// Host paths whose writable bind-mount into a container grants host-root
/// authority. Mounting any of these writable lets a container process (running
/// as root in the daemon, outside the supervised tree) modify host state.
fn is_sensitive_mount_source(src: &str) -> bool {
    let s = src.trim_end_matches('/');
    if s.is_empty() {
        return true; // "/" — the whole host filesystem
    }
    if s.contains("/.ssh") {
        return true;
    }
    const ROOTS: &[&str] = &[
        "/etc", "/root", "/boot", "/usr", "/var", "/home", "/lib", "/lib64", "/sys", "/proc",
        "/dev", "/bin", "/sbin",
    ];
    ROOTS
        .iter()
        .any(|r| s == *r || s.starts_with(&format!("{r}/")))
}

/// True when a `docker`/`podman` `-v`/`--volume`/`--mount` spec grants host
/// authority: the container control socket (full daemon API, even read-only),
/// or a writable bind-mount of a sensitive host path.
fn mount_spec_is_dangerous(spec: &str) -> bool {
    // `--mount type=bind,source=/etc,target=…[,readonly]`
    if spec.contains("source=") || spec.contains("src=") {
        let src = spec.split(',').find_map(|kv| {
            kv.strip_prefix("source=")
                .or_else(|| kv.strip_prefix("src="))
        });
        let Some(src) = src else { return false };
        if src.contains("docker.sock") {
            return true;
        }
        let read_only = spec.contains("readonly") || spec.contains("ro=true");
        return !read_only && is_sensitive_mount_source(src);
    }
    // `-v src:dest[:opts]` (a leading `/` distinguishes a host path from a
    // named volume).
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() < 2 || !parts[0].starts_with('/') {
        return false;
    }
    let src = parts[0];
    if src.contains("docker.sock") {
        return true; // socket = full daemon API regardless of ro
    }
    let read_only = parts
        .get(2)
        .is_some_and(|opts| opts.split(',').any(|o| o == "ro"));
    !read_only && is_sensitive_mount_source(src)
}

/// H2 Option 3 (IPC-delegated authority): a `docker`/`podman` `run`/`create`
/// whose effect escalates to host authority. The privileged action executes
/// inside the daemon — outside the supervised process tree — so the resulting
/// writes are never intercepted; we score the dangerous *shape* at spawn time.
/// Mediated (QUEUE) rather than hard-denied: privileged/bind-mount container
/// use is sometimes legitimate (CI), so it freezes for human approval.
fn docker_run_escalation(cmd_lc: &str, tokens: &[&str]) -> Option<Hit> {
    let runtime_idx = tokens
        .iter()
        .position(|t| matches!(basename(t), "docker" | "podman" | "nerdctl"))?;
    let subcommand = tokens[runtime_idx + 1..]
        .iter()
        .find(|t| !t.starts_with('-'))
        .map(|s| basename(s));
    if !matches!(subcommand, Some("run") | Some("create")) {
        return None;
    }

    if cmd_lc.contains("--privileged") {
        return Some(Hit::queue(
            "docker-run-privileged",
            5.0,
            Severity::Error,
            "container run --privileged (full host capabilities)",
        ));
    }
    if cmd_lc.contains("--pid=host") || cmd_lc.contains("--pid host") {
        return Some(Hit::queue(
            "docker-run-pid-host",
            5.0,
            Severity::Error,
            "container run --pid=host (host process namespace)",
        ));
    }

    let mut specs: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        if (t == "-v" || t == "--volume" || t == "--mount") && i + 1 < tokens.len() {
            specs.push(tokens[i + 1]);
            i += 2;
            continue;
        }
        if let Some(v) = t
            .strip_prefix("--volume=")
            .or_else(|| t.strip_prefix("-v="))
            .or_else(|| t.strip_prefix("--mount="))
        {
            specs.push(v);
        }
        i += 1;
    }
    if specs.iter().any(|s| mount_spec_is_dangerous(s)) {
        return Some(Hit::queue(
            "docker-run-host-mount",
            5.0,
            Severity::Error,
            "container run with the docker socket or a writable sensitive host bind-mount",
        ));
    }
    None
}

/// Classify a reconstructed shell command. Returns the highest-scoring
/// destructive verdict, or `None` if nothing destructive is recognised.
fn classify_command(cmd_lc: &str, tokens: &[&str], prod: bool) -> Option<Hit> {
    let mut hits: Vec<Hit> = Vec::new();

    // ---- Catastrophic host / storage destruction (DENY regardless of prod) ----

    // Filesystem format: mkfs, mkfs.<fs>, mke2fs, mkswap, mkdosfs, mkntfs.
    if tokens.iter().any(|t| {
        let b = basename(t);
        b == "mkfs"
            || b.starts_with("mkfs.")
            || matches!(b, "mke2fs" | "mkswap" | "mkdosfs" | "mkntfs")
    }) {
        hits.push(Hit::deny("filesystem-format", "filesystem format (mkfs)"));
    }

    // Filesystem signature wipe.
    if has_command(tokens, "wipefs") {
        hits.push(Hit::deny(
            "filesystem-signature-wipe",
            "filesystem signature wipe (wipefs)",
        ));
    }

    // rm --no-preserve-root (root filesystem destruction).
    if cmd_lc.contains("--no-preserve-root") {
        hits.push(Hit::deny(
            "rm-no-preserve-root",
            "rm with --no-preserve-root (root filesystem destruction)",
        ));
    }

    // dd writing to a raw block device.
    if has_command(tokens, "dd") {
        if let Some(dev) = tokens.iter().find_map(|t| t.strip_prefix("of=")) {
            if is_raw_block_device(&dev.to_lowercase()) {
                hits.push(Hit::deny("dd-device-write", "dd write to a block device"));
            }
        }
    }

    // shred: a block device → DENY; otherwise secure-overwrite → QUEUE.
    if has_command(tokens, "shred") {
        let device = tokens
            .iter()
            .any(|t| is_raw_block_device(&t.to_lowercase()));
        if device {
            hits.push(Hit::deny(
                "shred-device",
                "secure-overwrite of a block device (shred)",
            ));
        } else {
            hits.push(Hit::queue(
                "shred",
                4.0,
                Severity::Error,
                "secure overwrite (shred)",
            ));
        }
    }

    // Recursive removal: classify each non-flag target by sensitivity.
    if has_command(tokens, "rm") && has_recursive_flag(tokens) {
        // Targets are non-flag tokens after the `rm` binary, excluding the
        // binary itself and any leading wrapper (sudo/env/bash -c handled by
        // basename match — wrappers' own args may appear but are harmless to
        // re-classify, since non-sensitive tokens return None).
        let after_rm: Vec<&str> = {
            let idx = tokens.iter().position(|t| basename(t) == "rm").unwrap_or(0);
            tokens[idx + 1..]
                .iter()
                .copied()
                .filter(|t| !t.starts_with('-'))
                .collect()
        };
        let mut best: Option<Hit> = None;
        for target in after_rm {
            if let Some(class) = classify_rm_target(target) {
                let hit = path_class_to_hit(class);
                best = match best {
                    Some(b) if b.score >= hit.score => Some(b),
                    _ => Some(hit),
                };
            }
        }
        if let Some(hit) = best {
            hits.push(hit);
        }
    }

    // ---- SQL / datastore destruction ----
    if cmd_lc.contains("drop database") || cmd_lc.contains("db.dropdatabase") {
        hits.push(prod_gated(
            prod,
            "sql-drop-database",
            4.5,
            Severity::Error,
            "SQL DROP DATABASE",
        ));
    }
    if cmd_lc.contains("drop schema") {
        hits.push(prod_gated(
            prod,
            "sql-drop-schema",
            4.0,
            Severity::Error,
            "SQL DROP SCHEMA",
        ));
    }
    if cmd_lc.contains("drop keyspace") {
        hits.push(prod_gated(
            prod,
            "cql-drop-keyspace",
            4.0,
            Severity::Error,
            "CQL DROP KEYSPACE",
        ));
    }
    if cmd_lc.contains("drop table") {
        hits.push(prod_gated(
            prod,
            "sql-drop-table",
            4.0,
            Severity::Error,
            "SQL DROP TABLE",
        ));
    }
    // SQL `TRUNCATE` (the `TABLE` keyword is optional in Postgres/MySQL, so we
    // can't require it). Disambiguate from the coreutils `truncate -s <size>
    // <file>` form by requiring either the explicit `truncate table` phrase or
    // the presence of a database client on the command line.
    let db_client = tokens.iter().any(|t| {
        matches!(
            basename(t),
            "psql"
                | "mysql"
                | "mariadb"
                | "mysqlsh"
                | "mongo"
                | "mongosh"
                | "redis-cli"
                | "cqlsh"
                | "clickhouse-client"
                | "sqlplus"
                | "sqlcmd"
                | "pgcli"
                | "mycli"
                | "cockroach"
        )
    });
    if cmd_lc.contains("truncate table") || (cmd_lc.contains("truncate") && db_client) {
        hits.push(prod_gated(
            prod,
            "sql-truncate",
            3.5,
            Severity::Error,
            "SQL TRUNCATE",
        ));
    }
    // Redis flush (unambiguous).
    if cmd_lc.contains("flushall") || cmd_lc.contains("flushdb") {
        hits.push(prod_gated(
            prod,
            "redis-flush",
            4.0,
            Severity::Error,
            "Redis FLUSH",
        ));
    }

    // ---- Cloud / orchestration destruction (prod-gated) ----
    if cmd_lc.contains("aws s3 rb") {
        hits.push(prod_gated(
            prod,
            "aws-s3-bucket-delete",
            4.5,
            Severity::Error,
            "S3 bucket delete",
        ));
    }
    if cmd_lc.contains("aws s3 rm") {
        // Single-object, non-production deletes are routine; only recursive,
        // whole-bucket, or production deletes are flagged.
        let recursive = cmd_lc.contains("--recursive") || has_recursive_flag(tokens);
        let bucket_root = tokens.iter().any(|t| {
            t.strip_prefix("s3://")
                .map(|rest| !rest.trim_end_matches('/').contains('/'))
                .unwrap_or(false)
        });
        if recursive || bucket_root || prod {
            hits.push(prod_gated(
                prod,
                "aws-s3-recursive-delete",
                3.5,
                Severity::Warning,
                "S3 recursive object delete",
            ));
        }
    }
    if cmd_lc.contains("gsutil") && cmd_lc.contains(" rm") && has_recursive_flag(tokens) {
        hits.push(prod_gated(
            prod,
            "gcs-recursive-delete",
            4.0,
            Severity::Error,
            "GCS recursive delete",
        ));
    }
    if cmd_lc.contains("kubectl delete") && cmd_lc.contains("--all") {
        hits.push(prod_gated(
            prod,
            "kubectl-delete-all",
            4.5,
            Severity::Error,
            "kubectl delete --all",
        ));
    }
    if cmd_lc.contains("kubectl delete namespace") || cmd_lc.contains("kubectl delete ns ") {
        hits.push(prod_gated(
            prod,
            "kubectl-delete-namespace",
            4.5,
            Severity::Error,
            "kubectl delete namespace",
        ));
    }
    if cmd_lc.contains("terraform destroy")
        || cmd_lc.contains("terraform apply -destroy")
        || cmd_lc.contains("terraform apply --destroy")
    {
        hits.push(prod_gated(
            prod,
            "terraform-destroy",
            4.0,
            Severity::Error,
            "Infrastructure teardown (terraform destroy)",
        ));
    }
    if cmd_lc.contains("helm uninstall") || cmd_lc.contains("helm delete") {
        hits.push(prod_gated(
            prod,
            "helm-uninstall",
            3.5,
            Severity::Warning,
            "Helm release uninstall",
        ));
    }
    if cmd_lc.contains("az group delete") {
        hits.push(prod_gated(
            prod,
            "az-group-delete",
            4.0,
            Severity::Error,
            "Azure resource-group delete",
        ));
    }
    if cmd_lc.contains("gcloud") && cmd_lc.contains(" delete") {
        hits.push(prod_gated(
            prod,
            "gcloud-delete",
            4.0,
            Severity::Error,
            "gcloud resource delete",
        ));
    }
    if cmd_lc.contains("flyctl destroy") || cmd_lc.contains("fly destroy") {
        hits.push(prod_gated(
            prod,
            "flyctl-destroy",
            4.0,
            Severity::Error,
            "Fly.io app destroy",
        ));
    }
    // docker prune is local-only churn — always queue, never deny.
    if cmd_lc.contains("docker system prune") || cmd_lc.contains("docker volume prune") {
        hits.push(Hit::queue(
            "docker-prune",
            3.5,
            Severity::Warning,
            "Docker prune",
        ));
    }
    // H2 Option 3: container run that escalates to host authority.
    if let Some(hit) = docker_run_escalation(cmd_lc, tokens) {
        hits.push(hit);
    }

    hits.into_iter().max_by(|a, b| a.score.total_cmp(&b.score))
}

pub struct DestructiveActionFilter;

impl DestructiveActionFilter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DestructiveActionFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SecurityFilter for DestructiveActionFilter {
    fn name(&self) -> &str {
        "destructive-action"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Pattern
    }

    async fn evaluate(&self, ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        // Command-content path (ShellExec / ProcessSpawn).
        if let Some(full) = ctx.full_command() {
            let cmd_lc = full.to_lowercase();
            let tokens: Vec<&str> = full.split_whitespace().collect();
            let cwd_lc = ctx
                .arguments
                .get("cwd")
                .and_then(|v| v.as_str())
                .map(str::to_lowercase)
                .unwrap_or_default();
            let prod = has_prod_db_endpoint(&cmd_lc)
                || has_prod_lexical(&cmd_lc)
                || has_prod_lexical(&cwd_lc);
            if let Some(hit) = classify_command(&cmd_lc, &tokens, prod) {
                return Ok(FilterResult::matched(
                    self.name(),
                    hit.rule_id,
                    hit.score,
                    hit.severity,
                    &hit.message,
                ));
            }
            return Ok(FilterResult::no_match(self.name()));
        }

        // File-operation path (destructive write/delete/rename on a sensitive
        // data/backup target the path heuristic does not cover).
        if is_destructive_file_op(&ctx.call_type) {
            if let Some(path) = ctx.path() {
                let path_lc = path.to_lowercase();
                if let Some(class) = classify_fileop_target(&path_lc) {
                    let hit = path_class_to_hit(class);
                    return Ok(FilterResult::matched(
                        self.name(),
                        hit.rule_id,
                        hit.score,
                        hit.severity,
                        &hit.message,
                    ));
                }
            }
        }

        Ok(FilterResult::no_match(self.name()))
    }
}

fn is_destructive_file_op(call_type: &ToolCallType) -> bool {
    matches!(
        call_type,
        ToolCallType::FileWrite { .. }
            | ToolCallType::FileAppend { .. }
            | ToolCallType::FileDelete { .. }
            | ToolCallType::FileRename { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use uuid::Uuid;

    fn shell(cmd: &str) -> ToolCallContext {
        let parts: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
        let (command, args) = parts.split_first().unwrap();
        ToolCallContext::new(
            "test",
            ToolCallType::ShellExec {
                command: command.clone(),
                args: args.to_vec(),
            },
            Uuid::new_v4(),
        )
    }

    async fn score(cmd: &str) -> FilterResult {
        DestructiveActionFilter::new()
            .evaluate(&shell(cmd))
            .await
            .unwrap()
    }

    fn is_deny(r: &FilterResult) -> bool {
        r.matched && r.score > 8.0
    }
    fn is_queue(r: &FilterResult) -> bool {
        r.matched && r.score > 3.0 && r.score <= 8.0
    }

    #[tokio::test]
    async fn catastrophic_ops_deny() {
        for cmd in [
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sdb1",
            "mkfs /dev/sdb1",
            "wipefs -a /dev/sda",
            "rm -rf --no-preserve-root /",
            "rm -rf /",
            "rm -rf /var/lib/postgresql/data",
            "rm -rf /etc",
            "shred -n 3 /dev/sda",
        ] {
            let r = score(cmd).await;
            assert!(
                is_deny(&r),
                "must DENY: {cmd:?} -> {} ({})",
                r.score,
                r.rule_id
            );
        }
    }

    #[tokio::test]
    async fn benign_dev_ops_allow() {
        for cmd in [
            "rm -rf ./node_modules",
            "rm -rf target/debug",
            "rm -rf /tmp/build-cache",
            "dd if=/dev/zero of=disk.img bs=1M count=10",
            "dd if=/dev/urandom of=/dev/null",
            "aws s3 rm s3://staging-builds/old-artifact.zip",
            "kubectl get pods",
            "helm list",
            "git commit -m wip",
            "truncate -s 0 logfile.txt",
            "ls -la /var/lib/postgresql",
            // H2 Option 3 negatives: benign container use.
            "docker run alpine echo hi",
            "docker build -t app .",
            "docker ps -a",
            "docker run -v ./data:/data:ro alpine",
            "docker run -v /etc/hosts:/x:ro alpine",
            "docker run -v myvolume:/data alpine",
        ] {
            let r = score(cmd).await;
            assert!(
                !r.matched,
                "must ALLOW: {cmd:?} -> {} ({})",
                r.score, r.rule_id
            );
        }
    }

    #[tokio::test]
    async fn docker_run_host_escalation_queues() {
        // H2 Option 3 (IPC-delegated authority): container runs that escalate
        // to host authority freeze for review.
        for cmd in [
            "docker run -v /etc:/host-etc:rw alpine", // the public exploit
            "docker run --privileged alpine",
            "docker run --pid=host alpine",
            "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
            "podman run -v /root:/r alpine", // default rw
            "docker run --mount type=bind,source=/etc,target=/x alpine",
        ] {
            let r = score(cmd).await;
            assert!(
                is_queue(&r),
                "must QUEUE: {cmd:?} -> {} ({})",
                r.score,
                r.rule_id
            );
        }
    }

    #[tokio::test]
    async fn destructive_non_prod_queues() {
        for cmd in [
            "psql -c TRUNCATE table users",
            "mysql -e DROP TABLE orders",
            "terraform destroy",
            "helm uninstall my-test-chart",
            "kubectl delete --all",
            "aws s3 rb s3://staging-bucket",
            "docker system prune -f",
            "gsutil rm -r gs://staging-data/old",
        ] {
            let r = score(cmd).await;
            assert!(
                is_queue(&r),
                "must QUEUE: {cmd:?} -> {} ({})",
                r.score,
                r.rule_id
            );
        }
    }

    #[tokio::test]
    async fn destructive_prod_denies() {
        for cmd in [
            "psql -h prod-db.cluster-abc.us-east-1.rds.amazonaws.com -c DROP DATABASE prod",
            "aws s3 rb s3://prod-backups --force",
            "kubectl delete namespace prod",
            "terraform destroy -var env=production",
            "mysql -h shop.sql.googleapis.com -e DROP TABLE orders",
        ] {
            let r = score(cmd).await;
            assert!(
                is_deny(&r),
                "must DENY: {cmd:?} -> {} ({})",
                r.score,
                r.rule_id
            );
        }
    }

    #[tokio::test]
    async fn terraform_destroy_prod_cwd_denies() {
        let mut ctx = shell("terraform destroy");
        ctx.arguments = serde_json::json!({ "cwd": "/srv/prod/infra" });
        let r = DestructiveActionFilter::new().evaluate(&ctx).await.unwrap();
        assert!(
            is_deny(&r),
            "prod cwd must DENY -> {} ({})",
            r.score,
            r.rule_id
        );

        let mut ctx2 = shell("terraform destroy");
        ctx2.arguments = serde_json::json!({ "cwd": "/home/u/staging/infra" });
        let r2 = DestructiveActionFilter::new()
            .evaluate(&ctx2)
            .await
            .unwrap();
        assert!(
            is_queue(&r2),
            "staging cwd must QUEUE -> {} ({})",
            r2.score,
            r2.rule_id
        );
    }

    #[tokio::test]
    async fn fileop_database_dir_denies_node_modules_allows() {
        let f = DestructiveActionFilter::new();
        let del = |p: &str| {
            ToolCallContext::new(
                "test",
                ToolCallType::FileDelete {
                    path: p.to_string(),
                },
                Uuid::new_v4(),
            )
        };
        let r = f
            .evaluate(&del("/var/lib/postgresql/data/base/1/12345"))
            .await
            .unwrap();
        assert!(
            is_deny(&r),
            "db data file delete must DENY -> {} ({})",
            r.score,
            r.rule_id
        );

        let r2 = f
            .evaluate(&del("/home/u/project/node_modules/.cache/x"))
            .await
            .unwrap();
        assert!(
            !r2.matched,
            "node_modules delete must ALLOW -> {} ({})",
            r2.score, r2.rule_id
        );
    }

    #[test]
    fn prod_lexical_boundary() {
        assert!(has_prod_lexical("s3://prod-backups"));
        assert!(has_prod_lexical("/srv/prod/infra"));
        assert!(has_prod_lexical("drop database prod"));
        assert!(has_prod_lexical("env=production"));
        assert!(!has_prod_lexical("staging-builds"));
        assert!(!has_prod_lexical("product-catalog"));
        assert!(!has_prod_lexical("reproduce.sh"));
        assert!(!has_prod_lexical("/home/u/project"));
    }

    #[test]
    fn raw_block_device_detection() {
        assert!(is_raw_block_device("/dev/sda"));
        assert!(is_raw_block_device("/dev/nvme0n1"));
        assert!(is_raw_block_device("/dev/mapper/vg-root"));
        assert!(!is_raw_block_device("/dev/null"));
        assert!(!is_raw_block_device("/dev/urandom"));
        assert!(!is_raw_block_device("/dev/pts/3"));
        assert!(!is_raw_block_device("disk.img"));
    }
}
