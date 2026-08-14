// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Work item 68 — destructive-action rule coverage acceptance suite.
//!
//! Drives the §1.4 scenario table through the full production filter pipeline
//! (`production_filter_registry`: the same filters and shipped 3.0/8.0
//! thresholds `config/default.toml` ships, `cold_start_calls = 0`). Each case
//! asserts the composite decision lands in ALLOW / QUEUE / DENY as required.
//!
//! The ALLOW rows are the load-bearing guardrail: false positives on ordinary
//! development workflows (`rm -rf ./node_modules`, single-object staging
//! deletes, read-only queries) would make the supervisor unusable. The DENY
//! rows back grith's public "blocks the destructive step" claim.

use grith_tests::{production_filter_registry, ProxyAction, ToolCallContext, ToolCallType};

/// Build a ShellExec context from a whitespace-tokenised command line.
fn shell(cmd: &str) -> ToolCallContext {
    let parts: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
    let (command, args) = parts.split_first().expect("non-empty command");
    ToolCallContext::new(
        "test",
        ToolCallType::ShellExec {
            command: command.clone(),
            args: args.to_vec(),
        },
        uuid::Uuid::new_v4(),
    )
}

fn shell_in_cwd(cmd: &str, cwd: &str) -> ToolCallContext {
    let mut ctx = shell(cmd);
    ctx.arguments = serde_json::json!({ "cwd": cwd });
    ctx
}

fn file_delete(path: &str) -> ToolCallContext {
    ToolCallContext::new(
        "test",
        ToolCallType::FileDelete {
            path: path.to_string(),
        },
        uuid::Uuid::new_v4(),
    )
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Allow,
    Queue,
    Deny,
}

async fn outcome(ctx: &ToolCallContext) -> (Outcome, f64, String) {
    let proxy = production_filter_registry();
    let d = proxy.evaluate(ctx).await;
    let o = match d.action {
        ProxyAction::Allow => Outcome::Allow,
        ProxyAction::Queue { .. } => Outcome::Queue,
        ProxyAction::Deny { .. } => Outcome::Deny,
    };
    let rules = d
        .filter_results
        .iter()
        .filter(|r| r.matched)
        .map(|r| format!("{}:{}", r.filter_name, r.rule_id))
        .collect::<Vec<_>>()
        .join(",");
    (o, d.composite_score, rules)
}

async fn assert_outcome(ctx: ToolCallContext, want: Outcome, label: &str) {
    let (got, score, rules) = outcome(&ctx).await;
    assert_eq!(
        got, want,
        "{label}: expected {want:?}, got {got:?} (score {score}, matched [{rules}])"
    );
}

/// Assert the destructive-action filter itself contributes NOTHING — the #68
/// guardrail that ordinary development operations are not flagged as
/// destructive. (The composite pipeline outcome may differ if an orthogonal
/// filter fires; see `s3_remove_staging_object_*`.)
async fn assert_destructive_action_silent(ctx: ToolCallContext, label: &str) {
    let proxy = production_filter_registry();
    let d = proxy.evaluate(&ctx).await;
    let da: Vec<_> = d
        .filter_results
        .iter()
        .filter(|r| r.matched && r.filter_name == "destructive-action")
        .map(|r| format!("{}={}", r.rule_id, r.score))
        .collect();
    assert!(
        da.is_empty(),
        "{label}: destructive-action filter must not fire, got {da:?}"
    );
}

#[tokio::test]
async fn drop_database_against_prod_rds_denies() {
    assert_outcome(
        shell("psql -h prod-db.cluster-abc.us-east-1.rds.amazonaws.com -c DROP DATABASE prod"),
        Outcome::Deny,
        "DROP DATABASE on prod RDS",
    )
    .await;
}

#[tokio::test]
async fn truncate_non_prod_queues() {
    assert_outcome(
        shell("psql -c TRUNCATE users"),
        Outcome::Queue,
        "TRUNCATE users",
    )
    .await;
}

#[tokio::test]
async fn rm_rf_database_data_dir_denies() {
    assert_outcome(
        shell("rm -rf /var/lib/postgresql/data"),
        Outcome::Deny,
        "rm -rf database data dir",
    )
    .await;
    // Supervisor view: the unlink syscalls underneath also deny.
    assert_outcome(
        file_delete("/var/lib/postgresql/data/base/1/2836"),
        Outcome::Deny,
        "FileDelete under database data dir",
    )
    .await;
}

#[tokio::test]
async fn rm_rf_node_modules_allows() {
    assert_outcome(
        shell("rm -rf ./node_modules"),
        Outcome::Allow,
        "rm -rf node_modules (regression)",
    )
    .await;
}

#[tokio::test]
async fn drop_table_non_prod_queues() {
    assert_outcome(
        shell("mysql -e DROP TABLE orders"),
        Outcome::Queue,
        "DROP TABLE, no prod host",
    )
    .await;
}

#[tokio::test]
async fn s3_remove_prod_bucket_denies() {
    assert_outcome(
        shell("aws s3 rb s3://prod-backups --force"),
        Outcome::Deny,
        "s3 rb prod-backups",
    )
    .await;
}

#[tokio::test]
async fn s3_remove_staging_object_allows() {
    // §1.4: a single-object, non-production delete is routine and must ALLOW.
    // The destructive-action filter stays silent, and (after the egress
    // object-storage-URI fix) `egress-policy` no longer flags the `s3://…`
    // bucket as an unknown network destination, so the composite is ALLOW.
    let cmd = "aws s3 rm s3://staging-builds/old-artifact.zip";
    assert_destructive_action_silent(shell(cmd), "s3 rm: destructive-action silent").await;
    assert_outcome(
        shell(cmd),
        Outcome::Allow,
        "s3 rm single staging object (regression)",
    )
    .await;
}

#[tokio::test]
async fn terraform_destroy_prod_vs_staging() {
    assert_outcome(
        shell_in_cwd("terraform destroy", "/srv/prod/infra"),
        Outcome::Deny,
        "terraform destroy in prod cwd",
    )
    .await;
    assert_outcome(
        shell_in_cwd("terraform destroy", "/home/u/staging/infra"),
        Outcome::Queue,
        "terraform destroy in staging cwd",
    )
    .await;
}

#[tokio::test]
async fn kubectl_delete_prod_namespace_denies() {
    assert_outcome(
        shell("kubectl delete namespace prod"),
        Outcome::Deny,
        "kubectl delete namespace prod",
    )
    .await;
}

#[tokio::test]
async fn dd_to_device_denies() {
    assert_outcome(
        shell("dd if=/dev/zero of=/dev/sda"),
        Outcome::Deny,
        "dd to raw device",
    )
    .await;
}

#[tokio::test]
async fn mkfs_denies() {
    assert_outcome(shell("mkfs.ext4 /dev/sdb1"), Outcome::Deny, "mkfs.ext4").await;
}

#[tokio::test]
async fn helm_uninstall_test_chart_queues() {
    assert_outcome(
        shell("helm uninstall my-test-chart"),
        Outcome::Queue,
        "helm uninstall test chart",
    )
    .await;
}

#[tokio::test]
async fn benign_read_allows() {
    assert_outcome(shell("cat /etc/hostname"), Outcome::Allow, "benign read").await;
}
