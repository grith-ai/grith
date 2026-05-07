// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith digest` subcommand — review and act on queued tool calls.

use crate::daemon;

pub fn cmd_digest(
    daemon: &daemon::Daemon,
    action: Option<crate::DigestAction>,
) -> anyhow::Result<()> {
    match action {
        None => {
            let pending = daemon.digest_queue.count_pending().unwrap_or(0);
            println!("Digest queue: {pending} pending items");

            let items = daemon.digest_queue.get_pending(20, 0).unwrap_or_default();
            if items.is_empty() {
                println!("  No pending digest items.");
            } else {
                for item in &items {
                    println!(
                        "  [{:.1}] {} — {}",
                        item.composite_score, item.tool_call_type, item.arguments_summary
                    );
                }
            }
        }
        Some(crate::DigestAction::Review) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(grith_cli::run_digest_review_session(&daemon.digest_queue))?;
        }
    }
    Ok(())
}
