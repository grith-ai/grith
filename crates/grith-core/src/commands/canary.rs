// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! `grith canary` subcommand — manage canary tokens (list, add, remove, rotate).

use crate::daemon;
use grith_proxy::filters::canary::{resolve_canary_value, CanaryToken};

pub fn cmd_canary(daemon: &daemon::Daemon, action: crate::CanaryAction) -> anyhow::Result<()> {
    match action {
        crate::CanaryAction::List => {
            let tokens = daemon.canary_registry.list();
            if tokens.is_empty() {
                println!("No canary tokens registered.");
                return Ok(());
            }
            println!("Registered canary tokens ({}):", tokens.len());
            for token in tokens {
                println!("  {} | {} | {}", token.id, token.label, token.value);
            }
        }
        crate::CanaryAction::Add {
            label,
            value,
            generate,
        } => {
            let value = resolve_canary_value(value, generate).map_err(anyhow::Error::msg)?;
            let token = CanaryToken {
                id: uuid::Uuid::new_v4(),
                label,
                value,
            };
            daemon.canary_registry.add(token.clone());
            println!("Added canary:");
            println!("  id:    {}", token.id);
            println!("  label: {}", token.label);
            println!("  value: {}", token.value);
        }
        crate::CanaryAction::Remove { id } => {
            let id = uuid::Uuid::parse_str(&id)
                .map_err(|_| anyhow::anyhow!("invalid canary ID: {id}"))?;
            if daemon.canary_registry.remove(&id) {
                println!("Removed canary {id}");
            } else {
                println!("Canary not found: {id}");
            }
        }
        crate::CanaryAction::Rotate {
            id,
            value,
            generate,
        } => {
            let id = uuid::Uuid::parse_str(&id)
                .map_err(|_| anyhow::anyhow!("invalid canary ID: {id}"))?;
            let value = resolve_canary_value(value, generate).map_err(anyhow::Error::msg)?;
            match daemon.canary_registry.rotate(&id, value) {
                Some(token) => {
                    println!("Rotated canary:");
                    println!("  old id: {}", id);
                    println!("  new id: {}", token.id);
                    println!("  label:  {}", token.label);
                    println!("  value:  {}", token.value);
                }
                None => {
                    println!("Canary not found: {id}");
                }
            }
        }
    }
    Ok(())
}
