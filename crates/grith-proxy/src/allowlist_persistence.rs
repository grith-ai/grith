// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Persistent allowlist helpers for `allow_always` review actions.

use crate::filters::allowlist::{AllowlistConfig, ListEntry};
use crate::types::ToolCallContext;
use std::path::{Path, PathBuf};

const USER_ALLOWLIST_RELATIVE_PATH: &str = "grith/filters/allowlist.toml";

#[derive(Debug, thiserror::Error)]
pub enum AllowlistPersistenceError {
    #[error("unable to resolve user config directory")]
    ConfigDirUnavailable,
    #[error("failed to create allowlist directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read allowlist file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse allowlist file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("failed to serialize allowlist: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("failed to write allowlist file {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Resolve the persistent user allowlist file path.
pub fn user_allowlist_path() -> Result<PathBuf, AllowlistPersistenceError> {
    dirs::config_dir()
        .map(|dir| dir.join(USER_ALLOWLIST_RELATIVE_PATH))
        .ok_or(AllowlistPersistenceError::ConfigDirUnavailable)
}

/// Load allowlist config from a specific path.
///
/// Missing files return an empty config.
pub fn load_allowlist_from_path(path: &Path) -> Result<AllowlistConfig, AllowlistPersistenceError> {
    if !path.exists() {
        return Ok(AllowlistConfig::default());
    }
    let content =
        std::fs::read_to_string(path).map_err(|source| AllowlistPersistenceError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    toml::from_str::<AllowlistConfig>(&content).map_err(|source| AllowlistPersistenceError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Load the persistent user allowlist file.
pub fn load_user_allowlist() -> Result<AllowlistConfig, AllowlistPersistenceError> {
    let path = user_allowlist_path()?;
    load_allowlist_from_path(&path)
}

/// Persist an `allow_always` entry for the provided context.
///
/// Returns the written path if an entry was derived, or `None` if the context
/// type has no stable allowlist target.
pub fn persist_allow_always(
    ctx: &ToolCallContext,
) -> Result<Option<PathBuf>, AllowlistPersistenceError> {
    let path = user_allowlist_path()?;
    persist_allow_always_at_path(&path, ctx)
}

/// Persist an `allow_always` entry to an explicit path (primarily for tests).
pub fn persist_allow_always_at_path(
    path: &Path,
    ctx: &ToolCallContext,
) -> Result<Option<PathBuf>, AllowlistPersistenceError> {
    let Some(pattern) = allowlist_pattern_for_context(ctx) else {
        return Ok(None);
    };
    let entry = ListEntry {
        pattern,
        plugins: vec![ctx.plugin_id.clone()],
    };
    persist_allow_entry_at_path(path, &entry)?;
    Ok(Some(path.to_path_buf()))
}

fn persist_allow_entry_at_path(
    path: &Path,
    entry: &ListEntry,
) -> Result<(), AllowlistPersistenceError> {
    let mut config = load_allowlist_from_path(path)?;
    if !config
        .allow
        .iter()
        .any(|e| e.pattern == entry.pattern && e.plugins == entry.plugins)
    {
        config.allow.push(entry.clone());
    }
    write_allowlist(path, &config)
}

fn write_allowlist(path: &Path, config: &AllowlistConfig) -> Result<(), AllowlistPersistenceError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| AllowlistPersistenceError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let content = toml::to_string_pretty(config)?;
    std::fs::write(path, content).map_err(|source| AllowlistPersistenceError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn allowlist_pattern_for_context(ctx: &ToolCallContext) -> Option<String> {
    if let Some(path) = ctx.path() {
        return Some(path.to_string());
    }
    if let Some(url) = ctx.url() {
        if let Some(host) = host_from_url(url) {
            return Some(format!("*://{host}/*"));
        }
        return Some(url.to_string());
    }
    if let Some(command) = ctx.full_command() {
        return Some(command);
    }
    if let Some((addr, port)) = ctx.address() {
        return Some(format!("{addr}:{port}"));
    }
    None
}

fn host_from_url(url: &str) -> Option<&str> {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = authority.split(':').next().unwrap_or(authority).trim();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn file_read_ctx(path: &str) -> ToolCallContext {
        ToolCallContext::new(
            "builtin-agent",
            ToolCallType::FileRead {
                path: path.to_string(),
            },
            Uuid::new_v4(),
        )
    }

    #[test]
    fn persist_allow_always_writes_and_deduplicates() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allowlist.toml");
        let ctx = file_read_ctx("/etc/hosts");

        let first = persist_allow_always_at_path(&path, &ctx).unwrap();
        assert_eq!(first.as_deref(), Some(path.as_path()));

        let second = persist_allow_always_at_path(&path, &ctx).unwrap();
        assert_eq!(second.as_deref(), Some(path.as_path()));

        let loaded = load_allowlist_from_path(&path).unwrap();
        assert_eq!(loaded.allow.len(), 1);
        assert_eq!(loaded.allow[0].pattern, "/etc/hosts");
        assert_eq!(loaded.allow[0].plugins, vec!["builtin-agent".to_string()]);
    }

    #[test]
    fn persist_allow_always_http_uses_host_pattern() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allowlist.toml");
        let ctx = ToolCallContext::new(
            "supervisor:codex",
            ToolCallType::HttpRequest {
                method: "GET".to_string(),
                url: "https://api.example.com/v1/chat".to_string(),
            },
            Uuid::new_v4(),
        );

        persist_allow_always_at_path(&path, &ctx).unwrap();
        let loaded = load_allowlist_from_path(&path).unwrap();
        assert_eq!(loaded.allow.len(), 1);
        assert_eq!(loaded.allow[0].pattern, "*://api.example.com/*");
        assert_eq!(
            loaded.allow[0].plugins,
            vec!["supervisor:codex".to_string()]
        );
    }
}
