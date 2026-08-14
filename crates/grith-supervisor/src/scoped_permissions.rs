// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Session-only directory-scoped permission defaults and validation.

use std::path::{Component, Path, PathBuf};

use grith_digest::ScopedAllowRequest;

/// A validated scoped request ready to insert into a session allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedScopedAllow {
    /// Canonical or safely normalized directory, always with a trailing slash.
    pub directory: String,
    /// Namespaced session allowlist entries selected by the reviewer.
    pub rules: Vec<String>,
    /// Warning shown when the directory does not yet exist.
    pub warning: Option<String>,
}

/// A best-effort path preview for the scope editor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePathPreview {
    /// Canonical or safely normalized directory, always with a trailing slash.
    pub resolved_directory: String,
    /// Whether the proposed directory currently exists.
    pub exists: bool,
}

/// Build the safe default scope for a displayed file operation.
///
/// The digest queue stores the `Display` form of `ToolCallType`, so this
/// helper deliberately parses only the small, explicit file-operation set
/// supported by v1.
pub fn default_scoped_allow(tool_call: &str) -> Option<ScopedAllowRequest> {
    let (target, read, write, delete, use_target_directory) =
        if let Some(path) = unary_target(tool_call, "FileRead") {
            (path, true, false, false, false)
        } else if let Some(path) = unary_target(tool_call, "DirList") {
            (path, true, false, false, true)
        } else if let Some(path) = unary_target(tool_call, "FileWrite") {
            (path, false, true, false, false)
        } else if let Some(path) = unary_target(tool_call, "FileAppend") {
            (path, false, true, false, false)
        } else if let Some(path) = unary_target(tool_call, "DirCreate") {
            (path, false, true, false, false)
        } else if let Some(path) = unary_target(tool_call, "FileDelete") {
            (path, false, false, true, false)
        } else {
            let body = unary_target(tool_call, "FileRename")?;
            let old_path = body.split_once(" -> ")?.0;
            (old_path, false, false, true, false)
        };

    let directory = if use_target_directory {
        PathBuf::from(target)
    } else {
        Path::new(target).parent()?.to_path_buf()
    };

    Some(ScopedAllowRequest {
        directory: with_trailing_separator(&directory.to_string_lossy()),
        read,
        write,
        delete,
        persist: false,
    })
}

/// Resolve a directory proposal for display without applying security policy.
pub fn preview_scope_path(directory: &str) -> Result<ScopePathPreview, String> {
    let (path, exists) = resolve_directory(directory)?;
    Ok(ScopePathPreview {
        resolved_directory: with_trailing_separator(&path.to_string_lossy()),
        exists,
    })
}

/// Validate and canonicalize a session-only scoped permission.
pub fn validate_scoped_allow(
    request: &ScopedAllowRequest,
    current_tool_call: &str,
) -> Result<ValidatedScopedAllow, String> {
    if request.persist {
        return Err("Persistent directory scopes are not available in v1".to_string());
    }
    if !request.read && !request.write && !request.delete {
        return Err("Select at least one operation".to_string());
    }

    let (directory, exists) = resolve_directory(&request.directory)?;
    reject_broad_or_sensitive_scope(&directory, request)?;

    let target = scoped_operation_target(current_tool_call)
        .ok_or_else(|| "This operation does not support directory scoping".to_string())?;
    let target = resolve_target(&target)?;
    if !target.starts_with(&directory) {
        return Err("The directory must contain the current operation target".to_string());
    }

    let directory = with_trailing_separator(&directory.to_string_lossy());
    let mut rules = Vec::with_capacity(3);
    if request.read {
        rules.push(format!("ro-prefix:{directory}"));
    }
    if request.write {
        rules.push(format!("write-prefix:{directory}"));
    }
    if request.delete {
        rules.push(format!("delete-prefix:{directory}"));
    }

    Ok(ValidatedScopedAllow {
        directory,
        rules,
        warning: (!exists).then(|| {
            "Directory does not exist; this scope is session-only and uses the resolved parent"
                .to_string()
        }),
    })
}

/// Return the path whose authority is consumed by the scoped operation.
pub(crate) fn scoped_operation_target(tool_call: &str) -> Option<String> {
    for kind in [
        "FileRead",
        "DirList",
        "FileWrite",
        "FileAppend",
        "DirCreate",
        "FileDelete",
    ] {
        if let Some(path) = unary_target(tool_call, kind) {
            return Some(path.to_string());
        }
    }
    unary_target(tool_call, "FileRename")
        .and_then(|body| body.split_once(" -> ").map(|(old, _)| old.to_string()))
}

/// Return the scoped authority target directly from an evaluated tool call.
pub(crate) fn scoped_call_target(call_type: &grith_proxy::types::ToolCallType) -> Option<&str> {
    use grith_proxy::types::ToolCallType;
    match call_type {
        ToolCallType::FileRead { path }
        | ToolCallType::DirList { path }
        | ToolCallType::FileWrite { path, .. }
        | ToolCallType::FileAppend { path }
        | ToolCallType::DirCreate { path }
        | ToolCallType::FileDelete { path } => Some(path),
        ToolCallType::FileRename { old_path, .. } => Some(old_path),
        _ => None,
    }
}

/// Resolve a filesystem target using the same existing-ancestor strategy as
/// directory validation. This keeps nonexistent create targets comparable to
/// a canonical directory without following a broader symlink silently.
pub(crate) fn resolve_target(path: &str) -> Result<PathBuf, String> {
    resolve_path(path).map(|(path, _)| path)
}

fn unary_target<'a>(tool_call: &'a str, kind: &str) -> Option<&'a str> {
    tool_call
        .strip_prefix(kind)?
        .strip_prefix('(')?
        .strip_suffix(')')
}

fn resolve_directory(directory: &str) -> Result<(PathBuf, bool), String> {
    let raw = Path::new(directory);
    if directory.trim().is_empty() {
        return Err("Directory cannot be empty".to_string());
    }
    if !raw.is_absolute() {
        return Err("Directory must be an absolute path".to_string());
    }

    let (resolved, exists) = resolve_path(directory)?;
    if exists && !resolved.is_dir() {
        return Err("Scope path must be a directory".to_string());
    }
    Ok((resolved, exists))
}

fn resolve_path(path: &str) -> Result<(PathBuf, bool), String> {
    let cleaned = normalize_absolute(Path::new(path))?;
    if cleaned.exists() {
        return std::fs::canonicalize(&cleaned)
            .map(|path| (path, true))
            .map_err(|e| format!("Could not resolve path: {e}"));
    }

    let mut ancestor = cleaned.as_path();
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| "Could not resolve an existing parent directory".to_string())?;
        suffix.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| "Could not resolve an existing parent directory".to_string())?;
    }
    let mut resolved = std::fs::canonicalize(ancestor)
        .map_err(|e| format!("Could not resolve parent directory: {e}"))?;
    for component in suffix.iter().rev() {
        resolved.push(component);
    }
    Ok((resolved, false))
}

fn normalize_absolute(path: &Path) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("Directory escapes the filesystem root".to_string());
                }
            }
        }
    }
    Ok(normalized)
}

fn reject_broad_or_sensitive_scope(
    directory: &Path,
    request: &ScopedAllowRequest,
) -> Result<(), String> {
    let normalized = directory.to_string_lossy().replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    let components: Vec<&str> = trimmed.split('/').filter(|part| !part.is_empty()).collect();
    let is_user_home = matches!(
        components.as_slice(),
        ["home", _] | ["Users", _] | ["users", _]
    );
    if trimmed.is_empty()
        || matches!(trimmed, "/home" | "/Users" | "/tmp" | "/var")
        || components.len() < 2
        || is_user_home
    {
        return Err("That directory scope is too broad".to_string());
    }

    let home = dirs::home_dir().and_then(|path| std::fs::canonicalize(path).ok());
    if let Some(home) = &home {
        if directory == home {
            return Err("The home directory cannot be scoped".to_string());
        }
    }

    let lower = format!("{}/", trimmed.to_ascii_lowercase());
    let is_sensitive_parent = lower.trim_end_matches('/').ends_with("/.config");

    let mut sensitive_roots = Vec::new();
    if let Some(home) = &home {
        for suffix in [
            ".ssh",
            ".aws",
            ".gnupg",
            ".kube",
            ".config/gcloud",
            ".mozilla",
            ".config/google-chrome",
            ".config/chromium",
            ".config/BraveSoftware",
            ".config/microsoft-edge",
        ] {
            sensitive_roots.push(home.join(suffix));
        }
    }
    for base in [dirs::config_dir(), dirs::data_dir(), dirs::cache_dir()]
        .into_iter()
        .flatten()
    {
        sensitive_roots.push(base.join("grith"));
    }

    // A parent such as ~/.config would sweep several unrelated credential
    // stores into one approval. Keep those broad sensitive parents blocked.
    // An explicitly selected sensitive directory may be scoped for reads in
    // this session, but write/delete authority remains single-request only.
    let contains_sensitive_root = sensitive_roots
        .iter()
        .any(|sensitive| sensitive != directory && sensitive.starts_with(directory));
    if is_sensitive_parent || contains_sensitive_root {
        return Err("Sensitive directories require single-request approval".to_string());
    }

    let targets_sensitive_directory = crate::syscall_map::is_sensitive_path(trimmed)
        || crate::syscall_map::is_sensitive_path(&lower)
        || sensitive_roots
            .iter()
            .any(|sensitive| directory.starts_with(sensitive));
    if targets_sensitive_directory && (request.write || request.delete) {
        return Err(
            "Sensitive directories only support read-only scope for this session".to_string(),
        );
    }

    if request.delete {
        if std::env::current_dir()
            .ok()
            .and_then(|path| std::fs::canonicalize(path).ok())
            .is_some_and(|project| project == directory)
        {
            return Err(
                "Delete scope for the project root is blocked; choose a subdirectory".to_string(),
            );
        }
        if let Some(home) = &home {
            if let Ok(relative) = directory.strip_prefix(home) {
                if relative
                    .components()
                    .next()
                    .and_then(|part| part.as_os_str().to_str())
                    .is_some_and(|part| part.starts_with('.'))
                {
                    return Err(
                        "Delete scopes are blocked for home configuration directories".to_string(),
                    );
                }
            }
        }
        if components.windows(3).any(|parts| {
            matches!(parts, ["home", _, hidden] | ["Users", _, hidden] | ["users", _, hidden]
                    if hidden.starts_with('.'))
        }) {
            return Err("Delete scopes are blocked for home configuration directories".to_string());
        }
    }

    Ok(())
}

fn with_trailing_separator(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if normalized.ends_with('/') {
        normalized
    } else {
        format!("{normalized}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_operation_intent() {
        let read = default_scoped_allow("FileRead(/repo/src/lib.rs)").unwrap();
        assert_eq!(read.directory, "/repo/src/");
        assert!(read.read);
        assert!(!read.write);
        assert!(!read.delete);

        let write = default_scoped_allow("FileWrite(/repo/src/lib.rs)").unwrap();
        assert!(write.write);
        assert!(!write.delete);

        let delete = default_scoped_allow("FileDelete(/repo/target/a.o)").unwrap();
        assert_eq!(delete.directory, "/repo/target/");
        assert!(delete.delete);
        assert!(!delete.write);

        let rename = default_scoped_allow("FileRename(/repo/old/a -> /repo/new/a)").unwrap();
        assert_eq!(rename.directory, "/repo/old/");
        assert!(rename.delete);

        let create = default_scoped_allow("DirCreate(/repo/new-dir)").unwrap();
        assert_eq!(create.directory, "/repo/");
        assert!(create.write);
    }

    #[test]
    fn non_file_operations_do_not_offer_scope() {
        assert!(default_scoped_allow("ProcessSpawn(cargo)").is_none());
        assert!(default_scoped_allow("FileChmod(/repo/a, 755)").is_none());
    }

    #[test]
    fn validation_rejects_broad_and_unrelated_scopes() {
        let broad = ScopedAllowRequest {
            directory: "/".to_string(),
            read: true,
            write: false,
            delete: false,
            persist: false,
        };
        assert!(validate_scoped_allow(&broad, "FileRead(/repo/a)").is_err());

        let unrelated = ScopedAllowRequest {
            directory: "/usr/share/".to_string(),
            ..broad
        };
        assert!(validate_scoped_allow(&unrelated, "FileRead(/repo/a)").is_err());

        let other_home = ScopedAllowRequest {
            directory: "/home/another-user/".to_string(),
            ..unrelated
        };
        assert!(
            validate_scoped_allow(&other_home, "FileRead(/home/another-user/document.txt)")
                .is_err()
        );
    }

    #[test]
    fn validation_rejects_sensitive_scope_parents() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let request = ScopedAllowRequest {
            directory: home.join(".config").to_string_lossy().into_owned(),
            read: true,
            write: false,
            delete: false,
            persist: false,
        };
        assert!(validate_scoped_allow(
            &request,
            &format!("FileRead({})", home.join(".config/example").display())
        )
        .is_err());
    }

    #[test]
    fn validation_allows_read_only_sensitive_session_scope() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let directory = home.join(".config/grith");
        let target = directory.join("daemon.token");
        let request = ScopedAllowRequest {
            directory: directory.to_string_lossy().into_owned(),
            read: true,
            write: false,
            delete: false,
            persist: false,
        };

        let validated =
            validate_scoped_allow(&request, &format!("FileRead({})", target.display())).unwrap();
        assert_eq!(validated.rules.len(), 1);
        assert!(validated.rules[0].starts_with("ro-prefix:"));
    }

    #[test]
    fn validation_rejects_sensitive_session_mutation_scope() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let directory = home.join(".config/grith");
        let target = directory.join("config.toml");
        let request = ScopedAllowRequest {
            directory: directory.to_string_lossy().into_owned(),
            read: false,
            write: true,
            delete: false,
            persist: false,
        };

        let error = validate_scoped_allow(&request, &format!("FileWrite({})", target.display()))
            .unwrap_err();
        assert!(error.contains("read-only"));
    }

    #[test]
    fn validation_allows_nonexistent_session_directory_with_warning() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("future");
        let target = directory.join("file.txt");
        let request = ScopedAllowRequest {
            directory: directory.to_string_lossy().into_owned(),
            read: false,
            write: true,
            delete: false,
            persist: false,
        };

        let validated =
            validate_scoped_allow(&request, &format!("FileWrite({})", target.display())).unwrap();
        assert!(validated.warning.is_some());
        assert_eq!(validated.rules.len(), 1);
        assert!(validated.rules[0].starts_with("write-prefix:"));
    }
}
