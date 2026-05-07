// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Offline signing tool for remote profile overlay manifests.
//!
//! Reads `profiles.remote.toml`, validates the restricted schema and profile
//! names against the bundled `profiles.toml`, canonicalizes the payload, signs
//! with an Ed25519 private key, and emits the final signed JSON manifest.
//!
//! Usage:
//!   cargo run -p grith-core --bin sign-profiles -- \
//!     --input config/supervisor/profiles.remote.toml \
//!     --output dist/profiles.latest.json \
//!     --version 1 \
//!     --key-file /path/to/profile-signing.key
//!
//! The private key file should contain a 32-byte Ed25519 seed encoded as
//! 64 lowercase hex characters. Alternatively, set the PROFILE_SIGNING_KEY
//! env var with the same hex content.

use base64::prelude::*;
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[allow(dead_code)]
#[path = "../profile_manifest.rs"]
mod profile_manifest;

#[derive(Parser)]
#[command(
    name = "sign-profiles",
    about = "Sign a remote profile overlay manifest"
)]
struct Args {
    /// Path to profiles.remote.toml
    #[arg(long)]
    input: PathBuf,

    /// Output path for the signed JSON manifest
    #[arg(long)]
    output: PathBuf,

    /// Monotonically increasing version number
    #[arg(long)]
    version: u64,

    /// Path to the signing key file (hex-encoded 32-byte seed).
    /// If not provided, reads from PROFILE_SIGNING_KEY env var.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

/// TOML source format for profiles.remote.toml.
#[derive(Deserialize)]
struct RemoteTomlSource {
    schema_version: u32,
    min_grith_version: String,
    changelog: String,
    #[serde(default)]
    profiles: HashMap<String, RemoteTomlOverlay>,
}

#[derive(Deserialize)]
struct RemoteTomlOverlay {
    #[serde(default)]
    routine_paths: Vec<String>,
    #[serde(default)]
    routine_commands: Vec<String>,
    #[serde(default)]
    routine_destinations: Vec<String>,
    #[serde(default)]
    readonly_paths: Vec<String>,
    #[serde(default)]
    readonly_path_patterns: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 1. Read and parse the TOML source.
    let toml_content = std::fs::read_to_string(&args.input)?;
    let source: RemoteTomlSource = toml::from_str(&toml_content)?;

    if source.schema_version != 1 {
        anyhow::bail!(
            "unsupported schema_version: {} (expected 1)",
            source.schema_version
        );
    }

    // 2. Load bundled profiles and get known names.
    let bundled = grith_supervisor::SupervisorProfile::load_bundled_config()
        .map_err(|e| anyhow::anyhow!("failed to load bundled profiles: {e}"))?;
    let known_names: std::collections::HashSet<String> =
        bundled.profiles.iter().map(|p| p.name.clone()).collect();

    // 3. Validate profile names and entries.
    for (name, overlay) in &source.profiles {
        if !known_names.contains(name) {
            anyhow::bail!("unknown profile name: {name}");
        }
        validate_overlay(name, overlay)?;
    }

    // 4. Build the manifest JSON (without signature).
    let profiles: HashMap<String, profile_manifest::RemoteProfileOverlay> = source
        .profiles
        .iter()
        .map(|(name, overlay)| {
            (
                name.clone(),
                profile_manifest::RemoteProfileOverlay {
                    routine_paths: overlay.routine_paths.clone(),
                    routine_commands: overlay.routine_commands.clone(),
                    routine_destinations: overlay.routine_destinations.clone(),
                    readonly_paths: overlay.readonly_paths.clone(),
                    readonly_path_patterns: overlay.readonly_path_patterns.clone(),
                },
            )
        })
        .collect();

    let released_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut manifest = profile_manifest::RemoteProfileManifest {
        schema_version: source.schema_version,
        profiles_version: args.version,
        min_grith_version: source.min_grith_version,
        released_at: released_at.clone(),
        changelog: source.changelog,
        profiles,
        signature: String::new(),
    };
    let canonical = profile_manifest::canonicalize_manifest(&manifest);

    // 5. Load signing key.
    let signing_key = load_signing_key(args.key_file.as_deref())?;

    // 6. Sign.
    let signature = signing_key.sign(canonical.as_bytes());
    manifest.signature = BASE64_STANDARD.encode(signature.to_bytes());

    let output_json = serde_json::to_string_pretty(&manifest)?;

    // 8. Write output.
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, &output_json)?;

    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let mut sorted_names: Vec<&String> = manifest.profiles.keys().collect();
    sorted_names.sort();
    eprintln!(
        "Signed manifest v{} written to {}",
        args.version,
        args.output.display()
    );
    eprintln!("  Public key (hex): {verifying_key_hex}");
    eprintln!("  Profiles: {}", sorted_names.len());
    eprintln!("  Released at: {released_at}");

    Ok(())
}

fn load_signing_key(key_file: Option<&std::path::Path>) -> anyhow::Result<SigningKey> {
    let hex_str = if let Some(path) = key_file {
        std::fs::read_to_string(path)?.trim().to_string()
    } else if let Ok(val) = std::env::var("PROFILE_SIGNING_KEY") {
        val.trim().to_string()
    } else {
        anyhow::bail!("no signing key provided. Use --key-file or set PROFILE_SIGNING_KEY env var");
    };

    let bytes =
        hex::decode(&hex_str).map_err(|e| anyhow::anyhow!("invalid hex in signing key: {e}"))?;

    if bytes.len() != 32 {
        anyhow::bail!(
            "signing key must be 32 bytes (got {}). Provide the ed25519 seed.",
            bytes.len()
        );
    }

    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid key length"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn validate_overlay(profile_name: &str, overlay: &RemoteTomlOverlay) -> anyhow::Result<()> {
    for v in &overlay.routine_destinations {
        profile_manifest::validate_destination(v)
            .map_err(|e| anyhow::anyhow!("{profile_name}.routine_destinations: {e}"))?;
    }
    for v in &overlay.routine_commands {
        profile_manifest::validate_command(v)
            .map_err(|e| anyhow::anyhow!("{profile_name}.routine_commands: {e}"))?;
    }
    for v in &overlay.routine_paths {
        profile_manifest::validate_routine_path(v)
            .map_err(|e| anyhow::anyhow!("{profile_name}.routine_paths: {e}"))?;
    }
    for v in &overlay.readonly_paths {
        profile_manifest::validate_readonly_path(v)
            .map_err(|e| anyhow::anyhow!("{profile_name}.readonly_paths: {e}"))?;
    }
    for v in &overlay.readonly_path_patterns {
        profile_manifest::validate_readonly_path_pattern(v)
            .map_err(|e| anyhow::anyhow!("{profile_name}.readonly_path_patterns: {e}"))?;
    }
    Ok(())
}
