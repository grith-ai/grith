// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! grith-docgen — emit structured JSON describing the grith product surface,
//! for consumption by the docs site (grith-docs).
//!
//! Outputs four JSON files into `--out-dir`:
//!   - `config.json` — parsed from `config/default.toml`
//!   - `filters.json` — scanned from `crates/grith-proxy/src/filters/`,
//!     enriched from `crates/grith-docgen/data/filters.toml`
//!   - `cli.json`    — parsed from `crates/grith-core/src/main.rs` (best-effort
//!     regex extraction of clap derives)
//!   - `api.json`    — enriched from `crates/grith-docgen/data/api.toml` (curated)

mod api;
mod cli;
mod config;
mod filters;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "grith-docgen",
    version,
    about = "Generate JSON documentation data for grith-docs"
)]
struct Args {
    /// Path to the grith repository root.
    /// Defaults to the parent of the workspace this binary was built in.
    #[arg(long)]
    grith_root: Option<PathBuf>,

    /// Directory to write JSON files into.
    /// Defaults to ../grith-docs/src/data/generated relative to --grith-root.
    #[arg(long)]
    out_dir: Option<PathBuf>,

    /// Restrict emission to a subset of generators.
    #[arg(long, value_enum)]
    only: Vec<Generator>,

    /// Print what would be written without writing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
enum Generator {
    Config,
    Filters,
    Cli,
    Api,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let grith_root = match args.grith_root {
        Some(p) => p,
        None => default_grith_root()?,
    };
    let grith_root = grith_root
        .canonicalize()
        .with_context(|| format!("canonicalize grith_root: {}", grith_root.display()))?;

    let out_dir = match args.out_dir {
        Some(p) => p,
        None => grith_root
            .parent()
            .context("grith_root has no parent")?
            .join("grith-docs/src/data/generated"),
    };

    if !args.dry_run {
        std::fs::create_dir_all(&out_dir)
            .with_context(|| format!("create out_dir: {}", out_dir.display()))?;
    }

    let want = |g: Generator| args.only.is_empty() || args.only.contains(&g);

    println!("grith-docgen");
    println!("  grith_root: {}", grith_root.display());
    println!("  out_dir:    {}", out_dir.display());
    println!("  dry_run:    {}", args.dry_run);

    if want(Generator::Config) {
        let json = config::emit(&grith_root)?;
        write(&out_dir, "config.json", &json, args.dry_run)?;
    }
    if want(Generator::Filters) {
        let json = filters::emit(&grith_root)?;
        write(&out_dir, "filters.json", &json, args.dry_run)?;
    }
    if want(Generator::Cli) {
        let json = cli::emit(&grith_root)?;
        write(&out_dir, "cli.json", &json, args.dry_run)?;
    }
    if want(Generator::Api) {
        let json = api::emit(&grith_root)?;
        write(&out_dir, "api.json", &json, args.dry_run)?;
    }

    Ok(())
}

fn default_grith_root() -> Result<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Ok(PathBuf::from(manifest)
        .parent()
        .context("crate dir has no parent")?
        .parent()
        .context("crates/ dir has no parent")?
        .to_path_buf())
}

fn write(
    out_dir: &std::path::Path,
    name: &str,
    value: &serde_json::Value,
    dry_run: bool,
) -> Result<()> {
    let path = out_dir.join(name);
    let body = serde_json::to_string_pretty(value)? + "\n";
    if dry_run {
        println!(
            "  [dry-run] would write {} ({} bytes)",
            path.display(),
            body.len()
        );
    } else {
        std::fs::write(&path, &body).with_context(|| format!("write {}", path.display()))?;
        println!("  wrote {} ({} bytes)", path.display(), body.len());
    }
    Ok(())
}
