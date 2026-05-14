// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Ensure `dashboard/dist/index.html` exists before `include_dir!` runs at
//! compile time. CI builds the real dashboard with `npm run build` before
//! `cargo build`, so this just covers fresh-checkout / `cargo build`-without-
//! npm cases where the embedded dashboard would otherwise refuse to compile.
//! The placeholder content is what gets served if a user runs a locally-built
//! binary without first building the dashboard.

use std::fs;
use std::path::PathBuf;

const PLACEHOLDER: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>grith dashboard</title>
    <style>
        body { font-family: system-ui; background: #0a0a0a; color: #e0e0e0; display: flex;
               justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { text-align: center; max-width: 500px; padding: 2rem; }
        h1 { color: #7c3aed; }
        code { background: #1a1a2e; padding: 0.5rem 1rem; border-radius: 4px; display: block;
               margin: 1rem 0; font-size: 0.9rem; }
        p { color: #999; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>grith dashboard</h1>
        <p>This binary was built without a dashboard bundle. To build the
        dashboard and re-embed it, run:</p>
        <code>cd dashboard &amp;&amp; npm install &amp;&amp; npm run build</code>
        <p>then rebuild grith. Release binaries always ship with the
        dashboard pre-built.</p>
        <p>The API is available at <a href="/api/health" style="color:#7c3aed">/api/health</a></p>
    </div>
</body>
</html>"#;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dist = manifest.join("../../dashboard/dist");
    let index = dist.join("index.html");

    if !index.exists() {
        let _ = fs::create_dir_all(&dist);
        let _ = fs::write(&index, PLACEHOLDER);
    }

    // include_dir! emits its own rerun-if-changed for embedded files,
    // but cover the create-on-first-build case so the placeholder is
    // re-written if someone deletes the dist dir entirely.
    println!("cargo:rerun-if-changed=../../dashboard/dist/index.html");
}
