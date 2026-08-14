// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Static file serving for the embedded React dashboard.
//!
//! The dashboard's `dist/` tree is baked into the binary at build time via
//! [`include_dir!`] so release binaries ship with a working dashboard out
//! of the box (no separate `npm run build` step required after install).
//! A `dashboard_dir` config pointing at an existing on-disk `dist/` still
//! takes precedence so developers can iterate on the dashboard without
//! rebuilding the Rust binary.

use axum::extract::Request;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use include_dir::{include_dir, Dir};
use tower_http::services::ServeDir;

use crate::AppState;

/// Entire `dashboard/dist/` tree, baked in at build time. A `build.rs`
/// step ensures the path exists with at least an `index.html` placeholder
/// before this macro runs so fresh checkouts compile without `npm run
/// build`. CI builds the real dashboard with `npm ci && npm run build`
/// before `cargo build`, so release binaries ship the real bundle.
static DASHBOARD: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../dashboard/dist");

/// Add static file serving to the router.
///
/// Resolution order:
/// 1. If `dashboard_dir` exists on disk and contains `index.html`, serve
///    from disk (dev workflow — edit the dashboard, hit refresh).
/// 2. Otherwise serve from the embedded copy baked into the binary
///    (release workflow — works after a plain `install.sh`).
pub fn add_static_serving(router: Router<AppState>, dashboard_dir: &str) -> Router<AppState> {
    let path = std::path::Path::new(dashboard_dir);
    if path.exists() && path.join("index.html").exists() {
        tracing::info!(
            path = %path.display(),
            "serving dashboard from on-disk dist directory (dev override)"
        );
        return add_disk_serving(router, path);
    }
    tracing::info!("serving dashboard from embedded bundle");
    add_embedded_serving(router)
}

// ---------------------------------------------------------------------------
// Disk serving (dev override)
// ---------------------------------------------------------------------------

fn add_disk_serving(router: Router<AppState>, path: &std::path::Path) -> Router<AppState> {
    let index_html = match std::fs::read_to_string(path.join("index.html")) {
        Ok(content) => content,
        Err(e) => {
            tracing::error!(
                path = %path.join("index.html").display(),
                error = %e,
                "failed to read dashboard index.html"
            );
            String::new()
        }
    };

    let assets_dir = path.join("assets");
    let mut router = router.nest_service("/assets", ServeDir::new(assets_dir));

    for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
        let entry_path = entry.path();
        // Nest a ServeDir for every top-level subdirectory (fonts/, and any
        // future ones) so nested static files resolve in disk mode just like
        // they do in the embedded bundle. `assets/` is already nested above.
        if entry_path.is_dir() {
            if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
                if name != "assets" {
                    router = router.nest_service(&format!("/{name}"), ServeDir::new(&entry_path));
                }
            }
        } else if entry_path.is_file() && entry_path.file_name().unwrap_or_default() != "index.html"
        {
            if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
                let route = format!("/{name}");
                let file_bytes = match std::fs::read(&entry_path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::error!(
                            path = %entry_path.display(),
                            error = %e,
                            "failed to read dashboard static file, serving empty response"
                        );
                        Vec::new()
                    }
                };
                let mime = mime_from_extension(name);
                router = router.route(
                    &route,
                    get(move || {
                        let body = file_bytes.clone();
                        let content_type = mime.clone();
                        async move { ([(header::CONTENT_TYPE, content_type)], body) }
                    }),
                );
            }
        }
    }

    router.fallback(get(move || {
        let html = index_html.clone();
        async move { Html(html) }
    }))
}

// ---------------------------------------------------------------------------
// Embedded serving (default — release binaries)
// ---------------------------------------------------------------------------

fn add_embedded_serving(router: Router<AppState>) -> Router<AppState> {
    router.fallback(get(serve_embedded))
}

async fn serve_embedded(req: Request) -> Response {
    let raw = req.uri().path().trim_start_matches('/');
    // Empty path → index.html; otherwise look up the file directly.
    let lookup = if raw.is_empty() { "index.html" } else { raw };

    if let Some(file) = DASHBOARD.get_file(lookup) {
        let mime = mime_from_extension(lookup);
        return ([(header::CONTENT_TYPE, mime)], file.contents()).into_response();
    }

    // SPA fallback — unknown route, hand back index.html and let React
    // Router decide what to render (or show its own 404).
    match DASHBOARD.get_file("index.html") {
        Some(file) => {
            let html = file.contents_utf8().unwrap_or("").to_string();
            Html(html).into_response()
        }
        None => Html(String::new()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mime_from_extension(filename: &str) -> String {
    match filename.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8".into(),
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8".into(),
        Some("css") => "text/css; charset=utf-8".into(),
        Some("map") => "application/json".into(),
        Some("svg") => "image/svg+xml".into(),
        Some("png") => "image/png".into(),
        Some("jpg") | Some("jpeg") => "image/jpeg".into(),
        Some("gif") => "image/gif".into(),
        Some("webp") => "image/webp".into(),
        Some("ico") => "image/x-icon".into(),
        Some("woff") => "font/woff".into(),
        Some("woff2") => "font/woff2".into(),
        Some("ttf") => "font/ttf".into(),
        Some("otf") => "font/otf".into(),
        Some("json") => "application/json".into(),
        Some("wasm") => "application/wasm".into(),
        Some("txt") => "text/plain; charset=utf-8".into(),
        _ => "application/octet-stream".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_from_extension() {
        assert_eq!(mime_from_extension("grith.svg"), "image/svg+xml");
        assert_eq!(mime_from_extension("icon.png"), "image/png");
        assert_eq!(mime_from_extension("data.json"), "application/json");
        assert_eq!(
            mime_from_extension("app.js"),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(mime_from_extension("styles.css"), "text/css; charset=utf-8");
        assert_eq!(mime_from_extension("unknown"), "application/octet-stream");
    }

    /// Verify the build script left at least an index.html in the embedded
    /// dir — otherwise the binary would 404 on every page load.
    #[test]
    fn embedded_dashboard_has_index() {
        assert!(
            DASHBOARD.get_file("index.html").is_some(),
            "embedded dashboard is missing index.html — build.rs should have created a placeholder"
        );
    }
}
