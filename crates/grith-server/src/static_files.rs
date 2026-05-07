// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Static file serving for the embedded React dashboard.

use axum::response::Html;
use axum::routing::get;
use axum::Router;
use tower_http::services::ServeDir;

use crate::AppState;

/// Add static file serving to the router.
/// Serves files from the dashboard directory with SPA fallback.
///
/// Static assets (/assets/*, favicon) are served directly from the dist
/// directory.  All other non-API paths receive index.html so React Router
/// can handle client-side routing.
pub fn add_static_serving(router: Router<AppState>, dashboard_dir: &str) -> Router<AppState> {
    let path = std::path::Path::new(dashboard_dir);

    if path.exists() && path.join("index.html").exists() {
        // Read index.html into memory at startup for the SPA fallback handler.
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

        // Serve hashed build assets (JS, CSS, sourcemaps) from dist/assets/.
        let assets_dir = path.join("assets");
        let mut router = router.nest_service("/assets", ServeDir::new(assets_dir));

        // Serve any other static files at the root of dist/ (e.g. grith.svg).
        for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() && entry_path.file_name().unwrap_or_default() != "index.html" {
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
                            async move {
                                (
                                    [(axum::http::header::CONTENT_TYPE, content_type)],
                                    body,
                                )
                            }
                        }),
                    );
                }
            }
        }

        // SPA fallback: any non-API, non-asset path gets index.html so
        // React Router can handle client-side routes.
        router.fallback(get(move || {
            let html = index_html.clone();
            async move { Html(html) }
        }))
    } else {
        // Dashboard not built — serve a placeholder page
        router.fallback(get(dashboard_not_built))
    }
}

fn mime_from_extension(filename: &str) -> String {
    match filename.rsplit('.').next() {
        Some("svg") => "image/svg+xml".into(),
        Some("png") => "image/png".into(),
        Some("ico") => "image/x-icon".into(),
        Some("json") => "application/json".into(),
        Some("txt") => "text/plain".into(),
        _ => "application/octet-stream".into(),
    }
}

async fn dashboard_not_built() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
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
        <p>The dashboard has not been built yet. To build it, run:</p>
        <code>cd dashboard && npm install && npm run build</code>
        <p>The API is available at <a href="/api/health" style="color:#7c3aed">/api/health</a></p>
    </div>
</body>
</html>"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dashboard_not_built_page() {
        let response = dashboard_not_built().await;
        let html = response.0;
        assert!(html.contains("grith dashboard"));
        assert!(html.contains("npm run build"));
    }

    #[test]
    fn test_mime_from_extension() {
        assert_eq!(mime_from_extension("grith.svg"), "image/svg+xml");
        assert_eq!(mime_from_extension("icon.png"), "image/png");
        assert_eq!(mime_from_extension("data.json"), "application/json");
        assert_eq!(mime_from_extension("unknown"), "application/octet-stream");
    }
}
