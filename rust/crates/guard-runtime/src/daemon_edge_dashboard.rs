//! The dashboard the daemon serves: its HTML shell on every dashboard route,
//! the bundled static files and the short approval links, as
//! `server_dashboard_support.py` and `dashboard_bundle.py` did.
//!
//! Every file the dashboard serves (`index.html`, `assets/`, `brand/` and the
//! root icons) is read into memory the first time the bundle is asked for and
//! kept for the life of the process. So an in-place upgrade never pairs a new
//! dashboard with this daemon's API. And once the daemon has started, serving
//! never depends on the folder: a frozen launcher hands the daemon its own
//! temporary unpack folder, which is deleted when that launcher exits. A
//! folder that gave nothing is read again on the next request. The shell is
//! stamped with the fingerprint of `index.html` and `assets/`, so a tab left
//! open across a restart can tell it is stale.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use sha2::{Digest, Sha256};

use super::super::http::Request;

/// `_DASHBOARD_CSP`.
const DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
/// `_ROOT_STATIC_FILES`.
const ROOT_STATIC_FILES: [&str; 4] = [
    "/favicon.svg",
    "/favicon.ico",
    "/favicon-16x16.png",
    "/favicon-32x32.png",
];
/// `_is_dashboard_route`'s exact paths.
const DASHBOARD_ROUTES: [&str; 19] = [
    "/",
    "/home",
    "/dashboard",
    "/inbox",
    "/protect",
    "/evidence",
    "/extensions",
    "/supply-chain",
    "/audit",
    "/policy",
    "/feed-health",
    "/workspaces",
    "/releases",
    "/settings",
    "/cigar",
    "/about",
    "/protection/repair",
    "/requests",
    "/approvals",
];
const NO_STORE: &str =
    "Cache-Control: no-store, max-age=0\r\nPragma: no-cache\r\nExpires: 0\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n";

struct Bundle {
    files: HashMap<String, Vec<u8>>,
    build: Option<String>,
}

static PINNED: LazyLock<Mutex<HashMap<PathBuf, &'static Bundle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NO_BUNDLE: LazyLock<Bundle> = LazyLock::new(|| Bundle {
    files: HashMap::new(),
    build: None,
});

/// `_is_public_static_path`: files any page may load with a plain tag, so
/// they are served without an origin check.
pub(super) fn is_public_static(path: &str) -> bool {
    ROOT_STATIC_FILES.contains(&path) || path.starts_with("/assets/") || path.starts_with("/brand/")
}

/// Whether the dashboard answers this `GET` path.
pub(super) fn owns(path: &str) -> bool {
    is_public_static(path) || is_dashboard_route(path)
}

fn is_dashboard_route(path: &str) -> bool {
    DASHBOARD_ROUTES.contains(&path)
        || path.starts_with("/requests/")
        || path.starts_with("/apps/")
        || path.starts_with("/extensions/")
        || (path.starts_with("/approvals/") && !path.ends_with("/decision"))
}

/// The whole response for a dashboard `GET`, or `None` when the edge has no
/// dashboard directory to serve from.
pub(super) fn respond(
    request: &Request<'_>,
    static_dir: Option<&Path>,
    auth_key: &[u8],
    dashboard_build: Option<&str>,
) -> Option<Vec<u8>> {
    let static_dir = static_dir?;
    if is_public_static(request.path) {
        return Some(static_file(static_dir, &request.path[1..], dashboard_build));
    }
    if let Some(location) = std::str::from_utf8(auth_key).ok().and_then(|key| {
        crate::native_review_link::now_micros()
            .and_then(|now| crate::native_review_link::handoff_location(request.path, key, now))
    }) {
        return Some(redirect(&location, dashboard_build));
    }
    Some(shell(static_dir, dashboard_build))
}

/// The pinned bundle's fingerprint, or `None` when no dashboard is bundled.
pub(super) fn build_id(static_dir: &Path) -> Option<String> {
    pinned(static_dir).build.clone()
}

fn pinned(static_dir: &Path) -> &'static Bundle {
    let mut pinned = PINNED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(bundle) = pinned.get(static_dir) {
        return bundle;
    }
    let bundle = read_bundle(static_dir);
    // A folder that gave nothing, missing or unreadable, is read again on the
    // next request instead of serving a 503 for the life of the process.
    if bundle.files.is_empty() {
        return &NO_BUNDLE;
    }
    let bundle: &'static Bundle = Box::leak(Box::new(bundle));
    pinned.insert(static_dir.to_path_buf(), bundle);
    bundle
}

/// `_read_bundle` and `dashboard_build_id`: every file the dashboard serves.
fn read_bundle(static_dir: &Path) -> Bundle {
    let mut files = HashMap::new();
    if let Ok(root) = fs::canonicalize(static_dir) {
        let top_level =
            std::iter::once("index.html").chain(ROOT_STATIC_FILES.iter().map(|path| &path[1..]));
        for name in top_level {
            insert_file(&root, &root.join(name), &mut files);
        }
        let mut pending = vec![root.join("assets"), root.join("brand")];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                match entry.file_type() {
                    Ok(kind) if kind.is_dir() => pending.push(entry.path()),
                    Ok(_) => insert_file(&root, &entry.path(), &mut files),
                    Err(_) => {}
                }
            }
        }
    }
    let mut names: Vec<&String> = files.keys().filter(|name| is_fingerprinted(name)).collect();
    let build = (!names.is_empty()).then(|| {
        names.sort();
        let mut digest = Sha256::new();
        for name in names {
            digest.update(name.as_bytes());
            digest.update(b"\0");
            digest.update(Sha256::digest(&files[name]));
        }
        hex::encode(digest.finalize())[..20].to_owned()
    });
    Bundle { files, build }
}

/// Reads one file into the bundle under its path relative to `root`, unless
/// it resolves outside `root`, as a symbolic link can.
fn insert_file(root: &Path, path: &Path, files: &mut HashMap<String, Vec<u8>>) {
    let Ok(target) = fs::canonicalize(path) else {
        return;
    };
    if !target.starts_with(root) || !target.is_file() {
        return;
    }
    let Some(relative) = path.strip_prefix(root).ok().and_then(Path::to_str) else {
        return;
    };
    if let Ok(bytes) = fs::read(&target) {
        files.insert(relative.replace('\\', "/"), bytes);
    }
}

/// The files the build id covers: the dashboard itself, not its images, so
/// the id names the same build whichever icons sit beside it.
fn is_fingerprinted(relative: &str) -> bool {
    relative == "index.html" || relative.starts_with("assets/")
}

/// `_write_static_asset`.
fn static_file(static_dir: &Path, relative: &str, dashboard_build: Option<&str>) -> Vec<u8> {
    let Some(body) = pinned(static_dir).files.get(relative).cloned() else {
        return head_only(404, "Not Found", dashboard_build);
    };
    let mut head = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n{NO_STORE}",
        content_type(relative),
        body.len()
    );
    finish(&mut head, dashboard_build);
    let mut response = head.into_bytes();
    response.extend_from_slice(&body);
    response
}

/// `_write_dashboard_shell`.
fn shell(static_dir: &Path, dashboard_build: Option<&str>) -> Vec<u8> {
    let bundle = pinned(static_dir);
    let (Some(index), true) = (
        bundle.files.get("index.html"),
        bundle.files.contains_key("assets/guard-dashboard.js"),
    ) else {
        return super::json_response(
            503,
            &serde_json::json!({"error": "dashboard_bundle_missing"}),
            dashboard_build,
            None,
            false,
        );
    };
    let body = stamp(index, bundle.build.as_deref());
    let mut head = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n{NO_STORE}Content-Security-Policy: {DASHBOARD_CSP}\r\n",
        body.len()
    );
    finish(&mut head, dashboard_build);
    let mut response = head.into_bytes();
    response.extend_from_slice(&body);
    response
}

/// `stamp_dashboard_build`.
fn stamp(index: &[u8], build: Option<&str>) -> Vec<u8> {
    const HEAD_END: &[u8] = b"</head>";
    let (Some(build), Some(at)) = (
        build,
        index
            .windows(HEAD_END.len())
            .position(|window| window == HEAD_END),
    ) else {
        return index.to_vec();
    };
    let meta = format!("<meta name=\"guard-dashboard-build\" content=\"{build}\" />");
    let mut stamped = Vec::with_capacity(index.len() + meta.len());
    stamped.extend_from_slice(&index[..at]);
    stamped.extend_from_slice(meta.as_bytes());
    stamped.extend_from_slice(&index[at..]);
    stamped
}

/// `_serve_approval_handoff`.
fn redirect(location: &str, dashboard_build: Option<&str>) -> Vec<u8> {
    let mut head = format!(
        "HTTP/1.0 303 See Other\r\nLocation: {location}\r\nCache-Control: no-store, max-age=0\r\nReferrer-Policy: no-referrer\r\nContent-Length: 0\r\n"
    );
    finish(&mut head, dashboard_build);
    head.into_bytes()
}

fn head_only(status: u16, reason: &str, dashboard_build: Option<&str>) -> Vec<u8> {
    let mut head = format!("HTTP/1.0 {status} {reason}\r\n");
    finish(&mut head, dashboard_build);
    head.into_bytes()
}

fn finish(head: &mut String, dashboard_build: Option<&str>) {
    if let Some(build) = dashboard_build {
        head.push_str(&format!("X-Guard-Dashboard-Build: {build}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
}

/// `mimetypes.guess_type` for the files a dashboard bundle holds.
fn content_type(relative: &str) -> &'static str {
    let extension = relative
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" => "text/plain",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
#[path = "daemon_edge_dashboard_tests.rs"]
mod tests;
