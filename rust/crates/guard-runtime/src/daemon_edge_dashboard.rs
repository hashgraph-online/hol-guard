//! The dashboard the daemon serves: its HTML shell on every dashboard route,
//! the bundled static files and the short approval links, as
//! `server_dashboard_support.py` and `dashboard_bundle.py` did.
//!
//! Every public file is read into memory when the daemon starts and kept for
//! the life of the process, so an in-place upgrade never pairs a new
//! dashboard with this daemon's API, and a bundle unpacked by a launcher that
//! later exits is still served. The shell is stamped with the pinned bundle's
//! fingerprint, so a tab left open across a restart can tell it is stale.
//!
//! When HOL Guard Desktop says it opens request links, the shell also carries
//! a `guard-desktop-requests` marker. A browser tab that lands on
//! `/requests/<id>` hands that request to Desktop, so a relayed approval link
//! still reaches the app even when it lost its signed code on the way.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

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
/// Read by the dashboard's request-page handoff to Desktop.
const DESKTOP_REQUESTS_META: &str = "<meta name=\"guard-desktop-requests\" content=\"1\" />";
const NO_STORE: &str =
    "Cache-Control: no-store, max-age=0\r\nPragma: no-cache\r\nExpires: 0\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n";

struct Bundle {
    /// `index.html` and `assets/`, which the build fingerprint covers.
    files: HashMap<String, Vec<u8>>,
    /// The root icons and `brand/`, read only from inside the directory.
    public: HashMap<String, Vec<u8>>,
    build: Option<String>,
}

static PINNED: LazyLock<Mutex<HashMap<PathBuf, Arc<Bundle>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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
/// dashboard directory to serve from. `guard_home` is where Desktop's
/// deep-link marker lives.
pub(super) fn respond(
    request: &Request<'_>,
    static_dir: Option<&Path>,
    auth_key: &[u8],
    dashboard_build: Option<&str>,
    guard_home: &Path,
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
    let desktop = crate::desktop_review_link::desktop_opens_requests(guard_home);
    Some(shell(static_dir, dashboard_build, desktop))
}

/// The pinned bundle's fingerprint, or `None` when no dashboard is bundled.
pub(super) fn build_id(static_dir: &Path) -> Option<String> {
    pinned(static_dir).build.clone()
}

fn pinned(static_dir: &Path) -> Arc<Bundle> {
    let mut pinned = PINNED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(bundle) = pinned.get(static_dir) {
        return Arc::clone(bundle);
    }
    let bundle = Arc::new(read_bundle(static_dir));
    // A directory read before it was unpacked, or after it was removed, is
    // not kept, so the next request looks again instead of serving nothing.
    if !bundle.files.is_empty() {
        pinned.insert(static_dir.to_path_buf(), Arc::clone(&bundle));
    }
    bundle
}

/// `_read_bundle` and `dashboard_build_id`, plus every other public file.
fn read_bundle(static_dir: &Path) -> Bundle {
    let mut files = HashMap::new();
    if let Ok(bytes) = fs::read(static_dir.join("index.html")) {
        files.insert("index.html".to_owned(), bytes);
    }
    read_tree(static_dir, "assets", &mut files, &|path| {
        fs::read(path).ok()
    });
    let mut public = HashMap::new();
    if let Ok(root) = fs::canonicalize(static_dir) {
        let read = |path: &Path| contained_read(&root, path);
        for name in ROOT_STATIC_FILES.map(|path| &path[1..]) {
            if let Some(bytes) = read(&static_dir.join(name)) {
                public.insert(name.to_owned(), bytes);
            }
        }
        read_tree(static_dir, "brand", &mut public, &read);
    }
    let build = (!files.is_empty()).then(|| {
        let mut names: Vec<&String> = files.keys().collect();
        names.sort();
        let mut digest = Sha256::new();
        for name in names {
            digest.update(name.as_bytes());
            digest.update(b"\0");
            digest.update(Sha256::digest(&files[name]));
        }
        hex::encode(digest.finalize())[..20].to_owned()
    });
    Bundle {
        files,
        public,
        build,
    }
}

/// Every file under `static_dir/top`, keyed by its `/`-separated path.
fn read_tree(
    static_dir: &Path,
    top: &str,
    files: &mut HashMap<String, Vec<u8>>,
    read: &dyn Fn(&Path) -> Option<Vec<u8>>,
) {
    let mut pending = vec![static_dir.join(top)];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(static_dir)
                    .ok()
                    .and_then(|relative| relative.to_str())
                    .map(|relative| relative.replace('\\', "/"));
                if let (Some(relative), Some(bytes)) = (relative, read(&path)) {
                    files.insert(relative, bytes);
                }
            }
        }
    }
}

/// A file that resolves inside `root`; anything resolving outside is not read.
fn contained_read(root: &Path, path: &Path) -> Option<Vec<u8>> {
    let target = fs::canonicalize(path).ok()?;
    (target.is_file() && target.starts_with(root) && target != root)
        .then(|| fs::read(&target).ok())
        .flatten()
}

fn is_pinned_path(relative: &str) -> bool {
    relative == "index.html" || relative == "assets" || relative.starts_with("assets/")
}

/// `_write_static_asset`.
fn static_file(static_dir: &Path, relative: &str, dashboard_build: Option<&str>) -> Vec<u8> {
    let bundle = pinned(static_dir);
    let body = if is_pinned_path(relative) {
        bundle.files.get(relative)
    } else {
        bundle.public.get(relative)
    };
    let Some(body) = body else {
        return head_only(404, "Not Found", dashboard_build);
    };
    let mut head = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n{NO_STORE}",
        content_type(relative),
        body.len()
    );
    finish(&mut head, dashboard_build);
    let mut response = head.into_bytes();
    response.extend_from_slice(body);
    response
}

/// `_write_dashboard_shell`.
fn shell(static_dir: &Path, dashboard_build: Option<&str>, desktop: bool) -> Vec<u8> {
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
    let body = stamp(index, bundle.build.as_deref(), desktop);
    let mut head = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n{NO_STORE}Content-Security-Policy: {DASHBOARD_CSP}\r\n",
        body.len()
    );
    finish(&mut head, dashboard_build);
    let mut response = head.into_bytes();
    response.extend_from_slice(&body);
    response
}

/// `stamp_dashboard_build`, plus the Desktop marker when Desktop opens
/// request links.
fn stamp(index: &[u8], build: Option<&str>, desktop: bool) -> Vec<u8> {
    const HEAD_END: &[u8] = b"</head>";
    let Some(at) = index
        .windows(HEAD_END.len())
        .position(|window| window == HEAD_END)
    else {
        return index.to_vec();
    };
    let mut meta = build
        .map(|build| format!("<meta name=\"guard-dashboard-build\" content=\"{build}\" />"))
        .unwrap_or_default();
    if desktop {
        meta.push_str(DESKTOP_REQUESTS_META);
    }
    if meta.is_empty() {
        return index.to_vec();
    }
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
