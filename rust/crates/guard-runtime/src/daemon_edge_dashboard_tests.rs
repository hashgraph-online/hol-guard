use std::fs;
use std::path::Path;

use super::super::super::http::parse_request;
use super::{owns, respond};

fn bundle(dir: &Path) {
    fs::create_dir_all(dir.join("assets/chunks")).unwrap();
    fs::write(
        dir.join("index.html"),
        "<html><head></head><body></body></html>",
    )
    .unwrap();
    fs::write(dir.join("assets/guard-dashboard.js"), "app()").unwrap();
    fs::write(dir.join("assets/chunks/a.css"), "a{}").unwrap();
    fs::write(dir.join("favicon.svg"), "<svg/>").unwrap();
}

fn get(dir: Option<&Path>, path: &str) -> String {
    get_in(dir, path, Path::new("/nonexistent/guard-home"))
}

fn get_in(dir: Option<&Path>, path: &str, guard_home: &Path) -> String {
    let head = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
    let request = parse_request(head.as_bytes()).unwrap();
    let response = respond(&request, dir, b"k", Some("b1"), guard_home).unwrap();
    String::from_utf8(response).unwrap()
}

#[test]
fn owns_the_dashboard_routes_and_bundled_files_only() {
    for path in [
        "/",
        "/inbox",
        "/requests/abc",
        "/approvals/x",
        "/assets/a.js",
        "/favicon.svg",
        "/brand/x.png",
    ] {
        assert!(owns(path), "{path}");
    }
    for path in [
        "/v1/requests",
        "/approvals/x/decision",
        "/healthz",
        "/favicon.png",
    ] {
        assert!(!owns(path), "{path}");
    }
}

#[test]
fn serves_the_stamped_shell_with_its_policy() {
    let dir = tempfile::tempdir().unwrap();
    bundle(dir.path());
    let answer = get(Some(dir.path()), "/inbox");
    assert!(answer.starts_with("HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"));
    assert!(answer.contains("Content-Security-Policy: default-src 'self';"));
    assert!(answer.contains("X-Guard-Dashboard-Build: b1\r\n"));
    assert!(answer.contains("<meta name=\"guard-dashboard-build\" content=\""));
    assert!(answer.ends_with("</head><body></body></html>"));
}

#[test]
fn without_desktop_the_shell_carries_no_desktop_marker() {
    let dir = tempfile::tempdir().unwrap();
    bundle(dir.path());
    let answer = get(
        Some(dir.path()),
        "/requests/0123456789abcdef0123456789abcdef",
    );
    assert!(!answer.contains("guard-desktop-requests"), "{answer}");
}

#[cfg(unix)]
#[test]
fn a_desktop_that_opens_requests_marks_the_shell() {
    use crate::claude_hook_bridge_fixture::{write_private, GuardHome};

    let dir = tempfile::tempdir().unwrap();
    bundle(dir.path());
    let home = GuardHome::new("dashboard-desktop-marker");
    let marker = serde_json::json!({
        "version": 1,
        "scheme": "hol-guard-desktop",
        "routes": ["requests"],
        "app_path": home.home.to_string_lossy(),
    });
    write_private(
        &home.home.join("desktop-deep-link.json"),
        &marker.to_string(),
    );
    let answer = get_in(
        Some(dir.path()),
        "/requests/0123456789abcdef0123456789abcdef",
        &home.home,
    );
    assert!(
        answer.contains("<meta name=\"guard-desktop-requests\" content=\"1\" /></head>"),
        "{answer}"
    );
    assert!(answer.contains("<meta name=\"guard-dashboard-build\" content=\""));
}

#[test]
fn a_missing_bundle_is_a_503() {
    let dir = tempfile::tempdir().unwrap();
    let answer = get(Some(dir.path()), "/");
    assert!(answer.starts_with("HTTP/1.0 503 "));
    assert!(answer.ends_with("{\"error\":\"dashboard_bundle_missing\"}"));
}

#[test]
fn serves_pinned_and_root_files_and_nothing_outside() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("static");
    bundle(&root);
    fs::write(dir.path().join("outside.svg"), "no").unwrap();
    let css = get(Some(&root), "/assets/chunks/a.css");
    assert!(css.starts_with("HTTP/1.0 200 OK\r\nContent-Type: text/css\r\n"));
    assert!(css.ends_with("a{}"));
    assert!(get(Some(&root), "/favicon.svg").ends_with("<svg/>"));
    assert!(get(Some(&root), "/brand/../../outside.svg").starts_with("HTTP/1.0 404 "));
    assert!(get(Some(&root), "/assets/missing.js").starts_with("HTTP/1.0 404 "));
}

#[test]
fn the_pinned_bundle_outlives_an_upgrade_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    bundle(dir.path());
    assert!(get(Some(dir.path()), "/assets/guard-dashboard.js").ends_with("app()"));
    fs::write(dir.path().join("assets/guard-dashboard.js"), "new()").unwrap();
    assert!(get(Some(dir.path()), "/assets/guard-dashboard.js").ends_with("app()"));
}

#[test]
fn a_short_link_redirects_to_its_request_page() {
    let dir = tempfile::tempdir().unwrap();
    bundle(dir.path());
    let id = "0123456789abcdef0123456789abcdef";
    let forged = get(
        Some(dir.path()),
        &format!("/requests/{id}/1-{}", "0".repeat(32)),
    );
    assert!(forged.starts_with("HTTP/1.0 303 See Other\r\n"));
    assert!(forged.contains(&format!("Location: /requests/{id}\r\n")));
    let now = crate::native_review_link::now_micros().unwrap();
    let link = crate::native_review_link::handoff_url_for_tests(
        &format!("http://127.0.0.1:1/requests/{id}"),
        "k",
        now,
    )
    .unwrap();
    let path = link.strip_prefix("http://127.0.0.1:1").unwrap();
    let signed = get(Some(dir.path()), path);
    let location = format!("Location: /requests/{id}#guard-{}=gld1.", "token");
    assert!(signed.contains(&location), "{signed}");
}

#[test]
fn no_static_directory_leaves_the_route_unanswered() {
    let head = b"GET / HTTP/1.1\r\n\r\n";
    let request = parse_request(head).unwrap();
    assert!(respond(&request, None, b"k", None, Path::new("/nonexistent")).is_none());
}
