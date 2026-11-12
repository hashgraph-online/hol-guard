use std::fs;
use std::path::Path;

use super::super::super::http::parse_request;
use super::{build_id, owns, respond};

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
    let head = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
    let request = parse_request(head.as_bytes()).unwrap();
    let response = respond(&request, dir, b"k", Some("b1")).unwrap();
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
fn a_missing_bundle_is_a_503() {
    let dir = tempfile::tempdir().unwrap();
    let answer = get(Some(dir.path()), "/");
    assert!(answer.starts_with("HTTP/1.0 503 "));
    assert!(answer.ends_with("{\"error\":\"dashboard_bundle_missing\"}"));
}

#[test]
fn a_folder_that_gave_nothing_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("static");
    assert!(get(Some(&root), "/").starts_with("HTTP/1.0 503 "));
    assert_eq!(build_id(&root), None);
    bundle(&root);
    assert!(get(Some(&root), "/").starts_with("HTTP/1.0 200 OK\r\n"));
    assert!(build_id(&root).is_some());
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

/// The folder a daemon is launched with can be the launcher's temporary
/// unpack folder, deleted once the launcher exits. The daemon pins the bundle
/// at startup (its handshake asks for the build id), so every file it serves
/// must still be there after the folder is gone.
#[test]
fn every_served_file_outlives_its_folder() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("static");
    bundle(&root);
    fs::create_dir_all(root.join("brand")).unwrap();
    fs::write(root.join("brand/logo.png"), "logo").unwrap();
    fs::write(root.join("favicon-32x32.png"), "icon").unwrap();
    assert!(build_id(&root).is_some());
    fs::remove_dir_all(&root).unwrap();
    for (path, body) in [
        ("/brand/logo.png", "logo"),
        ("/favicon-32x32.png", "icon"),
        ("/favicon.svg", "<svg/>"),
        ("/assets/guard-dashboard.js", "app()"),
    ] {
        let answer = get(Some(&root), path);
        assert!(
            answer.starts_with("HTTP/1.0 200 OK\r\n"),
            "{path}: {answer}"
        );
        assert!(answer.ends_with(body), "{path}: {answer}");
    }
    assert!(get(Some(&root), "/inbox").starts_with("HTTP/1.0 200 OK\r\n"));
}

#[test]
fn brand_and_root_files_leave_the_build_id_alone() {
    let plain = tempfile::tempdir().unwrap();
    bundle(plain.path());
    let branded = tempfile::tempdir().unwrap();
    bundle(branded.path());
    fs::create_dir_all(branded.path().join("brand")).unwrap();
    fs::write(branded.path().join("brand/logo.png"), "logo").unwrap();
    fs::write(branded.path().join("favicon.ico"), "ico").unwrap();
    assert_eq!(build_id(plain.path()), build_id(branded.path()));
    // Icons alone are not a dashboard.
    let icons = tempfile::tempdir().unwrap();
    fs::write(icons.path().join("favicon.svg"), "<svg/>").unwrap();
    assert_eq!(build_id(icons.path()), None);
    assert!(get(Some(icons.path()), "/").starts_with("HTTP/1.0 503 "));
}

#[cfg(unix)]
#[test]
fn a_link_out_of_the_folder_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("static");
    bundle(&root);
    fs::write(dir.path().join("outside.png"), "no").unwrap();
    fs::create_dir_all(root.join("brand")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("outside.png"), root.join("brand/out.png")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("outside.png"), root.join("assets/out.png"))
        .unwrap();
    assert!(get(Some(&root), "/brand/out.png").starts_with("HTTP/1.0 404 "));
    assert!(get(Some(&root), "/assets/out.png").starts_with("HTTP/1.0 404 "));
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
    assert!(respond(&request, None, b"k", None).is_none());
}
