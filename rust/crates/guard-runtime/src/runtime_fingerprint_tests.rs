use super::*;
use std::time::{Duration, SystemTime};

const VERSION: &str = "9.9.9";
/// 1_700_000_000.123456789 seconds after the epoch.
const MTIME_NS: u64 = 1_700_000_000_123_456_789;

fn plant(root: &Path, files: &[(&str, &[u8])]) {
    for (name, bytes) in files {
        let path = root.join(PACKAGE).join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        touch(&path, MTIME_NS);
    }
}

fn touch(path: &Path, nanos: u64) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos))
        .unwrap();
}

fn tree() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    plant(
        root.path(),
        &[
            ("a.py", b"x = 1\n"),
            ("guard/b.py", b"y = 2\n"),
            ("guard/daemon/static/index.html", b"<p>\n"),
            ("guard/daemon/static/app.py", b"z\n"),
            ("_native/runtime-manifest.json", b"{}"),
            ("notes.txt", b"ignored\n"),
        ],
    );
    root
}

fn run(root: &Path, cached: Option<Value>) -> Value {
    let mut request = json!({
        "schema": SCHEMA,
        "source_root": root.to_str().unwrap(),
        "version": VERSION,
    });
    if let Some(cached) = cached {
        request["cached"] = cached;
    }
    let bytes = run_command(request.to_string().as_bytes()).expect("answer");
    serde_json::from_slice(&bytes).expect("answer is JSON")
}

fn relative_names(root: &Path) -> Vec<String> {
    identity_paths(root)
        .iter()
        .map(|path| relative(root, path).replace('\\', "/"))
        .collect()
}

/// The walk lists every `*.py` file, the native manifest and each static
/// asset, in path order; a static `*.py` file is listed by both walks.
#[test]
fn the_identity_covers_sources_the_manifest_and_static_assets() {
    let root = tree();
    assert_eq!(
        relative_names(root.path()),
        [
            "codex_plugin_scanner/_native/runtime-manifest.json",
            "codex_plugin_scanner/a.py",
            "codex_plugin_scanner/guard/b.py",
            "codex_plugin_scanner/guard/daemon/static/app.py",
            "codex_plugin_scanner/guard/daemon/static/app.py",
            "codex_plugin_scanner/guard/daemon/static/index.html",
        ]
    );
}

/// The digests are the ones the Python walk produced for the same tree, so
/// a cache written before the move still reads as current.
#[cfg(unix)]
#[test]
fn digests_match_the_python_walk() {
    let root = tree();
    let answer = run(root.path(), None);
    assert_eq!(
        answer["tree_sig"],
        "732632e15ed917bb9099a58ef283da9cb077ad0f2b8568dae045ac41c749f457"
    );
    assert_eq!(
        answer["fingerprint"],
        "f56a7de7b285435772afbff0642a323d1ad5e0326fb9854ec27c2ec346313f80"
    );
    assert_eq!(answer["reused"], false);
}

/// Touching a file changes the tree signature but not the fingerprint;
/// changing its bytes changes both.
#[test]
fn the_fingerprint_ignores_mtime_and_tracks_content() {
    let root = tree();
    let target = root.path().join(PACKAGE).join("a.py");
    let first = run(root.path(), None);
    touch(&target, 1_600_000_000_000_000_000);
    let touched = run(root.path(), None);
    assert_ne!(touched["tree_sig"], first["tree_sig"]);
    assert_eq!(touched["fingerprint"], first["fingerprint"]);
    fs::write(&target, b"x = 2\n").unwrap();
    let changed = run(root.path(), None);
    assert_ne!(changed["fingerprint"], first["fingerprint"]);
}

/// A version change is an identity change even over the same bytes.
#[test]
fn the_version_is_part_of_the_identity() {
    let root = tree();
    let first = run(root.path(), None);
    let request = json!({
        "schema": SCHEMA,
        "source_root": root.path().to_str().unwrap(),
        "version": "9.9.10",
    });
    let other: Value =
        serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap();
    assert_ne!(other["tree_sig"], first["tree_sig"]);
    assert_ne!(other["fingerprint"], first["fingerprint"]);
}

/// A replaced native runtime manifest is a new generation.
#[test]
fn a_new_native_manifest_changes_the_fingerprint() {
    let root = tree();
    let first = run(root.path(), None);
    let manifest = root
        .path()
        .join(PACKAGE)
        .join("_native/runtime-manifest.json");
    fs::write(&manifest, br#"{"runtime_sha256":"b"}"#).unwrap();
    assert_ne!(run(root.path(), None)["fingerprint"], first["fingerprint"]);
}

/// A cached fingerprint is returned while the tree signature matches, and
/// ignored once it does not or when it is not a digest.
#[test]
fn a_cached_fingerprint_is_reused_only_for_its_tree() {
    let root = tree();
    let first = run(root.path(), None);
    let planted = "0".repeat(64);
    let cached = |tree_sig: &Value, fingerprint: &str| json!({ "tree_sig": tree_sig, "fingerprint": fingerprint });
    let reused = run(root.path(), Some(cached(&first["tree_sig"], &planted)));
    assert_eq!(reused["fingerprint"], planted.as_str());
    assert_eq!(reused["reused"], true);

    let stale = run(root.path(), Some(cached(&json!("other"), &planted)));
    assert_eq!(stale["fingerprint"], first["fingerprint"]);
    assert_eq!(stale["reused"], false);

    let malformed = run(
        root.path(),
        Some(cached(&first["tree_sig"], "not-a-digest")),
    );
    assert_eq!(malformed["fingerprint"], first["fingerprint"]);
    assert_eq!(malformed["reused"], false);
}

/// A symlinked directory is not entered, as the Python walk never entered
/// one, but a symlinked `*.py` file is listed.
#[cfg(unix)]
#[test]
fn symlinked_directories_are_not_entered() {
    let root = tree();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("x.py"), b"outside\n").unwrap();
    let package = root.path().join(PACKAGE);
    std::os::unix::fs::symlink(outside.path(), package.join("linked")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("x.py"), package.join("f.py")).unwrap();
    let names = relative_names(root.path());
    assert!(names.contains(&"codex_plugin_scanner/f.py".to_owned()));
    assert!(!names.iter().any(|name| name.contains("linked")));
}

#[test]
fn requests_are_validated() {
    let root = tree();
    let path = root.path().to_str().unwrap();
    for request in [
        json!({ "schema": "runtime-fingerprint.v0", "source_root": path, "version": VERSION }),
        json!({ "schema": SCHEMA, "source_root": "relative", "version": VERSION }),
        json!({ "schema": SCHEMA, "source_root": path }),
        json!({ "schema": SCHEMA, "source_root": path, "version": VERSION, "extra": true }),
        json!({ "schema": SCHEMA, "source_root": path, "version": VERSION, "cached": { "tree_sig": "a" } }),
        json!({ "schema": SCHEMA, "source_root": path, "version": VERSION, "cache_dir": 7 }),
    ] {
        assert_eq!(
            run_command(request.to_string().as_bytes()).expect_err("refused"),
            "runtime_fingerprint_request_invalid",
            "{request}"
        );
    }
}

/// A `cache_dir` that cannot hold a cache file is skipped, not refused, so
/// the daemon still learns its identity.
#[test]
fn an_unusable_cache_dir_only_costs_the_content_hash() {
    let root = tree();
    let expected = run(root.path(), None);
    let path = root.path().to_str().unwrap();
    for cache_dir in ["relative", "", "/"] {
        let request = json!({ "schema": SCHEMA, "source_root": path, "version": VERSION, "cache_dir": cache_dir });
        let answer: Value =
            serde_json::from_slice(&run_command(request.to_string().as_bytes()).expect("answer"))
                .unwrap();
        assert_eq!(
            answer["fingerprint"], expected["fingerprint"],
            "{cache_dir:?}"
        );
        assert_eq!(answer["reused"], false, "{cache_dir:?}");
    }
}

#[cfg(unix)]
fn private_cache_dir() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().join(".hol-guard");
    fs::create_dir(&guard_home).unwrap();
    fs::set_permissions(&guard_home, fs::Permissions::from_mode(0o700)).unwrap();
    let cache_dir = guard_home.join("runtime-fingerprint-cache");
    (home, cache_dir)
}

#[cfg(unix)]
fn run_with_cache_dir(root: &Path, cache_dir: &Path) -> Value {
    let request = json!({
        "schema": SCHEMA,
        "source_root": root.to_str().unwrap(),
        "version": VERSION,
        "cache_dir": cache_dir.to_str().unwrap(),
    });
    let bytes = run_command(request.to_string().as_bytes()).expect("answer");
    serde_json::from_slice(&bytes).expect("answer is JSON")
}

/// The cache file the daemon has always used: named by the SHA-256 of the
/// source root, keyed by it, and holding the tree signature and fingerprint.
#[cfg(unix)]
fn cache_file(cache_dir: &Path, root: &Path) -> PathBuf {
    let name = hex::encode(Sha256::digest(root.to_str().unwrap().as_bytes()));
    cache_dir.join(format!("{name}.json"))
}

#[cfg(unix)]
fn plant_cache(cache_dir: &Path, root: &Path, body: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(cache_dir).unwrap();
    fs::set_permissions(cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let path = cache_file(cache_dir, root);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A first answer hashes the tree and leaves a private cache file; the next
/// answer for the same tree reads it back without hashing, and a changed
/// tree hashes again and rewrites it.
#[cfg(unix)]
#[test]
fn the_cache_file_is_written_privately_and_reused() {
    use std::os::unix::fs::PermissionsExt;
    let root = tree();
    let (_home, cache_dir) = private_cache_dir();
    let first = run_with_cache_dir(root.path(), &cache_dir);
    assert_eq!(first["reused"], false);
    assert_eq!(first, run(root.path(), None));

    let path = cache_file(&cache_dir, root.path());
    let stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        stored,
        json!({
            "content_fingerprint": first["fingerprint"],
            "source_root": root.path().to_str().unwrap(),
            "tree_sig": first["tree_sig"],
        })
    );
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&cache_dir), 0o700);

    let second = run_with_cache_dir(root.path(), &cache_dir);
    assert_eq!(second["reused"], true);
    assert_eq!(second["fingerprint"], first["fingerprint"]);

    fs::write(root.path().join(PACKAGE).join("a.py"), b"x = 2\n").unwrap();
    let changed = run_with_cache_dir(root.path(), &cache_dir);
    assert_eq!(changed["reused"], false);
    assert_ne!(changed["fingerprint"], first["fingerprint"]);
    let stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(stored["content_fingerprint"], changed["fingerprint"]);
}

/// A cache file is trusted only when it names this source root, holds a
/// digest, and passes the private-file checks. Anything else costs a hash.
#[cfg(unix)]
#[test]
fn a_foreign_or_malformed_cache_file_is_ignored() {
    use std::os::unix::fs::PermissionsExt;
    let root = tree();
    let expected = run(root.path(), None);
    let planted = "0".repeat(64);
    let body = |source_root: &str, fingerprint: &str| {
        json!({
            "content_fingerprint": fingerprint,
            "source_root": source_root,
            "tree_sig": expected["tree_sig"],
        })
        .to_string()
        .into_bytes()
    };
    let source = root.path().to_str().unwrap();
    let oversized = {
        let mut stored: Value = serde_json::from_slice(&body(source, &planted)).unwrap();
        stored["padding"] = json!("x".repeat(4096));
        stored.to_string().into_bytes()
    };
    for (label, bytes, mode) in [
        ("other root", body("/elsewhere", &planted), 0o600),
        ("not a digest", body(source, "not-a-digest"), 0o600),
        ("group readable", body(source, &planted), 0o640),
        ("oversized", oversized, 0o600),
        ("not json", b"{".to_vec(), 0o600),
    ] {
        let (_home, cache_dir) = private_cache_dir();
        plant_cache(&cache_dir, root.path(), &bytes, mode);
        let answer = run_with_cache_dir(root.path(), &cache_dir);
        assert_eq!(answer["reused"], false, "{label}");
        assert_eq!(answer["fingerprint"], expected["fingerprint"], "{label}");
    }

    // The same file is trusted from a private directory, and not from one
    // other users can enter.
    let (_home, cache_dir) = private_cache_dir();
    plant_cache(&cache_dir, root.path(), &body(source, &planted), 0o600);
    assert_eq!(
        run_with_cache_dir(root.path(), &cache_dir)["fingerprint"],
        planted.as_str()
    );
    plant_cache(&cache_dir, root.path(), &body(source, &planted), 0o600);
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(run_with_cache_dir(root.path(), &cache_dir)["reused"], false);
}

/// A symlinked cache file is never followed.
#[cfg(unix)]
#[test]
fn a_symlinked_cache_file_is_ignored() {
    let root = tree();
    let expected = run(root.path(), None);
    let (_home, cache_dir) = private_cache_dir();
    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("cache.json");
    plant_cache(&cache_dir, root.path(), b"{}", 0o600);
    let body = json!({
        "content_fingerprint": "0".repeat(64),
        "source_root": root.path().to_str().unwrap(),
        "tree_sig": expected["tree_sig"],
    });
    fs::write(&target, body.to_string()).unwrap();
    let path = cache_file(&cache_dir, root.path());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let answer = run_with_cache_dir(root.path(), &cache_dir);
    assert_eq!(answer["reused"], false);
    assert_eq!(answer["fingerprint"], expected["fingerprint"]);
}
