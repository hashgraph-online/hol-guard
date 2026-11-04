//! `file://` read targets: what resolves to a path, what stays unresolved,
//! and the decisions the resolved path earns through the ordinary read rules.

use super::local_file_url_path;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture_root() -> std::path::PathBuf {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("guard-omp-file-url-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let canonical = std::fs::canonicalize(root).unwrap();
    // Windows canonicalization returns a `\\?\C:\...` extended path. No host
    // spells a target that way, and the `?` is not part of the path, so the
    // fixture uses the plain drive path a `file://` URL can carry.
    match canonical
        .to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
    {
        Some(plain) => std::path::PathBuf::from(plain),
        None => canonical,
    }
}

/// A path as a URL carries it: forward slashes, and a Windows drive behind
/// the URL's root slash.
fn slashed(path: &std::path::Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    if text.starts_with('/') {
        text
    } else {
        format!("/{text}")
    }
}

/// The `file://` spelling of an absolute path, the way Oh My Pi spells it.
fn file_url(path: &std::path::Path) -> String {
    format!("file://{}", slashed(path))
}

fn read_target(
    target: &str,
    home: &std::path::Path,
    cwd: &std::path::Path,
) -> guard_contracts::PreToolResultV1 {
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": target},
        }),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

#[test]
fn file_urls_resolve_to_the_path_they_denote() {
    for (url, path) in [
        (
            "file:///home/u/project/NOTES.md",
            "/home/u/project/NOTES.md",
        ),
        // The scheme and the `localhost` authority are case-insensitive.
        (
            "FILE:///home/u/project/NOTES.md",
            "/home/u/project/NOTES.md",
        ),
        (
            "file://localhost/home/u/project/NOTES.md",
            "/home/u/project/NOTES.md",
        ),
        (
            "file://LocalHost/home/u/project/NOTES.md",
            "/home/u/project/NOTES.md",
        ),
        (
            "file:///home/u/my%20project/a%2Bb.md",
            "/home/u/my project/a+b.md",
        ),
        // Decoded before any path rule runs, so an encoded climb or hidden
        // component is judged as the path it spells, not as opaque URL text.
        (
            "file:///home/u/p/%2e%2e/%2e%2e/.ssh/id_ed25519",
            "/home/u/p/../../.ssh/id_ed25519",
        ),
        (
            "file:///home/u/%2econfig/tool/config.toml",
            "/home/u/.config/tool/config.toml",
        ),
        // Decoded exactly once: `%252e` is the two-character name `%2e`, not
        // a second escape to unwrap.
        (
            "file:///home/u/p/%252e%252e/NOTES.md",
            "/home/u/p/%2e%2e/NOTES.md",
        ),
        // Oh My Pi's own line selector survives the spelling.
        ("file:///home/u/p/main.rs:1-5", "/home/u/p/main.rs:1-5"),
        // The slash before a drive letter is the URL's root marker.
        ("file:///C:/u/p/NOTES.md", "C:/u/p/NOTES.md"),
        ("file:///c:/u/p", "c:/u/p"),
    ] {
        assert_eq!(local_file_url_path(url).as_deref(), Some(path), "{url}");
    }
}

#[test]
fn urls_that_name_no_plain_local_path_stay_unresolved() {
    for url in [
        // A non-local authority names a remote file, never a local path.
        "file://remote.example/home/u/NOTES.md",
        "file://user@remote.example/home/u/NOTES.md",
        "file://localhost:8080/home/u/NOTES.md",
        "file://localhost.remote.example/home/u/NOTES.md",
        // No authority component at all.
        "file:/home/u/NOTES.md",
        "file:home/u/NOTES.md",
        // An authority and no path.
        "file://localhost",
        "file://",
        // A query or a fragment changes what the host opens.
        "file:///home/u/NOTES.md?q=.a",
        "file:///home/u/NOTES.md#section",
        // NUL, other control characters, and invalid UTF-8 after decoding.
        "file:///home/u/%00NOTES.md",
        "file:///home/u/%0aNOTES.md",
        "file:///home/u/%ff.md",
        // Surrounding whitespace and backslashes, before and after decoding.
        "file:///home/u/NOTES.md%20",
        "file:///home/u/%5cNOTES.md",
        "file:///home\\u/NOTES.md",
        " file:///home/u/NOTES.md",
        // Not a `file:` URL at all.
        "https://example.test/NOTES.md",
        "/home/u/NOTES.md",
        "NOTES.md:1-5",
        "",
    ] {
        assert_eq!(local_file_url_path(url), None, "{url}");
    }
}

/// The reported false positive: an ordinary sibling-checkout read whose
/// target is spelled as a `file://` URL. Before the resolver every one of
/// these raised `native_unsupported_omp_read_selector`, while the plain
/// spelling of the same path has always been silent.
#[test]
fn file_url_reads_decide_exactly_as_the_plain_path_they_spell() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let sibling = home.join("sibling-checkout-2");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(sibling.join("src")).unwrap();
    std::fs::write(sibling.join("NOTES.md"), "sibling checkout notes\n").unwrap();
    std::fs::write(project.join("main.rs"), "fn main() {}\n").unwrap();

    for target in [
        sibling.clone(),
        sibling.join("src"),
        sibling.join("NOTES.md"),
        project.clone(),
        project.join("main.rs"),
    ] {
        let plain = target.to_string_lossy().into_owned();
        let url = file_url(&target);
        // The path the URL denotes, judged on its own: the URL must earn
        // exactly this, whatever separators the host platform spells.
        let denoted = local_file_url_path(&url).expect("the fixture URL names a local path");
        let denoted_decision = read_target(&denoted, &home, &project);
        let plain_decision = read_target(&plain, &home, &project);
        let url_decision = read_target(&url, &home, &project);
        assert_eq!(
            plain_decision.minimum_action, "allow",
            "{plain}: {} ({})",
            plain_decision.reason_code, plain_decision.reason
        );
        assert_eq!(
            (
                url_decision.minimum_action.as_str(),
                url_decision.reason_code.as_str(),
                url_decision.explicitly_benign,
            ),
            (
                denoted_decision.minimum_action.as_str(),
                denoted_decision.reason_code.as_str(),
                denoted_decision.explicitly_benign,
            ),
            "{url} must decide as {denoted}",
        );
        assert_eq!(
            url_decision.minimum_action, "allow",
            "{url}: {} ({})",
            url_decision.reason_code, url_decision.reason
        );
    }

    // The `localhost` authority and a line selector name the same file.
    for target in [
        format!("file://localhost{}", slashed(&sibling.join("NOTES.md"))),
        format!("{}:1-5", file_url(&project.join("main.rs"))),
    ] {
        let decision = read_target(&target, &home, &project);
        assert_eq!(
            decision.minimum_action, "allow",
            "{target}: {} ({})",
            decision.reason_code, decision.reason
        );
        assert_eq!(
            decision.reason_code, "native_exact_safe_file_read",
            "{target}"
        );
        assert!(decision.explicitly_benign, "{target}");
    }

    let _ = std::fs::remove_dir_all(root);
}

/// A `file://` spelling must never buy a weaker decision than the plain path
/// it denotes: a non-local authority, a percent-encoded climb and an encoded
/// credential or hidden name all keep the stricter answer.
#[test]
fn file_url_spellings_never_weaken_a_read_decision() {
    let root = fixture_root();
    let home = root.join("home");
    let project = home.join("project");
    let sibling = home.join("sibling-checkout-2");
    let ssh = home.join(".ssh");
    let config = home.join(".config").join("tool");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(sibling.join("NOTES.md"), "sibling checkout notes\n").unwrap();
    std::fs::write(ssh.join("id_ed25519"), "private-key-canary\n").unwrap();
    std::fs::write(config.join("config.toml"), "token = \"canary\"\n").unwrap();
    std::fs::write(project.join(".env"), "SECRET=canary\n").unwrap();

    // Whatever the plain spelling withholds, the URL spelling withholds too:
    // resolution happens before the screens run, so the sensitive-name rules
    // read the same path either way and no URL spelling of a withheld path
    // reaches the benign proof.
    for target in [
        ssh.join("id_ed25519"),
        ssh.clone(),
        project.join(".env"),
        config.join("config.toml"),
        home.join(".config"),
    ] {
        let plain = target.to_string_lossy().into_owned();
        let plain_decision = read_target(&plain, &home, &project);
        // A target the plain spelling already allows -- a home dot-directory
        // listing, for one -- proves nothing about weakening, so only the
        // ones the plain spelling withholds are measured.
        if plain_decision.minimum_action == "allow" {
            continue;
        }
        let url = file_url(&target);
        let url_decision = read_target(&url, &home, &project);
        assert_ne!(
            url_decision.minimum_action, "allow",
            "{url}: {}",
            url_decision.reason_code
        );
        assert!(!url_decision.explicitly_benign, "{url}");
    }

    for target in [
        // Another host's file: the path after the authority is not this
        // host's path and must not be resolved to it.
        format!("file://remote.example{}/NOTES.md", slashed(&sibling)),
        format!(
            "file://localhost.remote.example{}/NOTES.md",
            slashed(&sibling)
        ),
        format!("file://remote.example{}/main.rs", slashed(&project)),
        // A percent-encoded climb out of the workspace, decoded before the
        // path rules run so they see the climb.
        format!("file://{}/%2e%2e/%2e%2e/.ssh/id_ed25519", slashed(&project)),
        format!("file://{}/%2e%2e/.env", slashed(&project)),
        // An encoded credential or hidden-component name.
        format!("file://{}/%2essh/id_ed25519", slashed(&home)),
        format!("file://{}/%2eenv", slashed(&project)),
        format!("file://{}/.ssh/id%5fed25519", slashed(&home)),
    ] {
        let decision = read_target(&target, &home, &project);
        assert_ne!(
            decision.minimum_action, "allow",
            "{target}: {}",
            decision.reason_code
        );
        assert!(!decision.explicitly_benign, "{target}");
    }

    let _ = std::fs::remove_dir_all(root);
}
