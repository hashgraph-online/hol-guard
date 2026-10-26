//! Native-only archive vectors: BOM and null handling, lifecycle and
//! dependency policy, link behavior and exact cap boundaries. These extend
//! the shared parity fixture with cases only the native parser can pin.
#![cfg(unix)]

mod common;

use common::*;
use guard_archive::ArchiveOutcome;

// ------------------------------------------------------- native-only vectors

fn manifest(payload: &[u8]) -> ArchiveOutcome {
    inspect(&archive(&[package_json_member(payload)]))
}

fn code_of(outcome: &ArchiveOutcome) -> (String, &'static str) {
    (format!("{:?}", outcome.status).to_lowercase(), outcome.code)
}

#[test]
fn bom_and_null_handling() {
    let invalid = ("blocked".to_string(), "external_archive_manifest_invalid");
    let clean = ("clean".to_string(), "external_archive_inspection_clean");
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend(br#"{"name":"x"}"#);
    let mut rows: Vec<(&str, Vec<u8>, (String, &str))> = vec![
        ("utf-8 BOM", bom, invalid.clone()),
        ("empty manifest", Vec::new(), invalid.clone()),
        (
            "NUL byte in the JSON",
            b"{\"name\":\"x\"}\0".to_vec(),
            invalid.clone(),
        ),
        ("top-level array", b"[]".to_vec(), invalid.clone()),
        ("top-level null", b"null".to_vec(), invalid.clone()),
        // Stricter than `json.loads`, which accepts a lone surrogate; a
        // manifest the native parser cannot represent is refused, not guessed.
        (
            "lone surrogate escape",
            br#"{"name":"\ud800"}"#.to_vec(),
            invalid.clone(),
        ),
        (
            "null scripts",
            br#"{"name":"x","scripts":null}"#.to_vec(),
            clean.clone(),
        ),
        (
            "null dependencies",
            br#"{"name":"x","dependencies":null}"#.to_vec(),
            clean.clone(),
        ),
        (
            "null optionalDependencies",
            br#"{"optionalDependencies":null}"#.to_vec(),
            clean.clone(),
        ),
        (
            "scripts is a string",
            br#"{"scripts":"x"}"#.to_vec(),
            invalid.clone(),
        ),
        (
            "scripts is a list",
            br#"{"scripts":[]}"#.to_vec(),
            invalid.clone(),
        ),
        (
            "dependencies is a string",
            br#"{"dependencies":"x"}"#.to_vec(),
            invalid.clone(),
        ),
        (
            "dependency value null",
            br#"{"dependencies":{"a":null}}"#.to_vec(),
            invalid.clone(),
        ),
        (
            "dependency value number",
            br#"{"dependencies":{"a":1}}"#.to_vec(),
            invalid.clone(),
        ),
        (
            "null install script value",
            br#"{"scripts":{"install":null}}"#.to_vec(),
            clean.clone(),
        ),
        (
            "numeric install script value",
            br#"{"scripts":{"install":1}}"#.to_vec(),
            clean.clone(),
        ),
        (
            "empty install script",
            br#"{"scripts":{"install":""}}"#.to_vec(),
            clean.clone(),
        ),
        (
            "blank install script",
            br#"{"scripts":{"install":"  \t"}}"#.to_vec(),
            clean.clone(),
        ),
        (
            "duplicate scripts key: last one wins like json.loads",
            br#"{"scripts":{"install":"x"},"scripts":{}}"#.to_vec(),
            clean.clone(),
        ),
    ];
    let deep = format!("{}1{}", "[".repeat(500), "]".repeat(500));
    rows.push(("deeply nested manifest", deep.into_bytes(), invalid.clone()));
    let mut failures = Vec::new();
    for (label, payload, expected) in rows {
        let actual = code_of(&manifest(&payload));
        if actual != expected {
            failures.push(format!("{label}: {actual:?} != {expected:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn lifecycle_script_matrix() {
    let script = ("blocked".to_string(), "tarball_install_script");
    let clean = ("clean".to_string(), "external_archive_inspection_clean");
    let mut failures = Vec::new();
    for key in [
        "preinstall",
        "install",
        "postinstall",
        "prepublish",
        "preprepare",
        "prepare",
        "postprepare",
    ] {
        let payload = format!(r#"{{"name":"x","scripts":{{"{key}":"node run.js"}}}}"#);
        let actual = code_of(&manifest(payload.as_bytes()));
        if actual != script {
            failures.push(format!("{key}: {actual:?}"));
        }
    }
    // Hooks npm does not run at install time are not install scripts.
    for key in [
        "test",
        "build",
        "start",
        "prepack",
        "postpack",
        "preuninstall",
        "postpublish",
        "Install",
        "POSTINSTALL",
    ] {
        let payload = format!(r#"{{"name":"x","scripts":{{"{key}":"node run.js"}}}}"#);
        let actual = code_of(&manifest(payload.as_bytes()));
        if actual != clean {
            failures.push(format!("{key}: {actual:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn dependency_group_matrix() {
    let source = (
        "blocked".to_string(),
        "external_archive_nested_source_dependency",
    );
    let clean = ("clean".to_string(), "external_archive_inspection_clean");
    let mut failures = Vec::new();
    for group in [
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "devDependencies",
    ] {
        for (spec, expected) in [
            ("https://example.com/a.tgz", &source),
            ("git+ssh://git@example.com/a.git", &source),
            ("file:../a", &source),
            ("", &source),
            ("^1.0.0", &clean),
            ("1.2.3", &clean),
            ("npm:safe@^1", &clean),
        ] {
            let payload = format!(r#"{{"name":"x","{group}":{{"a":"{spec}"}}}}"#);
            let actual = code_of(&manifest(payload.as_bytes()));
            if &actual != expected {
                failures.push(format!("{group} {spec:?}: {actual:?}"));
            }
        }
    }
    let unlisted = code_of(&manifest(
        br#"{"name":"x","bundledDependencies":{"a":"https://e/x"}}"#,
    ));
    assert_eq!(unlisted, clean, "groups outside the four are not evaluated");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn link_behavior_vectors() {
    let slip = ("blocked".to_string(), "tarball_zip_slip");
    let clean = ("clean".to_string(), "external_archive_inspection_clean");
    let hard = ("blocked".to_string(), "external_archive_unsafe_hardlink");
    let rows: Vec<(&str, Vec<u8>, (String, &str))> = vec![
        (
            "relative symlink inside the tree",
            archive(&[symlink("p/l", "sibling")]),
            clean.clone(),
        ),
        (
            "symlink climbing out",
            archive(&[symlink("p/l", "../../x")]),
            slip.clone(),
        ),
        (
            "symlink climbing within the tree is fine",
            archive(&[symlink("p/q/l", "../sibling")]),
            clean.clone(),
        ),
        (
            "absolute symlink",
            archive(&[symlink("p/l", "/etc/passwd")]),
            slip.clone(),
        ),
        (
            "symlink with an empty target",
            archive(&[symlink("p/l", "")]),
            slip.clone(),
        ),
        (
            "backslash traversal in a name",
            archive(&[file("p\\..\\..\\x", b"x")]),
            slip.clone(),
        ),
        (
            "control character in a name",
            archive(&[file("p/a\u{1}b", b"x")]),
            slip.clone(),
        ),
        (
            "drive-style first component",
            archive(&[file("C:/x", b"x")]),
            slip.clone(),
        ),
        (
            "hardlink to a regular member",
            archive(&[file("p/a", b"x"), hardlink("p/b", "p/a")]),
            clean.clone(),
        ),
        (
            "hardlink to a case variant of a member",
            archive(&[file("p/a", b"x"), hardlink("p/b", "P/A")]),
            clean.clone(),
        ),
        (
            "hardlink to a directory",
            archive(&[dir("p"), hardlink("b", "p")]),
            hard.clone(),
        ),
        (
            "hardlink to a symlink",
            archive(&[symlink("p/s", "t"), hardlink("p/b", "p/s")]),
            hard.clone(),
        ),
        (
            "hardlink declared before its target",
            archive(&[hardlink("p/b", "p/a"), file("p/a", b"x")]),
            clean.clone(),
        ),
        (
            "hardlink to itself",
            archive(&[hardlink("p/a", "p/a")]),
            hard.clone(),
        ),
        (
            "hardlink absolute target",
            archive(&[hardlink("p/a", "/etc/passwd")]),
            slip.clone(),
        ),
        (
            "hardlink dotdot target",
            archive(&[file("a", b"x"), hardlink("p/b", "../a")]),
            slip.clone(),
        ),
    ];
    let mut failures = Vec::new();
    for (label, bytes, expected) in rows {
        let actual = code_of(&inspect(&bytes));
        if actual != expected {
            failures.push(format!("{label}: {actual:?} != {expected:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn cap_boundaries_are_exact() {
    let mut limit = caps();
    limit.max_member_bytes = 4096;
    limit.max_expanded_bytes = 8192;
    limit.max_files = 3;
    limit.max_path_depth = 3;
    limit.max_decompression_ratio = 1e9;
    let at = |bytes: &[u8]| code_of(&inspect_with(&gz(&archive(&[file("a", bytes)])), &limit));
    let clean = ("clean".to_string(), "external_archive_inspection_clean");
    assert_eq!(at(&vec![b'x'; 4096]), clean);
    assert_eq!(
        at(&vec![b'x'; 4097]),
        ("blocked".to_string(), "external_archive_member_size_limit")
    );
    let files = |count: usize| {
        let members: Vec<Vec<u8>> = (0..count).map(|i| file(&format!("f{i}"), b"x")).collect();
        code_of(&inspect_with(&gz(&archive(&members)), &limit))
    };
    assert_eq!(files(3), clean);
    assert_eq!(
        files(4),
        ("blocked".to_string(), "tarball_file_count_limit")
    );
    let depth = |path: &str| code_of(&inspect_with(&gz(&archive(&[file(path, b"x")])), &limit));
    assert_eq!(depth("a/b/c"), clean);
    assert_eq!(
        depth("a/b/c/d"),
        ("blocked".to_string(), "external_archive_path_depth_limit")
    );
    // The expanded cap counts the whole decompressed stream (headers,
    // padding and terminator included), so the boundary is the stream length.
    let tar = archive(&[file("a", b"hello")]);
    let wrapped = gz(&tar);
    let with_expanded = |cap: u64| {
        let mut c = limit.clone();
        c.max_expanded_bytes = cap;
        code_of(&inspect_with(&wrapped, &c))
    };
    assert_eq!(with_expanded(tar.len() as u64), clean);
    assert_eq!(
        with_expanded(tar.len() as u64 - 1),
        (
            "blocked".to_string(),
            "external_archive_expanded_size_limit"
        )
    );
    let with_archive = |cap: u64| {
        let mut c = limit.clone();
        c.max_archive_bytes = cap;
        code_of(&inspect_with(&wrapped, &c))
    };
    assert_eq!(with_archive(wrapped.len() as u64), clean);
    assert_eq!(
        with_archive(wrapped.len() as u64 - 1),
        (
            "blocked".to_string(),
            "external_archive_download_size_limit"
        )
    );
}
