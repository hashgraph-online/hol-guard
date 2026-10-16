use super::*;
#[cfg(unix)]
use base64::Engine;
use serde_json::Value;
#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};

const VECTORS: &str = include_str!("../../../../tests/fixtures/portable-project-identity.v1.json");
#[cfg(unix)]
const SCHEMA: &str = "guard.portable-project-identity.vectors.v1";

/// The vectors whose Python identity this resolver answers `Unknown`, each
/// with the reason the Python outcome is not reproduced.
#[cfg(unix)]
const UNKNOWN_ALLOWLIST: [(&str, &str); 2] = [
    (
        "remote_ipv6_explicit_port",
        "a bracketed IPv6 host is validated by version-specific urlsplit code",
    ),
    (
        "remote_ipv6_address_suffix",
        "a bracketed IPv6 host is validated by version-specific urlsplit code",
    ),
];

/// A fresh canonical directory (`/var` is a link on macOS).
#[cfg(unix)]
fn scratch(label: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "guard-project-identity-{}-{}-{label}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("scratch dir");
    fs::canonicalize(&path).expect("canonical scratch dir")
}

/// `materialize` (`tests/portable_identity_vector_cases.py`).
#[cfg(unix)]
fn materialize(case: &Value, root: &Path) -> String {
    for entry in case["tree"].as_array().expect("tree") {
        let target = root.join(entry["path"].as_str().expect("path"));
        fs::create_dir_all(target.parent().expect("parent")).expect("parent dir");
        if entry["dir"] == Value::Bool(true) {
            fs::create_dir_all(&target).expect("dir");
        } else if let Some(link) = entry["symlink"].as_str() {
            std::os::unix::fs::symlink(root.join(link), &target).expect("symlink");
        } else if let Some(encoded) = entry["base64"].as_str() {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("base64");
            fs::write(&target, bytes).expect("bytes");
        } else {
            let pad = entry["pad"].as_u64().unwrap_or(0);
            let mut bytes = entry["text"].as_str().expect("text").as_bytes().to_vec();
            bytes.resize(bytes.len() + usize::try_from(pad).expect("pad"), b'\n');
            fs::write(&target, bytes).expect("text");
        }
    }
    let workspace = case["workspace"].as_str().expect("workspace");
    if workspace.starts_with('/') {
        workspace.to_owned()
    } else {
        root.join(workspace).to_str().expect("utf-8").to_owned()
    }
}

#[cfg(unix)]
#[test]
fn every_vector_matches_the_python_resolver_or_is_allowlisted() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    assert_eq!(vectors["schema"], SCHEMA);
    let base = scratch("vectors");
    let mut failures = Vec::new();
    let mut unknown = Vec::new();
    for case in vectors["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        let workspace = materialize(case, &base.join(id));
        let expected = case["identity"].as_str();
        match (resolve(&workspace), expected) {
            (PortableIdentity::Identity(got), Some(want)) if got == want => {}
            (PortableIdentity::Absent, None) => {}
            (PortableIdentity::Unknown, _) => unknown.push(id.to_owned()),
            (got, want) => failures.push(format!("{id}: resolved {got:?}, Python {want:?}")),
        }
    }
    fs::remove_dir_all(&base).ok();
    assert!(failures.is_empty(), "{failures:#?}");
    let allowed: Vec<String> = UNKNOWN_ALLOWLIST
        .iter()
        .map(|(id, _)| (*id).to_owned())
        .collect();
    assert_eq!(
        unknown, allowed,
        "unknown outcomes must be exactly the allowlist"
    );
}

#[test]
fn the_corpus_holds_sixty_config_variants() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let corpus = vectors["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|case| {
            case["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("corpus_"))
        })
        .count();
    assert_eq!(corpus, 60);
}

#[cfg(unix)]
fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent dir");
    fs::write(path, text).expect("write");
}

#[cfg(unix)]
fn repository(root: &Path) {
    let remote = "https://github.com/example/cached.git";
    write(
        &root.join(".git/config"),
        &format!("[remote \"origin\"]\n\turl = {remote}\n"),
    );
    write(
        &root.join(".git/logs/HEAD"),
        &format!(
            "{} {} G <g@example.invalid> 1 +0000\tclone: from {remote}\n",
            "0".repeat(40),
            "1".repeat(40)
        ),
    );
}

#[cfg(unix)]
#[test]
fn a_cache_hit_never_skips_the_ancestor_walk() {
    let root = scratch("cache");
    repository(&root);
    let workspace = root.join("a/b");
    fs::create_dir_all(&workspace).expect("workspace");
    let workspace = workspace.to_str().expect("utf-8").to_owned();
    let PortableIdentity::Identity(first) = resolve(&workspace) else {
        panic!("the repository resolves");
    };
    assert_eq!(resolve(&workspace), PortableIdentity::Identity(first));
    // A gitdir pointer between the workspace and the cached repository ends
    // the walk there, so the identity kept for the outer `.git` is not read.
    write(&root.join("a/.git"), "gitdir: ../.git\n");
    assert_eq!(resolve(&workspace), PortableIdentity::Absent);
    fs::remove_file(root.join("a/.git")).expect("pointer");
    // A nearer, unconfigured repository also ends the walk.
    fs::create_dir_all(root.join("a/.git")).expect("inner git dir");
    assert_eq!(resolve(&workspace), PortableIdentity::Absent);
    fs::remove_dir_all(&root).ok();
}

#[cfg(unix)]
#[test]
fn workspaces_resolve_would_rewrite_are_unknown() {
    let root = scratch("rewrite");
    repository(&root);
    let canonical = root.to_str().expect("utf-8");
    assert!(matches!(resolve(canonical), PortableIdentity::Identity(_)));
    assert!(matches!(
        resolve(&format!("  {canonical}\n")),
        PortableIdentity::Identity(_)
    ));
    assert_eq!(resolve(&format!("{canonical}/")), PortableIdentity::Unknown);
    assert_eq!(
        resolve(&format!("{canonical}/./")),
        PortableIdentity::Unknown
    );
    assert_eq!(resolve("~/repository"), PortableIdentity::Unknown);
    assert_eq!(resolve("relative/repository"), PortableIdentity::Unknown);
    assert_eq!(
        resolve(&format!("{canonical}/missing")),
        PortableIdentity::Unknown
    );
    assert_eq!(resolve("   "), PortableIdentity::Absent);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn reflog_lines_split_like_splitlines() {
    let remote = "https://github.com/example/repo.git";
    let clone = format!(
        "{} {} s\tclone: from {remote}",
        "0".repeat(40),
        "1".repeat(40)
    );
    let want = Ok(Some("remote:github.com/example/repo".to_owned()));
    for separator in ["\u{2028}", "\u{0c}", "\u{1e}", "\u{85}", "\r", "\r\n"] {
        assert_eq!(clone_anchor(&format!("noise{separator}{clone}")), want);
    }
    // `\u{1f}` separates fields, not lines.
    assert_eq!(
        clone_anchor(&format!("x\u{1f}{clone}")),
        Ok(None),
        "a line whose first field is not all zeros records no clone"
    );
}

#[test]
fn a_workspace_already_naming_an_identity_is_its_own() {
    // `is_portable_project_identity`: the prefix and exactly 64 lowercase
    // hex digits, which `_portable_project_workspace` answers with itself.
    let identity = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "a".repeat(64));
    assert!(is_portable_project_identity(&identity));
    assert_eq!(
        portable_workspace(&format!("  {identity}\n")),
        PortableIdentity::Identity(identity.clone())
    );
    // One hex digit short, one too many, an uppercase digit and a digit
    // outside the alphabet are each an ordinary workspace path instead.
    for digest in [
        "a".repeat(63),
        "a".repeat(65),
        format!("{}A", "a".repeat(63)),
        format!("{}g", "a".repeat(63)),
    ] {
        let value = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{digest}");
        assert!(!is_portable_project_identity(&value), "{value}");
        // A relative path is a workspace this resolver does not reproduce.
        assert_eq!(portable_workspace(&value), PortableIdentity::Unknown);
    }
    assert!(!is_portable_project_identity(&"a".repeat(64)));
    assert_eq!(portable_workspace("   "), PortableIdentity::Absent);
}

#[cfg(unix)]
#[test]
fn a_relative_workspace_resolves_under_the_reported_directory() {
    let root = scratch("relative");
    repository(&root);
    let nested = root.join("a");
    fs::create_dir_all(&nested).expect("nested dir");
    let cwd = nested.to_str().expect("utf-8");
    let token = format!("package-request-workspace-exact:v1:{}", "b".repeat(64));

    // `Path(token).resolve(strict=False)` names `a/<token>` under the
    // checkout, whose identity the ancestor walk derives.
    let PortableIdentity::Identity(joined) = resolve_relative(&token, cwd) else {
        panic!("the reported directory resolves");
    };
    let PortableIdentity::Identity(outer) = resolve_relative(&token, root.to_str().expect("utf-8"))
    else {
        panic!("the checkout resolves");
    };
    // The relative workspace is read under the directory the caller reports,
    // so one token names a different identity in each of them.
    assert_ne!(joined, outer);

    // An absolute workspace, a blank one and one already naming an identity
    // are read exactly as the directory-less resolver reads them.
    assert!(matches!(
        resolve_relative(root.to_str().expect("utf-8"), cwd),
        PortableIdentity::Identity(_)
    ));
    assert_eq!(resolve_relative("   ", cwd), PortableIdentity::Absent);
    let identity = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "c".repeat(64));
    assert_eq!(
        resolve_relative(&format!(" {identity} "), cwd),
        PortableIdentity::Identity(identity)
    );
    fs::remove_dir_all(&root).ok();
}

#[cfg(unix)]
#[test]
fn a_relative_workspace_python_would_rewrite_is_unknown() {
    let root = scratch("relative-rewrite");
    repository(&root);
    let cwd = root.to_str().expect("utf-8").to_owned();
    let token = format!("package-request-workspace-exact:v1:{}", "d".repeat(64));

    // A directory `resolve` would rewrite, a relative directory and a name
    // carrying a separator, a dot segment or a home prefix are each a
    // resolution this reader does not reproduce.
    assert_eq!(
        resolve_relative(&token, &format!("{cwd}/")),
        PortableIdentity::Unknown
    );
    assert_eq!(
        resolve_relative(&token, "relative"),
        PortableIdentity::Unknown
    );
    for name in ["a/token", "./token", "../token", "~token"] {
        assert_eq!(
            resolve_relative(name, &cwd),
            PortableIdentity::Unknown,
            "{name}"
        );
    }

    // A name that already exists may be a link `resolve` follows.
    fs::create_dir_all(root.join(&token)).expect("token dir");
    assert_eq!(resolve_relative(&token, &cwd), PortableIdentity::Unknown);
    fs::remove_dir_all(&root).ok();
}
