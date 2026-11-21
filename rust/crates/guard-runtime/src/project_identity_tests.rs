use super::*;
#[cfg(unix)]
use base64::Engine;
use serde_json::Value;
#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};

const VECTORS: &str = include_str!("../../../../tests/fixtures/portable-project-identity.v1.json");
#[cfg(unix)]
const SCHEMA: &str = "guard.portable-project-identity.vectors.v1";

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
fn every_vector_resolves_to_its_recorded_identity() {
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
            (got, want) => failures.push(format!("{id}: resolved {got:?}, recorded {want:?}")),
        }
    }
    fs::remove_dir_all(&base).ok();
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(unknown.is_empty(), "unsettled vectors: {unknown:#?}");
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
fn workspaces_resolve_rewrites_read_as_the_directory_they_name() {
    let root = scratch("rewrite");
    repository(&root);
    let canonical = root.to_str().expect("utf-8");
    let identity = match resolve(canonical) {
        PortableIdentity::Identity(identity) => identity,
        other => panic!("canonical workspace: {other:?}"),
    };
    assert_eq!(
        resolve(&format!("  {canonical}\n")),
        PortableIdentity::Identity(identity.clone())
    );
    // `resolve(strict=False)` drops a trailing separator and a dot segment,
    // so both name the same repository rather than deferring the call.
    assert_eq!(
        resolve(&format!("{canonical}/")),
        PortableIdentity::Identity(identity.clone())
    );
    assert_eq!(
        resolve(&format!("{canonical}/./")),
        PortableIdentity::Identity(identity.clone())
    );
    // `expanduser` rewrites a `~` name and a relative name resolves against
    // the reader's own directory, neither of which is reproduced here.
    assert_eq!(resolve("~/repository"), PortableIdentity::Unknown);
    assert_eq!(resolve("relative/repository"), PortableIdentity::Unknown);
    // `resolve(strict=False)` appends a name that does not exist to the part
    // that does, so it is read as a workspace under this repository rather
    // than left unsettled, and it is not the repository itself.
    let PortableIdentity::Identity(missing) = resolve(&format!("{canonical}/missing")) else {
        panic!("an absent name under a repository has an identity");
    };
    assert_ne!(missing, identity);
    assert_eq!(resolve("   "), PortableIdentity::Absent);
    fs::remove_dir_all(&root).ok();
}

/// A workspace reached through a symlink is the directory it resolves to,
/// so a relayed call for such a path no longer hands off to the proxy.
#[cfg(unix)]
#[test]
fn workspaces_reached_through_a_symlink_resolve_to_their_real_path() {
    let root = scratch("symlinked");
    let real = root.join("repository");
    fs::create_dir_all(&real).expect("repository dir");
    repository(&real);
    let link = root.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let direct = resolve(real.to_str().expect("utf-8"));
    assert!(matches!(direct, PortableIdentity::Identity(_)));
    assert_eq!(resolve(link.to_str().expect("utf-8")), direct);
    fs::remove_dir_all(&root).ok();
}

/// The identity records the workspace's path inside the repository, so a
/// link retargeted to another directory of the same repository has to be
/// read again rather than answered from the entry kept under its spelling.
#[cfg(unix)]
#[test]
fn a_retargeted_link_is_not_answered_from_the_first_directory() {
    let root = scratch("retargeted");
    repository(&root);
    for name in ["first", "second"] {
        fs::create_dir_all(root.join(name)).expect("workspace dir");
    }
    let link = root.join("link");
    std::os::unix::fs::symlink(root.join("first"), &link).expect("symlink");
    let workspace = link.to_str().expect("utf-8").to_owned();

    let PortableIdentity::Identity(first) = resolve(&workspace) else {
        panic!("the repository resolves");
    };
    // Nothing the Git metadata prints has moved, so only the resolved path
    // keeps the second directory from reading the first one's identity.
    fs::remove_file(&link).expect("link");
    std::os::unix::fs::symlink(root.join("second"), &link).expect("symlink");
    let PortableIdentity::Identity(second) = resolve(&workspace) else {
        panic!("the repository resolves");
    };
    assert_ne!(first, second);
    assert_eq!(
        resolve(root.join("second").to_str().expect("utf-8")),
        PortableIdentity::Identity(second)
    );
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

    // `expanduser` reads a home prefix from an environment this reader does
    // not read, and a directory that is not absolute is resolved against the
    // reader's own directory rather than the one the caller reported.
    assert_eq!(resolve_relative("~token", &cwd), PortableIdentity::Unknown);
    assert_eq!(
        resolve_relative(&token, "relative"),
        PortableIdentity::Unknown
    );
    assert_eq!(resolve_relative(&token, ""), PortableIdentity::Unknown);

    // A link whose target is gone is followed by `resolve` to that target,
    // which this reader does not reproduce.
    std::os::unix::fs::symlink(root.join("gone"), root.join("dangling")).expect("link");
    assert_eq!(
        resolve_relative("dangling", &cwd),
        PortableIdentity::Unknown
    );
    fs::remove_dir_all(&root).ok();
}

/// A relative name carrying a separator or a dot segment, a name that
/// already exists and a reported directory `resolve` would rewrite are each
/// read rather than left unsettled, so an ordinary nested workspace still
/// reaches its project's policy.
#[cfg(unix)]
#[test]
fn relative_workspaces_resolve_reads_are_settled() {
    let root = scratch("relative-settled");
    repository(&root);
    let cwd = root.to_str().expect("utf-8").to_owned();
    let token = format!("package-request-workspace-exact:v1:{}", "e".repeat(64));
    let nested = root.join("a");
    fs::create_dir_all(&nested).expect("nested dir");

    let PortableIdentity::Identity(expected) = resolve_relative(&token, &cwd) else {
        panic!("the reported directory resolves");
    };
    // A trailing separator names the same directory.
    assert_eq!(
        resolve_relative(&token, &format!("{cwd}/")),
        PortableIdentity::Identity(expected.clone())
    );
    // `./<name>` and `<dir>/../<name>` resolve to that same name.
    for name in [format!("./{token}"), format!("a/../{token}")] {
        assert_eq!(
            resolve_relative(&name, &cwd),
            PortableIdentity::Identity(expected.clone()),
            "{name}"
        );
    }
    // A name carrying a separator is read under the reported directory, and
    // names a workspace of its own.
    let PortableIdentity::Identity(under) = resolve_relative(&format!("a/{token}"), &cwd) else {
        panic!("a nested name resolves");
    };
    assert_ne!(under, expected);
    // A name that already exists is read as the directory it resolves to.
    fs::create_dir_all(root.join(&token)).expect("token dir");
    assert_eq!(
        resolve_relative(&token, &cwd),
        PortableIdentity::Identity(expected)
    );
    fs::remove_dir_all(&root).ok();
}

#[cfg(unix)]
#[test]
fn a_workspace_that_is_gone_reads_the_repository_above_it() {
    let root = scratch("absent-workspace");
    repository(&root);
    let present = root.join("apps/first");
    fs::create_dir_all(&present).expect("present dir");

    // `resolve(strict=False)` appends the names that do not exist to the
    // part that does, so a workspace under a directory that was removed is
    // read under the repository above it rather than left unsettled.
    let absent = root.join("apps/second/deeper");
    let PortableIdentity::Identity(derived) = resolve(absent.to_str().expect("utf-8")) else {
        panic!("an absent workspace under a repository has an identity");
    };
    let PortableIdentity::Identity(sibling) = resolve(present.to_str().expect("utf-8")) else {
        panic!("a present workspace under a repository has an identity");
    };
    assert_ne!(derived, sibling);

    // A name that exists nowhere near a repository is still no identity.
    assert_eq!(
        resolve("/guard-no-such-root/workspace"),
        PortableIdentity::Absent
    );
    fs::remove_dir_all(&root).ok();
}

#[cfg(unix)]
#[test]
fn a_workspace_this_reader_cannot_read_is_unknown() {
    let root = scratch("unreadable-workspace");
    repository(&root);

    // A link that names itself answers `ELOOP`, which is not absence.
    let loop_path = root.join("loop");
    std::os::unix::fs::symlink(&loop_path, &loop_path).expect("link loop");
    assert_eq!(
        resolve(loop_path.to_str().expect("utf-8")),
        PortableIdentity::Unknown
    );

    // `..` below the part that exists is rewritten against what that part
    // resolved to, which this reader does not reproduce.
    let traversal = root.join("gone/../apps");
    assert_eq!(
        resolve(traversal.to_str().expect("utf-8")),
        PortableIdentity::Unknown
    );
    fs::remove_dir_all(&root).ok();
}
