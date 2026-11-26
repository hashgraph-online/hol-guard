use super::omp_bash_cwd::{resolve, BashCwd};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A session directory inside a scratch root, canonicalized. The resolver
/// takes only ASCII drive paths, so a temporary directory spelled with any
/// other character (a profile named `José`) cannot host the fixture; those
/// hosts skip the test rather than report a resolver regression.
fn layout(name: &str) -> Option<(PathBuf, PathBuf)> {
    let temp = std::env::temp_dir();
    if !temp.to_str().is_some_and(|text| text.is_ascii()) {
        eprintln!("skipped: the temporary directory is not an ASCII drive path");
        return None;
    }
    let root = temp.join(format!("guard-omp-wincwd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let session = root.join("org");
    std::fs::create_dir_all(&session).unwrap();
    Some((
        root.canonicalize().unwrap(),
        session.canonicalize().unwrap(),
    ))
}

/// The drive spelling of a canonical directory: Windows canonicalizes to the
/// verbatim form (`\\?\C:\...`), while a harness reports the session
/// directory as a plain drive path.
fn drive_spelling(path: &Path) -> String {
    let text = path.to_str().unwrap();
    text.strip_prefix(r"\\?\").unwrap_or(text).to_owned()
}

/// A Windows harness reports the session directory, and any `cwd` it passes
/// for it, as a drive path. The host resolves that with Windows rules, so the
/// directory is the session one, or one below it, rather than a form Guard
/// does not model.
#[test]
fn a_windows_drive_cwd_is_resolved_like_the_host_resolves_it() {
    let Some((root, session)) = layout("drive") else {
        return;
    };
    let session_text = drive_spelling(&session);
    std::fs::create_dir_all(session.join("src")).unwrap();
    let resolve_cwd = |cwd: &str| {
        resolve(
            &json!({"tool_input": {"command": "rg -n settings src", "cwd": cwd}}),
            None,
            Some(&session_text),
        )
    };
    for cwd in [
        session_text.clone(),
        format!("{session_text}\\"),
        session_text.replace('\\', "/"),
        ".".to_owned(),
    ] {
        assert!(matches!(resolve_cwd(&cwd), BashCwd::Session), "{cwd}");
    }
    let below = format!("{session_text}\\src");
    for cwd in [
        "src".to_owned(),
        ".\\src".to_owned(),
        below.clone(),
        below.replace('\\', "/"),
    ] {
        assert!(
            matches!(resolve_cwd(&cwd), BashCwd::Within(directory) if directory == below),
            "{cwd}"
        );
    }
    let outside = drive_spelling(&root);
    assert!(
        matches!(resolve_cwd(&outside), BashCwd::Outside(directory) if directory == outside),
        "{outside}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A drive-relative spelling resolves against a per-drive directory Guard
/// does not see, and a network or device path names no local folder, so
/// each stays a form the host resolves in a way Guard does not model.
#[test]
fn a_windows_cwd_without_a_drive_folder_stays_unresolved() {
    let Some((root, session)) = layout("unmodeled") else {
        return;
    };
    let session_text = drive_spelling(&session);
    let drive = &session_text[..2];
    for cwd in [
        format!("{drive}src"),
        format!(r"\\?\{session_text}"),
        format!(r"\\.\{session_text}"),
        r"\\localhost\share\src".to_owned(),
    ] {
        let result = resolve(
            &json!({"tool_input": {"command": "rg -n settings src", "cwd": cwd}}),
            None,
            Some(&session_text),
        );
        assert!(matches!(result, BashCwd::Unresolved), "{cwd}");
    }
    let _ = std::fs::remove_dir_all(&root);
}
