//! Claude Code's `Read` of a directory: the names-only proof OMP's listing
//! gets, without OMP's line selectors.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture_root() -> std::path::PathBuf {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-literal-directory-read-{}-{nonce}",
            std::process::id()
        ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn read(harness: &str, tool: &str, target: &str, home: &Path, cwd: &Path) -> (String, String) {
    let decision = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({
            "tool_name": tool,
            "tool_input": {"file_path": target},
        }),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    );
    (decision.minimum_action, decision.reason_code)
}

/// A repository with a sign-in folder named `auth`, as the Gauntlet seeds it.
fn repository(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = root.join("home");
    let project = home.join("project");
    let auth = project.join("console/src/lib/auth");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(project.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::create_dir_all(&auth).unwrap();
    std::fs::write(auth.join("README.md"), "Sign-in helpers.\n").unwrap();
    std::fs::write(auth.join("session.ts"), "export const ttl = 60;\n").unwrap();
    (home, project)
}

#[test]
fn claude_reads_of_a_feature_directory_list_names_without_review() {
    let root = fixture_root();
    let (home, project) = repository(&root);
    let absolute = project.join("console/src/lib/auth");
    for target in [
        absolute.to_string_lossy().into_owned(),
        "console/src/lib/auth".to_owned(),
        project.join("console/src").to_string_lossy().into_owned(),
    ] {
        assert_eq!(
            read("claude-code", "Read", &target, &home, &project),
            (
                "allow".to_owned(),
                "native_exact_safe_directory_read".to_owned()
            ),
            "{target}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn claude_directory_reads_keep_review_for_stores_and_streams() {
    let root = fixture_root();
    let (home, project) = repository(&root);
    for directory in [
        home.join(".ssh"),
        home.join(".aws"),
        project.join("config/prod-secrets"),
        // Outside a repository, a bare `auth` folder may be a real store.
        home.join("notes/auth"),
    ] {
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.to_string_lossy().into_owned();
        let (action, reason) = read("claude-code", "Read", &target, &home, &project);
        assert_ne!(action, "allow", "{target}");
        assert_ne!(reason, "native_exact_safe_directory_read", "{target}");
    }
    let auth = project.join("console/src/lib/auth");
    for target in [
        // An OMP selector is a different literal path, and on Windows a
        // colon after a directory name opens one of its streams.
        format!("{}:1", auth.to_string_lossy()),
        format!("{}:secret", auth.to_string_lossy()),
        "console/src/lib/auth:secret".to_owned(),
    ] {
        let (_, reason) = read("claude-code", "Read", &target, &home, &project);
        assert_ne!(reason, "native_exact_safe_directory_read", "{target}");
    }
    // Only the harnesses whose read tool lists a directory get the proof.
    let target = auth.to_string_lossy().into_owned();
    for (harness, tool) in [("codex", "Read"), ("claude-code", "read")] {
        let (_, reason) = read(harness, tool, &target, &home, &project);
        assert_ne!(
            reason, "native_exact_safe_directory_read",
            "{harness} {tool}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}
