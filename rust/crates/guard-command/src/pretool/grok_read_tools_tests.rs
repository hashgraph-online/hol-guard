//! Grok's `Read` of a folder, `Grep` of a folder and reads of its own memory
//! notes, sent the way Grok's hook sends them: snake-case fields with
//! camel-case copies.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

const DIRECTORY_READ: &str = "native_exact_safe_directory_read";
const SEARCH_SCOPE: &str = "native_bounded_search_scope";

/// A home with a folder of checkouts that is not itself a repository, as an
/// agent started from an organization folder sees it.
fn fixture() -> (PathBuf, PathBuf, PathBuf) {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("guard-grok-read-{}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("projects");
    let project = workspace.join("app");
    write(&project.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(&project.join("docs/guide.md"), "# Guide\n");
    write(&project.join("src/main.rs"), "fn main() {}\n");
    (
        std::fs::canonicalize(home).unwrap(),
        std::fs::canonicalize(workspace).unwrap(),
        std::fs::canonicalize(project).unwrap(),
    )
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn evaluate(payload: Value, home: &Path, cwd: &Path) -> (String, String) {
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "grok",
        "PreToolUse",
        &payload,
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

fn grok_payload(tool: &str, input: Value, copy: Value, truncated: bool) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "hookEventName": "PreToolUse",
        "tool_name": tool,
        "toolName": tool,
        "tool_input": input,
        "toolInput": copy,
        "toolInputTruncated": truncated,
    })
}

fn grok(tool: &str, input: Value, home: &Path, cwd: &Path) -> (String, String) {
    evaluate(grok_payload(tool, input.clone(), input, false), home, cwd)
}

fn allowed(decision: &(String, String), reason: &str) -> bool {
    decision.0 == "allow" && decision.1 == reason
}

#[test]
fn grok_lists_and_searches_project_folders_without_review() {
    let (home, workspace, project) = fixture();
    for folder in [&workspace, &project, &project.join("docs")] {
        let decision = grok(
            "Read",
            json!({"target_directory": text(folder)}),
            &home,
            &workspace,
        );
        assert!(allowed(&decision, DIRECTORY_READ), "{decision:?}");
    }
    let decision = grok(
        "Grep",
        json!({
            "pattern": "Always allow|approvals",
            "path": text(&project.join("docs")),
            "glob": "*.md",
            "head_limit": 40,
        }),
        &home,
        &workspace,
    );
    assert!(allowed(&decision, SEARCH_SCOPE), "{decision:?}");
    let decision = grok(
        "Grep",
        json!({"pattern": "main", "path": "src"}),
        &home,
        &project,
    );
    assert!(allowed(&decision, SEARCH_SCOPE), "{decision:?}");
}

#[test]
fn grok_searches_keep_review_when_a_secret_is_reachable() {
    let (home, workspace, project) = fixture();
    // Grok searches a gitignored file its glob matches, so an ignore rule
    // does not take the file out of reach.
    write(&project.join(".gitignore"), ".env\n");
    write(&project.join("docs/.env"), "TOKEN=canary\n");
    for glob in ["*", "*.md"] {
        let decision = grok(
            "Grep",
            json!({"pattern": "TOKEN", "path": text(&project.join("docs")), "glob": glob}),
            &home,
            &workspace,
        );
        assert_ne!(decision.0, "allow", "{glob}");
    }
}

#[test]
fn grok_searches_keep_review_for_unmodeled_input() {
    let (home, workspace, project) = fixture();
    let docs = text(&project.join("docs"));
    let input = json!({"pattern": "Guide", "path": docs});
    for (input, copy, truncated) in [
        // The copy names another folder, or the host cut the input short.
        (
            input.clone(),
            json!({"pattern": "Guide", "path": text(&home)}),
            false,
        ),
        (input.clone(), input.clone(), true),
        // A glob spelled outside the searched folder, or an unknown option.
        (
            json!({"pattern": "Guide", "path": docs, "glob": "../*"}),
            json!({"pattern": "Guide", "path": docs, "glob": "../*"}),
            false,
        ),
        (
            json!({"pattern": "Guide", "path": docs, "glob": "/etc/*"}),
            json!({"pattern": "Guide", "path": docs, "glob": "/etc/*"}),
            false,
        ),
        (
            json!({"pattern": "Guide", "path": docs, "follow": true}),
            json!({"pattern": "Guide", "path": docs, "follow": true}),
            false,
        ),
    ] {
        let decision = evaluate(
            grok_payload("Grep", input.clone(), copy, truncated),
            &home,
            &workspace,
        );
        assert_ne!(decision.1, SEARCH_SCOPE, "{input}");
    }
    // A folder or file read keeps review when its copy differs or Grok cut
    // it short.
    let guide = text(&project.join("docs/guide.md"));
    for (input, copy, truncated) in [
        (
            json!({"target_directory": docs}),
            json!({"target_directory": text(&home)}),
            false,
        ),
        (
            json!({"target_directory": docs}),
            json!({"target_directory": docs}),
            true,
        ),
        (
            json!({"target_file": guide}),
            json!({"target_file": guide}),
            true,
        ),
    ] {
        let decision = evaluate(
            grok_payload("Read", input.clone(), copy, truncated),
            &home,
            &workspace,
        );
        assert!(
            ![DIRECTORY_READ, "native_exact_safe_file_read"].contains(&decision.1.as_str()),
            "{input} {truncated} {decision:?}"
        );
    }
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let decision = grok(
        "Read",
        json!({"target_directory": text(&home.join(".ssh"))}),
        &home,
        &workspace,
    );
    assert_ne!(decision.0, "allow");
}

#[test]
fn grok_memory_notes_read_but_its_login_and_databases_do_not() {
    let (home, workspace, _) = fixture();
    let notes = home.join(".grok/memory-v2/workspaces/projects-1a2b/topics/runner.md");
    write(&notes, "# Runner\n");
    write(&home.join(".grok/memory-v2/global/index.sqlite"), "");
    write(&home.join(".grok/auth.json"), "{}\n");
    let decision = grok(
        "Read",
        json!({"target_file": text(&notes)}),
        &home,
        &workspace,
    );
    assert_eq!(decision.0, "allow", "{decision:?}");
    for denied in [
        home.join(".grok/memory-v2/global/index.sqlite"),
        home.join(".grok/auth.json"),
    ] {
        let decision = grok(
            "Read",
            json!({"target_file": text(&denied)}),
            &home,
            &workspace,
        );
        assert_ne!(decision.0, "allow", "{}", denied.display());
    }
}

#[test]
fn grok_camel_only_payloads_use_the_one_copy_sent() {
    let (home, workspace, project) = fixture();
    let camel_only = |tool: &str, input: Value| {
        json!({
            "hookEventName": "PreToolUse",
            "toolName": tool,
            "toolInput": input,
            "toolInputTruncated": false,
        })
    };
    let decision = evaluate(
        camel_only("Read", json!({"target_directory": text(&project)})),
        &home,
        &workspace,
    );
    assert!(allowed(&decision, DIRECTORY_READ), "{decision:?}");
    // The search proof reads the snake-case input, so a camel-only `Grep`
    // has nothing it can prove.
    let decision = evaluate(
        camel_only(
            "Grep",
            json!({"pattern": "Guide", "path": text(&project.join("docs"))}),
        ),
        &home,
        &workspace,
    );
    assert_ne!(decision.1, SEARCH_SCOPE, "{decision:?}");
}
