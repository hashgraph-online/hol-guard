//! Grok's folder search and folder listing under the names Grok's hook sends:
//! `grep` and `list_dir`, lower case, with camel-case copies of each field.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const DIRECTORY_READ: &str = "native_exact_safe_directory_read";
const SEARCH_SCOPE: &str = "native_bounded_search_scope";

/// A home holding a folder of checkouts with notes and a secrets file, and the
/// home stores a listing must never start in.
fn fixture(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grok-native-tool-names")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let workspace = home.join("projects");
    let project = workspace.join("tools");
    for (path, contents) in [
        ("projects/tools/.git/HEAD", "ref: refs/heads/main\n"),
        ("projects/tools/README.md", "# Tools\n"),
        ("projects/tools/docs/setup.md", "Run the report job.\n"),
        ("projects/tools/src/main.rs", "fn main() {}\n"),
        ("projects/tools/secrets.json", "{\"token\":\"canary\"}\n"),
        (".ssh/id_ed25519", "key\n"),
        (".config/cloud/credentials", "[default]\n"),
        ("projects/site/.git/HEAD", "ref: refs/heads/main\n"),
        ("projects/site/index.md", "# Site\n"),
        ("projects/site/pages/about.md", "About\n"),
    ] {
        let path = home.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    (
        std::fs::canonicalize(&home).unwrap(),
        std::fs::canonicalize(&workspace).unwrap(),
        std::fs::canonicalize(&project).unwrap(),
    )
}

fn grok(tool: &str, input: Value, home: &Path, cwd: &Path) -> (String, String) {
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "hookEventName": "PreToolUse",
        "tool_name": tool,
        "toolName": tool,
        "tool_input": input,
        "toolInput": input,
        "toolInputTruncated": false,
    });
    let result = evaluate_pre_tool_envelope_with_context(
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

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn grok_lists_and_searches_project_folders_by_its_own_tool_names() {
    let (home, workspace, project) = fixture("allowed");
    for folder in [
        // A checkout whose `.git` the listing leaves out, and folders inside
        // checkouts.
        text(&workspace.join("site")),
        text(&workspace.join("site/pages")),
        text(&project.join("docs")),
        text(&project.join("src")),
    ] {
        let decision = grok(
            "list_dir",
            json!({"target_directory": folder}),
            &home,
            &workspace,
        );
        assert_eq!(
            decision,
            ("allow".into(), DIRECTORY_READ.into()),
            "{folder}"
        );
    }
    let decision = grok(
        "list_dir",
        json!({"target_directory": "docs"}),
        &home,
        &project,
    );
    assert_eq!(decision, ("allow".into(), DIRECTORY_READ.into()));
    for (input, cwd) in [
        // The shapes Grok sends most: a folder and a plain word, a name glob
        // with a result limit, and no folder at all.
        (
            json!({"pattern": "report", "path": text(&project.join("docs"))}),
            &workspace,
        ),
        (
            json!({"pattern": "token", "path": text(&project), "glob": "*.md", "head_limit": 30}),
            &workspace,
        ),
        (
            json!({"pattern": "report", "glob": "*.md", "head_limit": 30}),
            &project,
        ),
        (json!({"pattern": "main", "path": "src", "-A": 2}), &project),
    ] {
        let decision = grok("grep", input.clone(), &home, cwd);
        assert_eq!(decision, ("allow".into(), SEARCH_SCOPE.into()), "{input}");
    }
}

#[test]
fn grok_listing_or_search_that_reaches_a_store_keeps_its_review() {
    let (home, workspace, project) = fixture("refused");
    for folder in [
        text(&home),
        text(&home.join(".ssh")),
        "~/.ssh".to_owned(),
        format!("{}/../..", text(&project)),
        format!("{}/*", text(&workspace)),
        // A hidden home folder whose tree names a credentials file.
        text(&home.join(".config")),
        // A tree that names a secrets file.
        text(&workspace),
        text(&project),
        // A system folder.
        "/etc".to_owned(),
    ] {
        let decision = grok(
            "list_dir",
            json!({"target_directory": folder}),
            &home,
            &workspace,
        );
        assert_ne!(decision.0, "allow", "{folder}");
    }
    for input in [
        // The secrets file holds the word searched for and no glob keeps it
        // out of the search.
        json!({"pattern": "token", "path": text(&project)}),
        json!({"pattern": "token", "path": text(&project), "glob": "*.json"}),
        json!({"pattern": "id", "path": text(&home.join(".ssh"))}),
        // An option the search screen does not model.
        json!({"pattern": "report", "path": text(&project), "follow": true}),
    ] {
        let decision = grok("grep", input.clone(), &home, &workspace);
        assert_ne!(decision.0, "allow", "{input}");
    }
    // A copy that names another folder is not the input Grok runs.
    let payload_copy = json!({"pattern": "id", "path": text(&home.join(".ssh"))});
    let result = evaluate_pre_tool_envelope_with_context(
        "grok",
        "PreToolUse",
        &json!({
            "tool_name": "grep",
            "toolName": "grep",
            "tool_input": {"pattern": "report", "path": text(&project.join("docs"))},
            "toolInput": payload_copy,
        }),
        None,
        None,
        home.to_str(),
        workspace.to_str(),
    );
    assert_ne!(result.minimum_action, "allow");
}
