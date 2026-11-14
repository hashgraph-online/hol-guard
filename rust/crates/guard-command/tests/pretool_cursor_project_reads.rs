//! Cursor reads back the working files it keeps for the session's own
//! workspace under `~/.cursor/projects/<workspace slug>/`. Those reads are
//! allowed; the same files from another workspace, another conversation's
//! transcript, Cursor's MCP auth store, and the same paths read by any other
//! harness keep their review.
#![cfg(unix)]

use guard_command::pretool::{
    evaluate_pre_tool_envelope_with_context, evaluate_pre_tool_envelope_with_execution_context,
    PathContext,
};
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const OWN_CONVERSATION: &str = "5d0c3b9e-7a41-4c1f-9b2e-0f6a8d4c2e71";

struct Fixture {
    home: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/pretool-cursor")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let home = root.join("home");
        let workspace = root.join("work").join("app-portal");
        std::fs::create_dir_all(&workspace).unwrap();
        let fixture = Self { home, workspace };
        let own = fixture.project_dir(&fixture.workspace);
        let other = fixture.project_dir(&root.join("work").join("billing-api"));
        for project in [&own, &other] {
            for leaf in [
                "terminals/120467.txt".to_owned(),
                "agent-tools/0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d.txt".to_owned(),
                "mcps/docs-server/INSTRUCTIONS.md".to_owned(),
                "mcps/docs-server/tools/search_docs.json".to_owned(),
                format!("agent-transcripts/{OWN_CONVERSATION}/compaction/INDEX.md"),
                "agent-transcripts/9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a/compaction/INDEX.md"
                    .to_owned(),
                "mcp-auth.json".to_owned(),
                "worker.log".to_owned(),
                "terminals/.state.txt".to_owned(),
            ] {
                let path = project.join(leaf);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, "synthetic\n").unwrap();
            }
        }
        let skill = fixture
            .home
            .join(".cursor/skills-cursor/create-rule/SKILL.md");
        std::fs::create_dir_all(skill.parent().unwrap()).unwrap();
        std::fs::write(skill, "# create-rule\n").unwrap();
        std::os::unix::fs::symlink(
            fixture
                .home
                .join(".cursor/skills-cursor/create-rule/SKILL.md"),
            own.join("terminals/linked.txt"),
        )
        .unwrap();
        fixture
    }

    fn project_dir(&self, workspace: &Path) -> PathBuf {
        let slug: String = workspace
            .to_string_lossy()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        self.home
            .join(".cursor/projects")
            .join(slug.trim_start_matches('-'))
    }

    fn own(&self, leaf: &str) -> String {
        self.project_dir(&self.workspace)
            .join(leaf)
            .to_string_lossy()
            .into_owned()
    }

    fn read(&self, harness: &str, path: &str, conversation: Option<&str>) -> PreToolResultV1 {
        let mut payload = read_payload(path);
        if let Some(conversation) = conversation {
            payload["conversation_id"] = Value::from(conversation);
        }
        self.evaluate(harness, &payload, &self.home)
    }

    fn evaluate(&self, harness: &str, payload: &Value, home: &Path) -> PreToolResultV1 {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            payload,
            None,
            None,
            home.to_str(),
            self.workspace.to_str(),
        )
    }
}

impl Fixture {
    /// A Cursor shell call whose execution environment is verified, so a
    /// leading `cd` is followed rather than reviewed.
    fn in_shell_environment(&self, payload: &Value) -> PreToolResultV1 {
        let environment = guard_contracts::GuardExecutionEnvironmentV1 {
            path: std::env::var("PATH").unwrap(),
            environment_names: vec!["GIT_CONFIG_NOSYSTEM".to_owned()],
            environment_digest: "0".repeat(64),
            home: self.home.to_str().map(str::to_owned),
            git_config_no_system: true,
            ..Default::default()
        };
        evaluate_pre_tool_envelope_with_execution_context(
            "cursor",
            "PreToolUse",
            payload,
            None,
            None,
            PathContext {
                home_dir: self.home.to_str(),
                cwd: self.workspace.to_str(),
                ..PathContext::default()
            },
            Some(&environment),
        )
    }
}

fn read_payload(path: &str) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": path, "path": path},
        "file_path": path,
    })
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn cursor_reads_its_own_workspace_output_and_tool_descriptions() {
    let fixture = Fixture::new("own");
    for leaf in [
        "terminals/120467.txt",
        "agent-tools/0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d.txt",
        "mcps/docs-server/INSTRUCTIONS.md",
        "mcps/docs-server/tools/search_docs.json",
    ] {
        let result = fixture.read("cursor", &fixture.own(leaf), None);
        assert!(allowed(&result), "{leaf}: {}", result.reason_code);
        assert_eq!(result.reason_code, "native_cursor_project_state_read");
    }
    let skill = fixture
        .home
        .join(".cursor/skills-cursor/create-rule/SKILL.md");
    let result = fixture.read("cursor", skill.to_str().unwrap(), None);
    assert!(allowed(&result), "skill: {}", result.reason_code);
}

#[test]
fn cursor_reads_only_its_own_conversation_transcript() {
    let fixture = Fixture::new("transcript");
    let own = fixture.own(&format!(
        "agent-transcripts/{OWN_CONVERSATION}/compaction/INDEX.md"
    ));
    assert!(allowed(&fixture.read(
        "cursor",
        &own,
        Some(OWN_CONVERSATION)
    )));
    // Without a conversation id the transcript tree stays reviewed.
    assert!(!allowed(&fixture.read("cursor", &own, None)));
    let other =
        fixture.own("agent-transcripts/9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a/compaction/INDEX.md");
    assert!(!allowed(&fixture.read(
        "cursor",
        &other,
        Some(OWN_CONVERSATION)
    )));
}

#[test]
fn conflicting_conversation_ids_admit_no_transcript() {
    let fixture = Fixture::new("conflict");
    const OTHER: &str = "9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a";
    for (id, alias, allowed_read) in [
        (OWN_CONVERSATION, OWN_CONVERSATION, true),
        (OWN_CONVERSATION, OTHER, false),
        (OTHER, OWN_CONVERSATION, false),
    ] {
        for transcript in [OWN_CONVERSATION, OTHER] {
            let path = fixture.own(&format!(
                "agent-transcripts/{transcript}/compaction/INDEX.md"
            ));
            let mut payload = read_payload(&path);
            payload["conversation_id"] = Value::from(id);
            payload["conversationId"] = Value::from(alias);
            let result = fixture.evaluate("cursor", &payload, &fixture.home);
            assert_eq!(
                allowed(&result),
                allowed_read && transcript == OWN_CONVERSATION,
                "{id} / {alias} reading {transcript}: {}",
                result.reason_code
            );
        }
    }
}

#[test]
fn cursor_reads_through_a_linked_home() {
    let fixture = Fixture::new("linked-home");
    let link = fixture.home.with_file_name("home-link");
    std::os::unix::fs::symlink(&fixture.home, &link).unwrap();
    let relative = fixture
        .project_dir(&fixture.workspace)
        .strip_prefix(&fixture.home)
        .unwrap()
        .join("terminals/120467.txt");
    for path in [
        format!("~/{}", relative.display()),
        link.join(&relative).to_string_lossy().into_owned(),
    ] {
        let result = fixture.evaluate("cursor", &read_payload(&path), &link);
        assert!(allowed(&result), "{path}: {}", result.reason_code);
    }
}

#[test]
fn cursor_project_state_outside_the_workspace_leaves_keeps_review() {
    let fixture = Fixture::new("negative");
    let other_project = fixture.project_dir(&fixture.workspace.with_file_name("billing-api"));
    let own_terminal = fixture.own("terminals/120467.txt");
    let traversal = format!("{}/../terminals/120467.txt", fixture.own("terminals"));
    for path in [
        other_project
            .join("terminals/120467.txt")
            .to_string_lossy()
            .into_owned(),
        fixture.own("mcp-auth.json"),
        fixture.own("worker.log"),
        fixture.own("terminals/.state.txt"),
        fixture.own("terminals/linked.txt"),
    ] {
        let result = fixture.read("cursor", &path, Some(OWN_CONVERSATION));
        assert!(!allowed(&result), "{path}: {}", result.reason_code);
    }
    // A `..` spelling that resolves back to the session's own saved output
    // reads the same file as the plain path, so it takes the same answer.
    let result = fixture.read("cursor", &traversal, Some(OWN_CONVERSATION));
    assert!(allowed(&result), "{traversal}: {}", result.reason_code);
    for harness in ["claude-code", "zcode", "codex"] {
        let result = fixture.read(harness, &own_terminal, None);
        assert!(
            !allowed(&result),
            "{harness}: {own_terminal}: {}",
            result.reason_code
        );
    }
}

fn shell(harness: &str, command: &str) -> Value {
    let tool = if harness == "cursor" { "Shell" } else { "Bash" };
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    })
}

#[test]
fn cursor_shell_reads_back_its_own_saved_output() {
    let fixture = Fixture::new("shell-outputs");
    let tool = fixture.own("agent-tools/0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d.txt");
    let terminal = fixture.own("terminals/120467.txt");
    let reads = [
        format!("cat {tool}"),
        format!("jq '.checks' {tool}"),
        format!("head -40 {terminal}"),
        format!("grep -n FAIL {terminal}"),
    ];
    for command in &reads {
        let result = fixture.evaluate("cursor", &shell("cursor", command), &fixture.home);
        assert!(allowed(&result), "{command}: {}", result.reason_code);
        for harness in ["codex", "claude-code"] {
            let result = fixture.evaluate(harness, &shell(harness, command), &fixture.home);
            assert!(!allowed(&result), "{harness} {command}");
        }
    }

    let other_workspace = fixture.workspace.with_file_name("billing-api");
    std::fs::create_dir_all(&other_workspace).unwrap();
    std::fs::create_dir_all(fixture.workspace.join("src")).unwrap();
    let other = fixture
        .project_dir(&other_workspace)
        .join("terminals/120467.txt");
    // The workspace is the session's, so a `cd` into a subdirectory still
    // reads its own output, and a `cd` into another workspace does not make
    // that workspace's output the session's own.
    let into_src = format!("cd src && cat {terminal}");
    let result = fixture.in_shell_environment(&shell("cursor", &into_src));
    assert!(allowed(&result), "{into_src}: {}", result.reason_code);
    let into_other = format!(
        "cd {} && cat {}",
        other_workspace.display(),
        other.display()
    );
    let result = fixture.in_shell_environment(&shell("cursor", &into_other));
    assert!(!allowed(&result), "{into_other}");
    // The same `cd` with the read of a file the target workspace may read
    // is allowed, so the review above is the saved-output rule's answer.
    let control = format!("cd {} && cat {terminal}", other_workspace.display());
    let result = fixture.in_shell_environment(&shell("cursor", &control));
    assert!(allowed(&result), "{control}: {}", result.reason_code);
    for command in [
        format!("cat {}", other.display()),
        format!("cat {}", fixture.own("terminals/.state.txt")),
        format!("cat {}", fixture.own("terminals/linked.txt")),
        format!("cat {}", fixture.own("mcp-auth.json")),
        format!("cat {}", fixture.own("worker.log")),
    ] {
        let result = fixture.evaluate("cursor", &shell("cursor", &command), &fixture.home);
        assert!(!allowed(&result), "{command}");
    }
}
