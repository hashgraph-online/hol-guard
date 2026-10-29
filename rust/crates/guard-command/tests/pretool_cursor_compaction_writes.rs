//! A Cursor conversation files its compaction summary as `INDEX.md` and
//! numbered `segment_NNN.md` notes beside its own transcript. Those writes are
//! allowed; the transcript itself, another name in the folder, another
//! conversation's or another workspace's notes, a linked or multiply linked
//! note, and the same write from any other harness keep their review.
#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const OWN_CONVERSATION: &str = "5d0c3b9e-7a41-4c1f-9b2e-0f6a8d4c2e71";
const OTHER_CONVERSATION: &str = "9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a";
const LINKED_CONVERSATION: &str = "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9";

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/pretool-cursor-compaction")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let home = root.join("home");
        let workspace = root.join("work").join("app-portal");
        std::fs::create_dir_all(&workspace).unwrap();
        let fixture = Self {
            home,
            workspace,
            root,
        };
        let own = fixture.project_dir(&fixture.workspace);
        let other = fixture.project_dir(&fixture.root.join("work").join("billing-api"));
        for project in [&own, &other] {
            for conversation in [OWN_CONVERSATION, OTHER_CONVERSATION] {
                let transcripts = project.join("agent-transcripts").join(conversation);
                for leaf in ["compaction/INDEX.md", "compaction/segment_000.md"] {
                    let path = transcripts.join(leaf);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, "# Synthetic summary\n").unwrap();
                }
                std::fs::write(transcripts.join(format!("{conversation}.jsonl")), "{}\n").unwrap();
            }
        }
        let compaction = fixture.own_compaction();
        std::fs::create_dir_all(compaction.join("nested")).unwrap();
        std::fs::write(compaction.join("segment_001.md"), "# Run\n").unwrap();
        std::fs::set_permissions(
            compaction.join("segment_001.md"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            compaction.join("INDEX.md"),
            compaction.join("segment_002.md"),
        )
        .unwrap();
        let outside = fixture.home.join("outside-note.md");
        std::fs::write(&outside, "# Elsewhere\n").unwrap();
        std::fs::hard_link(&outside, compaction.join("segment_003.md")).unwrap();
        let linked = own.join("agent-transcripts").join(LINKED_CONVERSATION);
        std::os::unix::fs::symlink(compaction.parent().unwrap(), &linked).unwrap();
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

    fn own_compaction(&self) -> PathBuf {
        self.project_dir(&self.workspace)
            .join("agent-transcripts")
            .join(OWN_CONVERSATION)
            .join("compaction")
    }

    fn write(&self, harness: &str, path: &Path, conversation: Option<&str>) -> PreToolResultV1 {
        let path = path.to_string_lossy();
        let mut payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": path, "content": "# Summary\n\nWork so far.\n"},
        });
        if let Some(conversation) = conversation {
            payload["conversation_id"] = Value::from(conversation);
        }
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &payload,
            None,
            None,
            self.home.to_str(),
            self.workspace.to_str(),
        )
    }
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn cursor_writes_its_own_conversation_compaction_notes() {
    let fixture = Fixture::new("own");
    let compaction = fixture.own_compaction();
    for leaf in ["INDEX.md", "segment_000.md", "segment_009.md"] {
        let result = fixture.write("cursor", &compaction.join(leaf), Some(OWN_CONVERSATION));
        assert!(allowed(&result), "{leaf}: {}", result.reason_code);
        assert_eq!(result.reason_code, "native_exact_safe_file_write");
    }
}

#[test]
fn other_compaction_targets_keep_review() {
    let fixture = Fixture::new("negative");
    let compaction = fixture.own_compaction();
    let own_transcripts = compaction.parent().unwrap().to_path_buf();
    let other_workspace = fixture
        .project_dir(&fixture.root.join("work").join("billing-api"))
        .join("agent-transcripts")
        .join(OWN_CONVERSATION)
        .join("compaction/segment_004.md");
    let other_conversation = own_transcripts
        .with_file_name(OTHER_CONVERSATION)
        .join("compaction/segment_004.md");
    for path in [
        own_transcripts.join(format!("{OWN_CONVERSATION}.jsonl")),
        compaction.join("notes.md"),
        compaction.join("AGENTS.md"),
        compaction.join("nested/segment_004.md"),
        compaction.join("segment_001.md"),
        compaction.join("segment_002.md"),
        compaction.join("segment_003.md"),
        compaction.join("../compaction/segment_004.md"),
        other_workspace,
        other_conversation,
    ] {
        let result = fixture.write("cursor", &path, Some(OWN_CONVERSATION));
        assert!(
            !allowed(&result),
            "{}: {}",
            path.display(),
            result.reason_code
        );
    }
    // A conversation folder that is a link to another one is not its own.
    let linked = own_transcripts
        .with_file_name(LINKED_CONVERSATION)
        .join("compaction/segment_004.md");
    let result = fixture.write("cursor", &linked, Some(LINKED_CONVERSATION));
    assert!(!allowed(&result), "linked folder: {}", result.reason_code);
    let note = compaction.join("segment_004.md");
    let result = fixture.write("cursor", &note, None);
    assert!(!allowed(&result), "no conversation: {}", result.reason_code);
    let result = fixture.write("cursor", &note, Some(OTHER_CONVERSATION));
    assert!(
        !allowed(&result),
        "other conversation: {}",
        result.reason_code
    );
    for harness in ["claude-code", "codex", "zcode"] {
        let result = fixture.write(harness, &note, Some(OWN_CONVERSATION));
        assert!(!allowed(&result), "{harness}: {}", result.reason_code);
    }
}
