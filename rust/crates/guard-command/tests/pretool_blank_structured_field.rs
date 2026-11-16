//! A structured field that is present and empty names nothing. These cases pin
//! that reading, and pin the payloads that must still be refused beside it.

use guard_command::pretool::evaluate_pre_tool_envelope;
use guard_command::MAX_COMMAND_BYTES;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

fn generic(payload: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope("claude-code", "PreToolUse", &payload)
}

/// A harness-native search tool spells "start where the project does" as an
/// empty path argument. The field is present and its type is right, so the
/// payload parses; there is simply no target in it, and a call that names no
/// target must not be read as a malformed payload and blocked. It must also
/// reach the answer a search of the project root reaches, because that is the
/// search it describes: the blank is the same scope an absent `path` names.
#[test]
fn a_blank_structured_field_names_nothing_rather_than_breaking_the_payload() {
    for payload in [
        json!({"hook_event_name": "PreToolUse", "tool_name": "glob", "tool_input": {"path": ""}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "glob", "tool_input": {"path": "   "}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "glob", "tool_input": {"path": "", "pattern": "**/*.md"}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "glob", "tool_input": {"path": ["", "src"]}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "grep", "tool_input": {"path": "", "pattern": "retryLimit"}}),
    ] {
        let result = evaluate_pre_tool_envelope("omp", "PreToolUse", &payload);
        assert_ne!(
            result.reason_code, "native_pre_tool_malformed_payload",
            "{payload}"
        );
        assert_ne!(result.minimum_action, "block", "{payload}");
    }
    // Proving the scope of a project-root search needs a verified workspace,
    // so the verdict itself is pinned against one.
    #[cfg(unix)]
    a_blank_search_path_earns_what_an_absent_one_earns();
}

/// A blank `path` and no `path` at all describe one search, so Oh My Pi's
/// `glob` and `grep` must answer both the same way: the bounded project-root
/// allow. Reading the blank as an unusable value instead dropped these calls
/// to a file-read review while the payload still parsed.
#[cfg(unix)]
fn a_blank_search_path_earns_what_an_absent_one_earns() {
    let workspace = BlankPathWorkspace::new();
    const LISTING: &str = "native_omp_directory_listing";
    const SEARCH: &str = "native_bounded_search_scope";
    for (tool, input, reason) in [
        // A blank path argument, in each spelling the extractor reads as
        // naming nothing.
        ("glob", json!({"path": ""}), LISTING),
        ("glob", json!({"path": "   "}), LISTING),
        ("glob", json!({"path": "", "pattern": "**/*.md"}), LISTING),
        ("grep", json!({"path": "", "pattern": "retryLimit"}), SEARCH),
        // The same calls with the key absent: the answer each blank must get.
        ("glob", json!({}), LISTING),
        ("glob", json!({"pattern": "**/*.md"}), LISTING),
        ("grep", json!({"pattern": "retryLimit"}), SEARCH),
    ] {
        let result = workspace.evaluate(tool, &input);
        assert_eq!(
            result.minimum_action, "allow",
            "{tool} {input}: {}",
            result.reason_code
        );
        assert_eq!(result.reason_code, reason, "{tool} {input}");
    }
}

/// An ordinary project inside its own home directory: the context a search
/// scope is proven against. Nothing sensitive lives in it, so the only thing
/// these cases can turn on is how the blank path itself is read.
#[cfg(unix)]
struct BlankPathWorkspace {
    root: std::path::PathBuf,
    home: std::path::PathBuf,
    project: std::path::PathBuf,
}

#[cfg(unix)]
impl Drop for BlankPathWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
impl BlankPathWorkspace {
    fn new() -> Self {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/pretool-blank-structured-field")
            .join(format!(
                "home-{}-{}",
                std::process::id(),
                crate::unique_nanos::unique_nanos()
            ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let home = root.join("home");
        let project = home.join("project");
        for file in ["README.md", "docs/retry.md", "src/index.ts"] {
            let path = project.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "synthetic fixture\n").unwrap();
        }
        Self {
            root,
            home,
            project,
        }
    }

    fn evaluate(&self, tool: &str, input: &Value) -> PreToolResultV1 {
        guard_command::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input}),
            None,
            None,
            self.home.to_str(),
            self.project.to_str(),
        )
    }
}

/// The blank reading applies to the fields that name a target, and nowhere
/// else. A payload that genuinely cannot be read, one that says two different
/// things, and one that exceeds the command bound each keep the answer they
/// had.
#[test]
fn unreadable_conflicting_and_oversized_payloads_still_block() {
    for unreadable in [
        json!({"tool_name": "glob", "tool_input": {"path": {"a": 1}}}),
        json!({"tool_name": "glob", "tool_input": {"path": null}}),
        json!({"tool_name": "glob", "tool_input": {"path": ["src", null]}}),
    ] {
        let result = generic(unreadable.clone());
        assert_eq!(result.minimum_action, "block", "{unreadable}");
        assert_eq!(
            result.reason_code, "native_pre_tool_malformed_payload",
            "{unreadable}"
        );
    }

    for blank_command in [
        json!({"tool_name": "Bash", "tool_input": {"command": ""}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "   "}}),
    ] {
        let result = generic(blank_command.clone());
        assert_eq!(result.minimum_action, "block", "{blank_command}");
        assert_eq!(
            result.reason_code, "native_pre_tool_malformed_payload",
            "{blank_command}"
        );
    }

    let oversized = generic(json!({
        "tool_name": "glob",
        "tool_input": {"path": "a".repeat(MAX_COMMAND_BYTES + 1)}
    }));
    assert_eq!(oversized.minimum_action, "block");
    assert_eq!(oversized.reason_code, "native_pre_tool_bounds_exceeded");

    let conflict = generic(json!({"command": "pwd", "cmd": "whoami"}));
    assert_eq!(conflict.minimum_action, "block");
    assert_eq!(conflict.reason_code, "native_pre_tool_ambiguous_payload");

    // A blank path is absent, not a read of nothing: the read-nothing proof
    // still needs an empty list or a null, so this call keeps its review.
    let blank_path = generic(json!({"tool_name": "Read", "tool_input": {"file_path": ""}}));
    assert_ne!(blank_path.reason_code, "native_empty_file_read_request");

    // Only a blank string reads as absent. A null target is not a read of
    // nothing either, so it can never earn that allow.
    let null_path = generic(json!({"tool_name": "Read", "tool_input": {"file_path": null}}));
    assert_ne!(null_path.minimum_action, "allow");
    assert_ne!(null_path.reason_code, "native_empty_file_read_request");
}

/// A file body skips the command-size bound only because the path beside it is
/// the value the decision reads. A path that names nothing cannot buy that
/// exemption, so an oversized body beside a blank path is still out of bounds.
#[test]
fn a_blank_path_does_not_exempt_the_body_beside_it_from_its_bound() {
    for path in [json!(""), json!("   "), json!([""]), json!([])] {
        let result = generic(json!({
            "tool_name": "Edit",
            "tool_input": {"path": path, "content": "a".repeat(MAX_COMMAND_BYTES + 1)}
        }));
        assert_eq!(result.minimum_action, "block", "{path}");
        assert_eq!(
            result.reason_code, "native_pre_tool_bounds_exceeded",
            "{path}"
        );
    }
    // A path that does name a file keeps the exemption: the body may be large.
    let named = generic(json!({
        "tool_name": "Edit",
        "tool_input": {"path": "src/report.ts", "content": "a".repeat(MAX_COMMAND_BYTES + 1)}
    }));
    assert_ne!(named.reason_code, "native_pre_tool_bounds_exceeded");
}
