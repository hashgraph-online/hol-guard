use super::*;
use serde_json::json;

fn object(value: Value) -> Map<String, Value> {
    let Value::Object(object) = value else {
        unreachable!()
    };
    object
}

fn receipt() -> Map<String, Value> {
    object(json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": WORKSPACE_REASON,
        "required_execution_profile": WORKSPACE_PROFILE,
        "reason": guard_command::pretool::CONTAINED_WORKTREE_ADD_REASON,
        "command_binding_digest": "a1",
    }))
}

#[test]
fn the_chain_must_keep_its_own_receipt_and_evidence() {
    let first = receipt();
    assert!(same_chain(&receipt(), &first));
    for (name, value) in [
        ("command_binding_digest", json!("b2")),
        ("command_binding_digest", Value::Null),
        ("observe_mode", json!(true)),
        ("reason", json!(split::PUBLISH_REASON)),
        ("decision", json!("allow")),
        ("policy_action", json!("review")),
    ] {
        let mut changed = receipt();
        changed.insert(name.to_owned(), value.clone());
        assert!(!same_chain(&changed, &first), "{name} = {value}");
    }
    // A first receipt without a digest binds nothing.
    let mut unbound = receipt();
    unbound.remove("command_binding_digest");
    assert!(!same_chain(&receipt(), &unbound));
}

/// The steps that fail before the resident is asked anything.
#[test]
fn a_chain_the_sink_cannot_split_again_runs_nothing() {
    let root = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let workspace = std::fs::canonicalize(root.path()).unwrap();
    let home = workspace.join("home");
    std::fs::create_dir(&home).unwrap();
    let arguments = Arguments {
        harness: "codex".to_owned(),
        guard_home: workspace.join("guard"),
        workspace: workspace.clone(),
        request_file: workspace.join("request.json"),
        request_sha256: String::new(),
        home,
    };
    let authority = Authority {
        arguments: &arguments,
        workspace: path_text(&workspace).unwrap(),
    };
    let signals = process::Signals::idle();
    let failure = |command: &str| {
        let payload = object(json!({ "tool_input": { "command": command } }));
        run(&payload, &workspace, &authority, &receipt(), &signals)
            .unwrap_err()
            .message
    };
    assert_eq!(failure("pytest"), UNSPLIT);
    // Another account's home is never resolved, whether or not the split
    // keeps the chain.
    let other =
        failure("git worktree add --detach ~other/app-fix HEAD && cd ~other/app-fix && pytest");
    assert!([UNSPLIT, NO_CHECKOUT].contains(&other.as_str()), "{other}");
    let empty = object(json!({ "tool_input": {} }));
    assert_eq!(
        run(&empty, &workspace, &authority, &receipt(), &signals)
            .unwrap_err()
            .reason,
        INVALID_COMMAND
    );
}
