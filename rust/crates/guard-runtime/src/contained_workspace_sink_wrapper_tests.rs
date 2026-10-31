use super::*;

#[test]
fn the_status_echo_reads_the_last_stage() {
    assert_eq!(status("pipe", 3, Some(1)), 1);
    assert_eq!(status("pipe", 3, None), 0);
    assert_eq!(status("head", 3, None), 0);
    assert_eq!(status("tail", 3, None), 0);
    assert_eq!(status("all", 3, None), 3);
}

#[test]
fn only_a_sandbox_receipt_peels() {
    let receipt = |decision: &str, action: &str, observe: bool| {
        let Value::Object(receipt) = serde_json::json!({
            "decision": decision,
            "policy_action": action,
            "required_execution_profile": "workspace",
            "observe_mode": observe,
        }) else {
            unreachable!()
        };
        receipt
    };
    assert!(contained_receipt(&receipt(
        "deny",
        "sandbox-required",
        false
    )));
    assert!(!contained_receipt(&receipt(
        "deny",
        "sandbox-required",
        true
    )));
    assert!(!contained_receipt(&receipt("deny", "block", false)));
    assert!(!contained_receipt(&receipt(
        "allow",
        "sandbox-required",
        false
    )));
    let mut bare = receipt("deny", "sandbox-required", false);
    bare.remove("required_execution_profile");
    assert!(!contained_receipt(&bare));
}

#[test]
fn the_edge_sends_a_core_the_sink_runs_from_the_root() {
    let home = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let root = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    let (home, workspace) = (home.path().to_str().unwrap(), root.path().to_str().unwrap());
    let canonical = std::fs::canonicalize(workspace).unwrap();
    let canonical = canonical.to_str().unwrap();
    let core = |command: &str| native_core(command, workspace, home);
    for (command, expected) in [
        ("pytest -q", "pytest -q"),
        ("pytest -q 2>&1", "pytest -q"),
        ("pytest -q | tail -5", "pytest -q"),
        ("pytest -q 2>&1 | head -c 400", "pytest -q"),
        ("pytest -q 2>&1 | grep -c passed", "pytest -q"),
        ("pytest -q; echo \"exit=$?\"", "pytest -q"),
        (
            &format!("cd {canonical} && pytest -q | tail -3"),
            "pytest -q",
        ),
    ] {
        assert_eq!(core(command).as_deref(), Some(expected), "{command}");
    }
    for command in [
        format!("cd {canonical}/sub && pytest -q"),
        "cd sub && pytest -q".to_owned(),
        "pytest -q | sort".to_owned(),
        "pytest -q | tail -5 | head -2 | grep a | rg b".to_owned(),
    ] {
        assert_eq!(core(&command), None, "{command}");
    }
}
