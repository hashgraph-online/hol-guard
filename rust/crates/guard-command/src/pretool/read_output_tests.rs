use super::*;

#[test]
fn output_logs_are_read_only_and_do_not_open_application_state() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-output-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let output = root.join(".agent-state/cli/exec/sess_6f77a76f-0997-4644-b4db-19dae37b96a4/call_fd767b64352243ab8094f19b-stdout.log");
    std::fs::create_dir_all(output.parent().unwrap()).unwrap();
    std::fs::write(&output, "synthetic compiler diagnostic").unwrap();
    let home = std::fs::canonicalize(&root).unwrap();
    let output = std::fs::canonicalize(output).unwrap();
    let home_text = home.to_str();
    assert!(execution_output_log(&output, home_text));
    let decision = super::super::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Read", "tool_input": {"file_path": output.to_str().unwrap()}}),
        None,
        None,
        home_text,
        home_text,
    );
    assert_eq!(decision.minimum_action, "allow", "{}", decision.reason_code);
    assert!(resolved_path_allowed_for_operation(
        &output, home_text, home_text, true, true
    ));
    assert!(!resolved_path_allowed_for_operation(
        &output, home_text, home_text, true, false
    ));
    for path in [
        home.join(".agent-state/cli/setting.json"), output.with_file_name("credentials.json"),
        output.with_file_name("call_invalid-stdout.log"),
        home.join(".ssh/cli/exec/sess_6f77a76f-0997-4644-b4db-19dae37b96a4/call_fd767b64352243ab8094f19b-stdout.log"),
    ] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "synthetic fixture").unwrap();
        assert!(!execution_output_log(&path, home_text), "{}", path.display());
    }
    assert!(!execution_output_log(
        &output,
        output.parent().and_then(|path| path.to_str())
    ));
    #[cfg(unix)]
    {
        let link = output.with_file_name("call_aaaaaaaaaaaaaaaaaaaaaaaa-stderr.log");
        std::os::unix::fs::symlink(output.with_file_name("credentials.json"), &link).unwrap();
        assert!(!bounded_file_read_target(
            link.to_str().unwrap(),
            home_text,
            home_text
        ));
    }
    std::fs::remove_dir_all(root).unwrap();
}
