#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn cwd_compounds_validate_reads_and_one_bounded_write() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/cwd-compound-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    std::fs::write(project.join("one.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(project.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
    std::os::unix::fs::symlink(project.join(".env"), project.join("alias.txt")).unwrap();
    for harness in ["omp", "zcode"] {
        for (suffix, allowed) in [
            ("&& cat one.txt", true),
            ("&& grep -n ordinary one.txt | head -1", true),
            ("&& wc -l one.txt", true),
            ("&& cat one.txt | sort -u", true),
            ("&& cat one.txt && head -1 one.txt", true),
            ("&& cat one.txt; cat one.txt", false),
            ("&& cat one.txt || cat one.txt", false),
            ("&& cat alias.txt", false),
            ("&& cat .env", false),
            ("; cat one.txt", false),
            ("|| cat one.txt", false),
            ("| cat one.txt", false),
            ("&& cd .. && cat one.txt", false),
            ("&& cp one.txt copy.txt", true),
            ("&& mkdir -p generated/nested", true),
            ("&& touch created.txt", true),
            ("&& mv one.txt moved.txt", true),
            ("&& cp .env copy.txt", false),
            ("&& cp alias.txt copy.txt", false),
            ("&& cp one.txt .env", false),
            ("&& cp one.txt .git/config", false),
            ("&& touch alias.txt", false),
            ("&& mkdir -p .git/hooks", false),
            ("&& mv one.txt .env", false),
            ("&& cp one.txt copy.txt && cat copy.txt", false),
            ("&& mkdir generated && touch generated/file.txt", false),
            ("&& rm -rf project", false),
            ("&& cat one.txt > copy.txt", false),
            ("&& cat one.txt >> .env", false),
            ("&& cat < .env", false),
            ("&& cat one.txt &", false),
            ("&& cat $(echo one.txt)", false),
            ("&& cat one.txt && gh auth token", false),
        ] {
            let command = format!("cd {} {suffix}", project.display());
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command}"
            );
        }
    }

    for harness in ["omp", "zcode"] {
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"cd project && cp one.txt relative-copy.txt"}}),
            None,
            None,
            root.to_str(),
            root.to_str(),
        );
        assert_ne!(
            result.minimum_action, "allow",
            "{harness}: relative cd copy"
        );
    }

    for target in [root.join("missing"), project.join(".."), root.join("alias")] {
        if target == root.join("alias") {
            std::os::unix::fs::symlink(&project, &target).unwrap();
        }
        let command = format!("cd {} && cat one.txt", target.display());
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            None,
            None,
            root.to_str(),
            root.to_str(),
        );
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
    let result = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":format!("cd {} && cat one.txt", project.display())}}),
        None,
        None,
        None,
        None,
    );
    assert_ne!(result.minimum_action, "allow");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cwd_compound_extension_deny_overrides_safe_neighbor() {
    use guard_command::native_command_controls::CompiledNativeCommandControls;
    use guard_command::native_command_program::packaged_command_program;
    use guard_contracts::NativeCommandControlBindingV1;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/cwd-compound-control-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    std::fs::write(project.join("one.txt"), "ordinary fixture\n").unwrap();
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":[{
                "target_kind":"permission", "target_id":"command.github.permission.read-local",
                "state":"disabled"
            }]
        }]
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    for harness in ["omp", "zcode"] {
        for command in [
            format!("cd {} && gh auth status", project.display()),
            format!(
                "cd {} && echo ordinary && gh auth status",
                project.display()
            ),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&controls),
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(result.minimum_action, "block", "{harness}: {command}");
            assert_eq!(result.decision, "deny", "{harness}: {command}");
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
