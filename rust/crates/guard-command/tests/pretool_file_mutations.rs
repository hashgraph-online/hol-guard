#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn routine_file_mutations_do_not_inherit_sensitive_or_directory_delete_access() {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-mutations");
    std::fs::create_dir_all(&fixtures).unwrap();
    let mut attempt = 0;
    let root = loop {
        let candidate = fixtures.join(format!("fixture-{}-{attempt}", std::process::id()));
        match std::fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => attempt += 1,
            Err(error) => panic!("failed to create fixture directory: {error}"),
        }
    };
    std::fs::create_dir(root.join("src")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("src/example.ts"), "ordinary source").unwrap();
    std::fs::write(root.join("src/existing.ts"), "preserve destination").unwrap();
    std::fs::write(root.join(".env"), "synthetic secret").unwrap();
    std::os::unix::fs::symlink(root.join(".env"), root.join("src/alias.ts")).unwrap();
    for harness in ["omp", "zcode"] {
        for (command, expected) in [
            ("mkdir -p generated/edge/nested", true),
            ("mkdir --parents src", true),
            ("touch src/new.ts", true),
            ("mv src/example.ts src/renamed.ts", true),
            ("mv src/example.ts src/existing.ts", false),
            ("mv src/example.ts src", false),
            ("cp src/example.ts src", true),
            ("mkdir -p .git/hooks", false),
            ("mkdir -p ../outside", false),
            ("touch .env", false),
            ("touch src/alias.ts", false),
            ("mv .env src/example.ts", false),
            ("mv src/example.ts .env", false),
            ("mv src generated", false),
            ("mv -f src/example.ts src/renamed.ts", false),
            ("mkdir -p src && rm -rf generated", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash","toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}"
            );
        }
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"toolName":"Bash","toolInput":{"command":"mv src/example.ts src/existing.ts"}}),
            None,
            None,
            root.to_str(),
            Some("~"),
        );
        assert_ne!(
            result.minimum_action, "allow",
            "{harness}: home-relative cwd overwrite"
        );
    }
}
