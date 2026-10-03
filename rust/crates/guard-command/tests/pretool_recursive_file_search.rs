#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

struct FixtureDirectory(std::path::PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn recursive_search_exclusions_prove_only_unread_descendants() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("exclusions-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    std::fs::create_dir_all(root.join("tests/fixtures/tls")).unwrap();
    std::fs::create_dir_all(root.join("mixed")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    // Match the real project's scale without touching production credentials.
    for index in 0..5_025 {
        std::fs::write(root.join(format!("tests/case-{index}.test.ts")), "ordinary").unwrap();
    }
    std::fs::write(
        root.join("tests/fixtures/tls/test-root-ca.key"),
        "synthetic key",
    )
    .unwrap();
    std::fs::write(root.join("mixed/one.ts"), "ordinary").unwrap();
    std::fs::write(root.join("mixed/private.key"), "synthetic key").unwrap();
    std::os::unix::fs::symlink(root.join("mixed/private.key"), root.join("mixed/alias.ts"))
        .unwrap();
    for harness in ["omp", "zcode"] {
        for (command, expected) in [
            ("grep -rn ordinary tests/", false),
            ("grep -rn --exclude-dir=fixtures ordinary tests/", true),
            ("grep -rn --exclude-dir fixtures ordinary tests/", true),
            ("grep -rn ordinary tests/ --exclude-dir=fixtures", true),
            ("grep -rn --exclude-dir=fixture ordinary tests/", false),
            ("grep -rn --exclude=fixtures ordinary tests/", false),
            ("grep -rn --exclude=test-root-ca.key ordinary tests/", true),
            ("grep -rn --exclude test-root-ca.key ordinary tests/", true),
            (
                "grep -rn --exclude=test-root-ca.key ordinary tests/fixtures/tls/test-root-ca.key",
                false,
            ),
            (
                "grep -rn --exclude-dir=fixtures ordinary tests/fixtures/",
                false,
            ),
            (
                "grep -rn --exclude-dir=fixtures ordinary tests/ mixed/",
                false,
            ),
            (
                "grep -rn --exclude=private.key --exclude=alias.ts ordinary mixed/",
                false,
            ),
            (
                "grep -rn --exclude-dir=fixtures --exclude='*.key' ordinary tests/",
                false,
            ),
            (
                "grep -rn --exclude-dir=fixtures ordinary tests/ --exclude",
                false,
            ),
            ("grep -rn --exclude-dir= fixtures ordinary tests/", false),
            (
                "grep -rn --exclude= test-root-ca.key ordinary tests/",
                false,
            ),
            (
                "grep -rn --exclude=test-root-ca.key --include=test-root-ca.key ordinary tests/",
                false,
            ),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
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
    }
}

#[test]
fn recursive_search_checks_every_reachable_path() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    std::fs::create_dir_all(root.join("src")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("src/one.ts"), "ordinary source").unwrap();
    std::fs::write(root.join("src/two.ts"), "ordinary source").unwrap();
    std::fs::create_dir_all(root.join("__tests__/nested")).unwrap();
    std::fs::write(
        root.join("__tests__/nested/canary.test.ts"),
        "ordinary source",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("unsafe-tests")).unwrap();
    std::fs::write(root.join("unsafe-tests/.env"), "synthetic secret").unwrap();
    std::fs::write(root.join(".env"), "synthetic secret").unwrap();
    std::os::unix::fs::symlink(root.join(".env"), root.join("src/alias.ts")).unwrap();
    std::os::unix::fs::symlink(root.join("__tests__"), root.join("test-alias")).unwrap();
    for harness in ["omp", "zcode"] {
        for cwd in ["~", "~/__tests__"] {
            let command = if cwd == "~" {
                "grep -rn ordinary __tests__/"
            } else {
                "grep -rn ordinary nested/"
            };
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                Some(cwd),
            );
            assert_eq!(result.minimum_action, "allow", "{harness}: {cwd}");
        }
        for (command, expected) in [
            ("grep -rn ordinary src/one.ts src/two.ts".to_owned(), true),
            (
                format!(
                    "grep -rn ordinary {}/src/one.ts {}/src/two.ts",
                    root.display(),
                    root.display()
                ),
                true,
            ),
            ("grep -Rn ordinary src/one.ts".to_owned(), true),
            ("grep --recursive -n ordinary src/one.ts".to_owned(), true),
            (
                "grep --directories=recurse ordinary src/one.ts".to_owned(),
                true,
            ),
            ("grep -rn ordinary src".to_owned(), false),
            ("grep -rn ordinary __tests__/".to_owned(), true),
            (
                format!("grep -rn ordinary {}/__tests__/", root.display()),
                true,
            ),
            ("grep -Rn ordinary __tests__/".to_owned(), true),
            ("grep --recursive ordinary __tests__/".to_owned(), true),
            ("grep -rn ordinary unsafe-tests/".to_owned(), false),
            (
                format!("rg -n ordinary {}/__tests__/", root.display()),
                true,
            ),
            (
                format!("rg -n ordinary {}/unsafe-tests/", root.display()),
                false,
            ),
            ("grep -Rn ordinary test-alias/".to_owned(), false),
            ("grep -rn ordinary __tests__/ src/".to_owned(), false),
            ("grep -rn -e ordinary __tests__/".to_owned(), true),
            ("grep -rn -- ordinary __tests__/".to_owned(), true),
            ("grep -rn ordinary .".to_owned(), false),
            ("grep -rn ordinary".to_owned(), false),
            ("grep -rn ordinary src/missing.ts".to_owned(), false),
            ("grep -rn ordinary src/alias.ts".to_owned(), false),
            ("grep -rn ordinary src/one.ts .env".to_owned(), false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
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
    }
}
