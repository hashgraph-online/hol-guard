#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

struct FixtureDirectory(std::path::PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn allowed(command: &str, root: &std::path::Path) -> Vec<bool> {
    ["omp", "zcode", "claude-code"]
        .into_iter()
        .map(|harness| {
            evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            )
            .minimum_action
                == "allow"
        })
        .collect()
}

#[test]
fn an_exclusion_after_the_operands_is_read_without_counting_it() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-late-exclusions")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    std::fs::create_dir_all(root.join("src/fixtures")).unwrap();
    std::fs::create_dir_all(root.join("keyed/fixtures/tls")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("src/app.ts"), "ordinary").unwrap();
    std::fs::write(root.join("src/fixtures/sample.json"), "{}").unwrap();
    std::fs::write(root.join("keyed/app.ts"), "ordinary").unwrap();
    std::fs::write(
        root.join("keyed/fixtures/tls/test-root-ca.key"),
        "synthetic key",
    )
    .unwrap();
    for (command, expected) in [
        // The tree is safe to search in full, so pruning part of it is too.
        ("grep -rln ordinary src --exclude-dir=fixtures", true),
        (
            "grep -rln ordinary src --include='*.ts' --exclude-dir=fixtures | sort -u",
            true,
        ),
        ("grep -rn ordinary src --exclude='*.min.js'", true),
        // A late exclusion is not proof: the walk must be safe without it.
        ("grep -rln ordinary keyed --exclude-dir=fixtures", false),
        // GNU grep widens an include list once an exclude comes first.
        (
            "grep -rn ordinary src --include='*.ts' --exclude='*.min.js'",
            false,
        ),
        // Under POSIXLY_CORRECT, `fixtures` would become a search root.
        ("grep -rln ordinary src --exclude-dir fixtures", false),
        ("grep -rln ordinary src --exclude-dir=", false),
        (
            "touch -- --exclude-dir=fixtures; grep -rln ordinary src --exclude-dir=fixtures",
            false,
        ),
        // An include alone narrows the walk to the files it names.
        ("grep -rln ordinary --include='*.ts' keyed", true),
        ("grep -rln ordinary --exclude-dir=fixtures src", true),
        // An exclude before the include widens it under GNU grep, so the key
        // matching neither list is searched.
        (
            "grep -rln ordinary --exclude='*.min.js' --include='*.ts' keyed",
            false,
        ),
        (
            "grep -rln ordinary --exclude '*.min.js' --include='*.ts' keyed",
            false,
        ),
        // `X='fixtures ../keyed'` splits into one more operand.
        ("grep -rln ordinary src --exclude-dir=$X", false),
        ("grep -rln ordinary --exclude-dir=$X src", false),
        ("grep -rln ordinary --exclude-dir \"$X\" src", false),
        ("grep -rln ordinary --exclude=$(cat list) src", false),
    ] {
        assert_eq!(allowed(command, &root), vec![expected; 3], "{command}");
    }
    // A file of that name would be the operand under POSIXLY_CORRECT.
    std::fs::write(root.join("--Exclude-dir=fixtures"), "planted").unwrap();
    assert_eq!(
        allowed("grep -rln ordinary src --exclude-dir=fixtures", &root),
        vec![false; 3]
    );
}
