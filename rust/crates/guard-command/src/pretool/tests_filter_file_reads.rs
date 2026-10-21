use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

fn allowed(command: &str) -> bool {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    evaluate_pre_tool_with_context(&request(command), Some(root), Some(root))
        .is_ok_and(|decision| decision.minimum_action == "allow")
}

#[test]
fn a_filter_reading_a_proven_file_needs_no_review() {
    for command in [
        "sort Cargo.toml",
        "sort -u Cargo.toml",
        "sort -rn Cargo.toml",
        "sort Cargo.toml src/pretool.rs",
        "uniq Cargo.toml",
        "uniq -c Cargo.toml",
        "cut -d= -f1 Cargo.toml",
        "cut -c1-10 Cargo.toml",
    ] {
        assert!(allowed(command), "{command}");
    }
}

#[test]
fn a_filter_that_could_write_or_reach_further_still_takes_review() {
    for command in [
        // `-o` names an output file.
        "sort -o sorted.txt Cargo.toml",
        // `uniq INPUT OUTPUT` truncates the second operand.
        "uniq Cargo.toml counted.txt",
        // No selection, so `cut` was never proven.
        "cut Cargo.toml",
        // `tr` takes character sets, never a file.
        "tr a-z A-Z Cargo.toml",
        // An operand outside the proven read scope.
        "sort /nonexistent-guard-fixture/secret.key",
        "cut -d: -f1 /nonexistent-guard-fixture/passwd",
    ] {
        assert!(!allowed(command), "{command}");
    }
}
