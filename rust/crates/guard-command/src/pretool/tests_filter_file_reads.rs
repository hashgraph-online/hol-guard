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
        // `-k` and `-t` carry a key definition and a field separator, not a
        // second file to read, attached or as the next word.
        "sort -k2 Cargo.toml",
        "sort -k 2,2 Cargo.toml",
        "sort -t= -k2 Cargo.toml",
        "sort -t = -k 1 Cargo.toml",
        "sort -nk2 Cargo.toml",
        "sort --key=2 --field-separator== Cargo.toml",
        "sort -z -c Cargo.toml",
        "sort -S 16M Cargo.toml",
        // The shell writes `$'\\t'` out before Guard reads the word, so a tab
        // separator arrives as the character itself and is screened as the
        // one literal it is.
        "sort -t$'\\t' -k2 -n Cargo.toml",
        "sort --field-separator=$'\\t' --key=2 Cargo.toml",
        "cut -d$'\\t' -f1 Cargo.toml",
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
        // `-T` names a directory for the temporary runs and
        // `--compress-program` hands them to another program.
        "sort -T /tmp Cargo.toml",
        "sort --compress-program=gzip Cargo.toml",
        // `--output` is `-o` spelled long, and an abbreviation of it is not a
        // reading option either.
        "sort --output=sorted.txt Cargo.toml",
        "sort --out=sorted.txt Cargo.toml",
        // A separator is still one literal character: a parameter is a
        // reference the shell has not written out, and two tabs are not a
        // delimiter.
        "sort -t$SEPARATOR -k2 Cargo.toml",
        "cut -d$'\\t\\t' -f1 Cargo.toml",
        "cut -d$DELIMITER -f1 Cargo.toml",
    ] {
        assert!(!allowed(command), "{command}");
    }
}
