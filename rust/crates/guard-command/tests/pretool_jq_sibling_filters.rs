#![cfg(unix)]

//! `jq` reads of a file in a sibling checkout admit the same reshaping
//! filters as reads inside the workspace: bare builtins (`keys`, `length`)
//! and objects built from admitted filters. Environment, input, format and
//! file-reading forms, and secret targets, stay reviewed.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    sibling: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture(name: &str) -> Fixture {
    // Avoid macOS's protected /private/var temporary root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-jq-sibling-filters")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    for repository in ["project", "sibling"] {
        let path = home.join("code").join(repository);
        std::fs::create_dir_all(&path).unwrap();
        assert!(Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&path)
            .status()
            .unwrap()
            .success());
    }
    let sibling = home.join("code/sibling");
    std::fs::write(
        sibling.join("package.json"),
        "{\"queries\":{\"x\":1,\"y\":2}}\n",
    )
    .unwrap();
    std::fs::write(sibling.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    Fixture {
        root,
        project: home.join("code/project"),
        sibling: home.join("code/sibling"),
        home,
    }
}

fn allowed(fixture: &Fixture, command: &str) -> bool {
    let input = json!({"toolName": "Bash", "toolInput": {"command": command}});
    ["zcode", "omp"].iter().all(|harness| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &input,
            None,
            None,
            fixture.home.to_str(),
            fixture.project.to_str(),
        )
        .minimum_action
            == "allow"
    })
}

#[test]
fn sibling_jq_reads_admit_builtins_and_objects() {
    let fixture = fixture("allow");
    let file = fixture.sibling.join("package.json");
    let file = file.to_str().unwrap();
    for filter in [
        "'keys'",
        "'length'",
        "'.queries | keys[]'",
        "\".queries | keys[]\"",
        "\".queries | keys | join(\\\"\\n\\\")\"",
        "\".queries | to_entries[] | .key\"",
        "\"{\\\"a\\\": .queries|has(\\\"x\\\"), \\\"b\\\": .queries|has(\\\"y\\\")}\"",
        "\".queries | has(\\\"x\\\")\"",
    ] {
        let command = format!("jq -r {filter} {file}");
        assert!(allowed(&fixture, &command), "{command}");
    }
}

#[test]
fn sibling_jq_reads_keep_reaching_forms_reviewed() {
    let fixture = fixture("review");
    let sibling = fixture.sibling.to_str().unwrap().to_owned();
    let file = format!("{sibling}/package.json");
    for command in [
        format!("jq -r 'env' {file}"),
        format!("jq -r '{{a: env}}' {file}"),
        format!("jq -r '{{a: input}}' {file}"),
        format!("jq -r '$ENV' {file}"),
        format!("jq -r '{{a: $__loc__}}' {file}"),
        format!("jq -r 'input_filename' {file}"),
        format!("jq -r '{{(.a): .b}}' {file}"),
        format!("jq -r '@sh' {file}"),
        format!("jq -r 'keys' {sibling}/.env"),
        format!("jq -r '{{a: .x}}' {sibling}/.env"),
        format!("jq --rawfile a {sibling}/.env 'keys' {file}"),
        format!("jq --slurpfile a {file} 'keys' {file}"),
        format!("jq -f {file} {file}"),
        format!("jq -r 'keys | @sh' {file} | sh"),
    ] {
        assert!(!allowed(&fixture, &command), "{command}");
    }
}
