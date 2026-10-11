#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}
fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-home-documents")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    write(home.join(".agent/skills/demo/SKILL.md"), "inert skill\n");
    write(home.join(".ssh/id_rsa"), "synthetic sensitive fixture\n");
    Fixture {
        root,
        home,
        project,
    }
}
fn omp(fixture: &Fixture, tool: &str, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":tool,"tool_input":input}),
        None,
        None,
        fixture.home.to_str(),
        fixture.project.to_str(),
    )
}
fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn omp_home_document_reads_and_searches_keep_credential_and_link_floors() {
    let f = fixture();
    write(f.home.join(".agent/artifacts/report.md"), "Inert report\n");
    let skills = f.home.join(".agent/skills");
    let artifacts = f.home.join(".agent/artifacts");
    let selector = format!("{}/**/SKILL.md", skills.display());
    assert!(allowed(&omp(
        &f,
        "read",
        json!({"path": artifacts.join("report.md")})
    )));
    assert!(allowed(&omp(
        &f,
        "glob",
        json!({"path": selector, "hidden":true, "gitignore":false})
    )));
    assert!(allowed(&omp(
        &f,
        "grep",
        json!({"path": artifacts, "pattern":"Inert"})
    )));
    for path in [
        ".agent/artifacts/auth.md",
        ".agent/artifacts/.hidden/report.md",
        ".agent/auth.json",
    ] {
        write(f.home.join(path), "synthetic sensitive fixture\n");
        assert!(
            !allowed(&omp(&f, "read", json!({"path": f.home.join(path)}))),
            "{path}"
        );
    }
    write(
        skills.join("demo/credentials.md"),
        "synthetic sensitive fixture\n",
    );
    assert!(!allowed(&omp(
        &f,
        "glob",
        json!({"path": selector, "hidden":true, "gitignore":false})
    )));
    assert!(!allowed(&omp(
        &f,
        "grep",
        json!({"path": artifacts, "pattern":"Inert"})
    )));
    assert!(!allowed(&omp(
        &f,
        "read",
        json!({"path": artifacts.join("../auth.json")})
    )));
    let link = artifacts.join("linked.md");
    std::os::unix::fs::symlink(f.home.join(".ssh/id_rsa"), &link).unwrap();
    assert!(!allowed(&omp(&f, "read", json!({"path": link}))));
}

#[test]
fn private_temp_creation_allows_only_the_unique_directory_form() {
    let f = fixture();
    assert!(allowed(&omp(&f, "bash", json!({"command":"mktemp -d"}))));
    for command in [
        "mktemp",
        "mktemp -u",
        "mktemp -d -u",
        "mktemp -d /etc/test.XXXXXX",
        "mktemp -d; rm -rf /tmp/other",
        "TMPDIR=/etc mktemp -d",
    ] {
        assert!(
            !allowed(&omp(&f, "bash", json!({"command":command}))),
            "{command}"
        );
    }
}

#[test]
fn omp_document_searches_refuse_hidden_descendants_and_benign_symlinks() {
    let f = fixture();
    let skills = f.home.join(".agent/skills");
    write(skills.join(".hidden/SKILL.md"), "inert hidden fixture\n");
    assert!(!allowed(&omp(
        &f,
        "glob",
        json!({"path":format!("{}/**/SKILL.md", skills.display())})
    )));
    let artifacts = f.home.join(".agent/artifacts");
    write(artifacts.join("report.md"), "Inert report\n");
    std::os::unix::fs::symlink(artifacts.join("report.md"), artifacts.join("linked.md")).unwrap();
    assert!(!allowed(&omp(
        &f,
        "grep",
        json!({"path":artifacts,"pattern":"Inert"})
    )));
}
