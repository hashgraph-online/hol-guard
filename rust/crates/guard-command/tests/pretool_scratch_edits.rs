#![cfg(unix)]

//! A chain may copy a file into a private temporary directory and edit the
//! copy: `cp /tmp/a.ts /tmp/b.ts && sed -i '' 's|x|y|' /tmp/b.ts`. Each step
//! only touches files the proof names, and nothing in the chain may link,
//! rename or change directory, so the checked path is the path that is opened.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    scratch: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Home and the project stay outside the temporary roots. The scratch
/// directory is private and sits directly under `/tmp`.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-scratch-edits")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(project.join("src/a.ts"), "export const a = 1;\n").unwrap();
    std::fs::write(home.join(".ssh/id_rsa"), "synthetic key\n").unwrap();
    std::fs::write(home.join(".zshrc"), "# synthetic\n").unwrap();
    let scratch = PathBuf::from(format!(
        "/tmp/hg-scratch-edit-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(scratch.join("a.ts"), "export const a = 1;\n").unwrap();
    std::fs::write(scratch.join("staged.ts"), "export const staged = 1;\n").unwrap();
    std::fs::write(scratch.join("run.sh"), "echo run\n").unwrap();
    std::fs::set_permissions(
        scratch.join("run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::os::unix::fs::symlink(home.join(".ssh/id_rsa"), scratch.join("link.ts")).unwrap();
    std::fs::write(scratch.join("held.md"), "held\n").unwrap();
    std::fs::hard_link(scratch.join("held.md"), scratch.join("alias.md")).unwrap();
    Fixture {
        home: std::fs::canonicalize(&home).unwrap(),
        project: std::fs::canonicalize(&project).unwrap(),
        root,
        scratch,
    }
}

fn permitted(fixture: &Fixture, command: &str) -> bool {
    let evaluate = |harness| {
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"toolName": "Bash", "toolInput": {"command": command}}),
            None,
            None,
            fixture.home.to_str(),
            fixture.project.to_str(),
        );
        result.decision == "allow" && matches!(result.minimum_action.as_str(), "allow" | "warn")
    };
    let zcode = evaluate("zcode");
    assert_eq!(zcode, evaluate("omp"), "host policy drift: {command}");
    zcode
}

#[test]
fn a_chain_edits_its_own_scratch_copy() {
    let fixture = fixture("allowed");
    let scratch = fixture.scratch.display();
    for command in [
        format!("cp {scratch}/a.ts {scratch}/copy.ts && sed -i '' 's|a = 1|a = 2|' {scratch}/copy.ts"),
        format!(
            "cp {scratch}/a.ts {scratch}/copy.ts && sed -i '' 's|a = 1|a = 2|' {scratch}/copy.ts && sed -n 1,3p {scratch}/copy.ts"
        ),
        format!(
            "cp {scratch}/a.ts {scratch}/copy.ts && sed -i '' -e 's|a = 1|a = 2|' -e 's|2|3|g' {scratch}/copy.ts"
        ),
        format!("sed -i '' 's|a = 1|a = 2|' {scratch}/a.ts"),
        format!(
            "awk 'NR==1 {{ print \"// first\"; print \"// second\"; next }} {{ print }}' {scratch}/a.ts > {scratch}/out.ts && wc -l {scratch}/out.ts"
        ),
        format!(
            "mkdir -p {scratch}/pkg && cp {scratch}/a.ts {scratch}/pkg/index.ts && cp {scratch}/staged.ts {scratch}/pkg/"
        ),
    ] {
        assert!(permitted(&fixture, &command), "{command}");
    }
}

/// BSD sed spells a line insert `/pat/a\` plus the text, and only BSD sed reads
/// `-i ''` followed by an address as a script. GNU sed would take that address
/// for a file name, so the same command stays reviewed there.
#[test]
fn a_bsd_line_insert_edits_a_scratch_copy_on_macos_only() {
    let fixture = fixture("insert");
    let scratch = fixture.scratch.display();
    let insert = format!(
        "cp {scratch}/a.ts {scratch}/copy.ts && sed -i '' '/export const a/a\\\nexport const b = 2;' {scratch}/copy.ts && sed -n 1,3p {scratch}/copy.ts"
    );
    assert_eq!(
        permitted(&fixture, &insert),
        cfg!(target_os = "macos"),
        "{insert}"
    );
    // Text that ends in an unescaped newline starts a second command.
    let second_command = format!(
        "cp {scratch}/a.ts {scratch}/copy.ts && sed -i '' '/export/a\\\nx\nw {scratch}/leak.txt' {scratch}/copy.ts"
    );
    assert!(!permitted(&fixture, &second_command), "{second_command}");
}

#[test]
fn scratch_edits_keep_link_target_and_script_boundaries() {
    let fixture = fixture("reviewed");
    let scratch = fixture.scratch.display();
    let home = fixture.home.display();
    for command in [
        // Links, hard-link aliases, executables, hidden names and missing parents.
        format!("sed -i '' 's|a|b|' {scratch}/link.ts"),
        format!("sed -i '' 's|a|b|' {scratch}/alias.md"),
        format!("sed -i '' 's|a|b|' {scratch}/run.sh"),
        format!("sed -i '' 's|a|b|' {scratch}/.hidden.ts"),
        format!("sed -i '' 's|a|b|' {scratch}/missing/x.ts"),
        // Files that are not scratch files.
        format!("sed -i '' 's|a|b|' {home}/.zshrc"),
        format!("cp {scratch}/a.ts {scratch}/c.ts && sed -i '' 's|a|b|' ~/.zshrc"),
        format!("cp {scratch}/a.ts {scratch}/c.ts && sed -i '' 's|a|b|' /etc/hosts"),
        // A backup file, and scripts that run commands or write other files.
        format!("sed -i.bak 's|a|b|' {scratch}/a.ts"),
        format!("sed -i '' 's|a|b|e' {scratch}/a.ts"),
        format!("sed -i '' 's|a|b|w {scratch}/leak.txt' {scratch}/a.ts"),
        format!("sed -i '' '/a/c\\\nx' {scratch}/a.ts"),
        format!("sed -i '' '1,2a\\\nx' {scratch}/a.ts"),
        // Another interpreter edits a scratch file.
        format!("perl -i -pe 's|a|b|' {scratch}/a.ts"),
        format!("node -e \"require('fs').writeFileSync('{scratch}/a.ts', 'x')\""),
        // The chain could link, rename or change directory first, or run the result.
        format!(
            "cp {scratch}/a.ts {scratch}/c.ts && ln -sf {home}/.ssh/id_rsa {scratch}/c.ts && sed -i '' 's|a|b|' {scratch}/c.ts"
        ),
        format!(
            "cp {scratch}/a.ts {scratch}/c.ts && mv {scratch}/c.ts {scratch}/d.ts && sed -i '' 's|a|b|' {scratch}/d.ts"
        ),
        format!("cd {scratch} && cp a.ts c.ts && sed -i '' 's|a|b|' c.ts"),
        format!(
            "cp {scratch}/a.ts {scratch}/c.sh && sed -i '' 's|a|b|' {scratch}/c.sh && sh {scratch}/c.sh"
        ),
        // A workspace file copied from scratch is edited under the workspace rules.
        format!("cp {scratch}/a.ts src/b.ts && sed -i '' 's|a|b|' src/b.ts"),
        // A new directory is only proven for files placed directly inside it.
        format!("mkdir -p {scratch}/pkg && cp {scratch}/a.ts {scratch}/other/index.ts"),
        format!("mkdir -p {scratch}/pkg && cp {scratch}/a.ts {scratch}/pkg/sub/index.ts"),
        format!("mkdir -p {scratch}/pkg && cp {scratch}/a.ts {scratch}/pkg/.hidden"),
        format!("mkdir -p {scratch}/pkg && ln -s {home}/.ssh {scratch}/pkg/keys"),
        format!("mkdir -p {scratch}/pkg && cp {scratch}/link.ts {scratch}/pkg/index.ts"),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
}

/// Another user could create `/tmp/<name>` before the chain runs, and
/// `mkdir -p` accepts it silently, so a copy into a directory made directly
/// under a shared root stays reviewed. A private parent keeps the copy quiet.
#[test]
fn a_directory_made_under_a_shared_root_keeps_review() {
    let fixture = fixture("shared-root");
    let scratch = fixture.scratch.display();
    let id = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    );
    for root in ["/tmp", "/var/tmp"] {
        let shared = format!("{root}/hg-shared-{id}");
        let command = format!("mkdir -p {shared} && cp {scratch}/a.ts {shared}/index.ts");
        assert!(!permitted(&fixture, &command), "{command}");
        assert!(!Path::new(&shared).exists(), "{shared}");
    }
    let private = format!("mkdir -p {scratch}/pkg && cp {scratch}/a.ts {scratch}/pkg/index.ts");
    assert!(permitted(&fixture, &private), "{private}");
}

/// GNU sed reads the script of `-i '' SCRIPT FILE` as a file, so a file of
/// that name in the working directory would be rewritten without a check.
/// BSD sed reads it as the script.
#[test]
fn an_existing_file_named_like_the_script_keeps_review_on_gnu_sed() {
    let fixture = fixture("script-file");
    let scratch = fixture.scratch.display();
    let command = format!("sed -i '' 's|a = 1|a = 2|' {scratch}/a.ts");
    assert!(permitted(&fixture, &command), "{command}");
    std::fs::write(fixture.project.join("s|a = 1|a = 2|"), "x\n").unwrap();
    assert_eq!(
        permitted(&fixture, &command),
        cfg!(target_os = "macos"),
        "{command}"
    );
}
