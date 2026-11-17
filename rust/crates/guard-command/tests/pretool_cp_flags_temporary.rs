#![cfg(unix)]
//! `cp` with `-c`, `-p` or `-v`, and `cp -R` into a private temporary
//! directory.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Fixture {
    home: PathBuf,
    project: PathBuf,
    scratch: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn write(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "synthetic fixture\n").unwrap();
}

fn directory(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Home and project stay outside the temporary roots. The scratch directory
/// under `/tmp` belongs to the user and holds a source tree, a file, a private
/// folder, a folder that already holds a `src`, and a folder anyone may write
/// to.
fn fixture(name: &str) -> Fixture {
    let home = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-cp-flags-temporary")
        .join(format!("{name}-{}", std::process::id()));
    let project = home.join("project");
    let scratch = PathBuf::from(format!("/tmp/hg-cp-flags-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&scratch);
    // Owns both trees from here on, so a failed setup step cleans up too.
    let mut fixture = Fixture {
        home: home.clone(),
        project: project.clone(),
        scratch: scratch.clone(),
    };
    for path in ["src/index.ts", "src/nested/util.ts", "secrets/.env"] {
        write(&project.join(path));
    }
    write(&home.join(".ssh/config"));
    directory(&scratch, 0o755);
    for path in ["src/lib/site.pth", "src/bin/run.txt", "note.txt"] {
        write(&scratch.join(path));
    }
    directory(&scratch.join("out"), 0o700);
    directory(&scratch.join("occupied/src"), 0o700);
    std::fs::set_permissions(
        scratch.join("occupied"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    directory(&scratch.join("shared"), 0o777);
    directory(&scratch.join("shared/inner"), 0o700);
    std::os::unix::fs::symlink(scratch.join("out"), scratch.join("alias")).unwrap();
    fixture.home = std::fs::canonicalize(&home).unwrap();
    fixture.project = std::fs::canonicalize(&project).unwrap();
    fixture
}

fn action(fixture: &Fixture, harness: &str, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        fixture.home.to_str(),
        fixture.project.to_str(),
    )
    .minimum_action
}

#[test]
fn copies_with_attribute_flags_and_trees_into_temporary_folders_are_bounded() {
    let fixture = fixture("allowed");
    let s = fixture.scratch.display();
    for command in [
        // A tree copied to a new temporary path, cloned, kept or named.
        format!("cp -cR {s}/src {s}/copy"),
        format!("cp -R {s}/src {s}/copy"),
        format!("cp -r {s}/src {s}/copy"),
        format!("cp -Rp {s}/src {s}/out/copy"),
        format!("cp -cRv {s}/src {s}/out"),
        // A project tree copied out to a scratch folder.
        format!("cp -R src {s}/project-src"),
        // Inside the project the flags change nothing either.
        "cp -Rp src src-copy".to_owned(),
        // One file, cloned or kept.
        format!("cp -c {s}/note.txt {s}/note-copy.txt"),
        format!("cp -p {s}/note.txt {s}/out/"),
        format!("cp -cpv {s}/note.txt {s}/note-2.txt"),
        "cp -p src/index.ts src/index.backup.ts".to_owned(),
    ] {
        for harness in ["claude-code", "codex", "cursor", "zcode"] {
            assert_eq!(
                action(&fixture, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn copies_that_merge_escape_or_take_other_flags_keep_their_review() {
    let fixture = fixture("refused");
    let s = fixture.scratch.display();
    let home = fixture.home.display();
    for command in [
        // A folder anyone may write to.
        format!("cp -cR {s}/src {s}/shared/copy"),
        // A private folder below one anyone may write to, who could swap the
        // shared folder for a planted tree after the check.
        format!("cp -R {s}/src {s}/shared/inner/copy"),
        // A link that resolves to the private folder now but can be pointed
        // elsewhere after the check.
        format!("cp -R {s}/src {s}/alias/copy"),
        format!("cp -c {s}/note.txt {s}/alias/note.txt"),
        // A new tree directly in the shared `/tmp`, where another user could
        // create the folder first.
        format!("cp -cR {s}/src /tmp/hg-cp-flags-new-{}", std::process::id()),
        format!(
            "cp -R {s}/src /var/tmp/hg-cp-flags-new-{}",
            std::process::id()
        ),
        // The tree would merge into an existing one.
        format!("cp -R {s}/src {s}/occupied"),
        // Into the source tree itself.
        format!("cp -R {s}/src {s}/src/again"),
        // A relative destination is the project, not the scratch folder.
        "cp -R src ../copy".to_owned(),
        // Sources that hold a secret, or are one.
        format!("cp -cR secrets {s}/secrets"),
        format!("cp -c {home}/.ssh/config {s}/config"),
        // A hidden home folder.
        format!("cp -R {s}/src {home}/.config/copy"),
        // Flags with another meaning.
        format!("cp -f {s}/note.txt {s}/forced.txt"),
        format!("cp -RL {s}/src {s}/followed"),
        format!("cp -Rn {s}/src {s}/copy"),
    ] {
        for harness in ["claude-code", "codex", "cursor", "zcode"] {
            assert_ne!(
                action(&fixture, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
