use super::ref_names;
use crate::pretool::search_pattern_text::command_sensitive;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A working directory holding one file whose name carries a credential
/// word, so a token that reaches it can be told from a ref name.
fn fixture() -> PathBuf {
    let serial = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "hol-guard-ref-names-{}-{serial}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("the fixture directory is created");
    std::fs::write(root.join("secrets.md"), "notes\n").expect("the document is written");
    root
}

fn model(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .expect("the command parses")
}

fn sensitive(command: &str, cwd: &str) -> bool {
    command_sensitive(&model(command), command, Some(cwd))
}

/// A credential word inside a branch, tag or refspec names a ref, not a
/// file. Reading the whole command text sent ordinary branch work to the
/// approval center, so each of these spellings sheds the word.
#[test]
fn a_credential_word_in_a_ref_name_is_not_a_read() {
    let root = fixture();
    let cwd = root.to_str().expect("the fixture path is text");
    for command in [
        "git checkout -b fix/secret-scan-gate",
        "git checkout -B fix/secret-scan-gate",
        "git branch feat/password-rotation",
        "git branch -m feat/api-key-rotation",
        "git switch -c chore/api-key-refresh",
        "git switch --create=chore/api-key-refresh",
        "git tag v2-secret-audit",
        "git push origin fix/secret-scan-gate",
        "git log --oneline origin/add-secret-blast-radius -5",
        "git clone --branch feat/password-reset https://example.test/project.git",
        "gh run list --branch add-secret-blast-radius",
        "gh pr list --head fix/secrets-redaction",
        "gh pr create --base main --head feat/api-key-rotation",
        "gh run list --branch=feat/password-reset",
        // Git's own options come before the verb, and `--` only ends the
        // options for a verb that has no path to name.
        "git --no-pager checkout -b fix/secret-scan-gate",
        "git -p log --oneline origin/add-secret-blast-radius -5",
        "git branch -- feat/secret-rotation",
    ] {
        assert!(
            !sensitive(command, cwd),
            "{command} still reads as sensitive"
        );
    }
}

/// Only a token the grammar fixes as a ref name is set aside. A pathspec, a
/// `rev:path` operand and a verb with no ref position each name something
/// the command can open, so every one of them keeps its screen.
#[test]
fn a_token_that_can_reach_a_file_keeps_its_screen() {
    let root = fixture();
    let cwd = root.to_str().expect("the fixture path is text");
    for command in [
        "git log -- secrets.md",
        "git log secrets.md",
        "git show main:config/secrets.json",
        "git checkout fix/secret-scan-gate -- secrets.md",
        "gh api repos/acme/project/contents/secrets.json",
        "cat secrets.md",
        // `-x` runs its value, and a ref name holds no whitespace, so the
        // shell command it carries keeps every word it spells.
        "git rebase -x 'cat secrets.md' main",
        // A pathspec the shell may expand onto a file is not a ref name.
        "git log *secret*",
        // `-b` is the body text for the create and edit verbs.
        "gh pr create -b 'password=example-value'",
        "gh issue create -t audit -b 'password=example-value'",
        // A global option that carries a value can send git elsewhere, so
        // no name is read against this directory at all.
        "git -C project checkout -b fix/secret-scan-gate",
    ] {
        assert!(
            sensitive(command, cwd),
            "{command} lost a signal to the mask"
        );
    }
}

/// A relative ref name is only proven against the directory the command
/// starts in. Once a segment moves between directories that reading is
/// gone, so no name is set aside.
#[test]
fn a_command_that_moves_between_directories_proves_no_ref_name() {
    let root = fixture();
    let cwd = root.to_str().expect("the fixture path is text");
    let command = "cd project && git checkout -b fix/secret-scan-gate";
    assert!(ref_names(&model(command), Some(cwd), true).is_empty());
    assert!(
        sensitive(command, cwd),
        "{command} lost a signal to the mask"
    );
}

/// Without a working directory a candidate name cannot be read against the
/// session, so nothing is proven.
#[test]
fn no_working_directory_proves_no_ref_name() {
    let command = "git checkout -b fix/secret-scan-gate";
    assert!(ref_names(&model(command), None, false).is_empty());
}
