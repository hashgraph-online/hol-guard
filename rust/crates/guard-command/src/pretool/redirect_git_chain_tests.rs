use super::*;
use crate::CommandModelRequestV1;

fn admitted(projected: &str, targets: &[&str]) -> bool {
    let model = crate::parse_command(&CommandModelRequestV1 {
        command: projected.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();
    let targets: Vec<String> = targets.iter().map(|value| (*value).to_owned()).collect();
    admits(&model, &targets)
}

#[test]
fn admits_prints_and_tree_keeping_git_steps_beside_relative_writes() {
    for projected in [
        "echo x && git add -A && git commit -m init",
        "printf 'draft' && git add notes.txt && git commit -m 'docs: add notes'",
        "echo x; git add -A; git commit -m update",
        "git switch -c feat/notes && echo x && git add notes.txt && git commit -m notes",
        "echo x && git status --short && git add -A && git commit -m init",
    ] {
        assert!(admitted(projected, &["notes.txt"]), "{projected}");
    }
    assert!(admitted(
        "echo x && git add -A && git commit -m init",
        &["docs/notes.md", "./CHANGELOG.md"]
    ));
}

#[test]
fn refuses_absolute_targets_and_steps_that_move_the_tree_or_publish() {
    for target in ["/tmp/notes.txt", "C:notes.txt", r"docs\notes.txt", ""] {
        assert!(
            !admitted("echo x && git add -A && git commit -m init", &[target]),
            "{target}"
        );
    }
    for projected in [
        "echo x && git add -A && git commit -m init && git push origin main",
        "echo x && git add -A && git -c core.hooksPath=hooks commit -m init",
        "echo x && git -C ../other add -A && git -C ../other commit -m init",
        "echo x && git --git-dir=../other/.git commit -m init",
        "cd sub && echo x && git add -A && git commit -m init",
        "echo x && git checkout main && git add -A && git commit -m init",
        "git checkout -b feat/a origin/main && echo x && git add -A",
        "echo x && git stash && git add -A && git commit -m init",
        "echo x && git restore notes.txt && git commit -am init",
        "ln -s ../outside notes.txt && git add -A && git commit -m init",
        "mkdir -p docs && echo x && git add -A && git commit -m init",
        "echo x && npm test && git commit -am init",
        "echo x && ls",
        "env echo x && git add -A && git commit -m init",
    ] {
        assert!(!admitted(projected, &["notes.txt"]), "{projected}");
    }
}

#[test]
fn includes_that_could_load_a_workspace_file_are_refused() {
    let home = Path::new("/home/tester");
    let cwd = Path::new("/home/tester/project");
    assert!(include_reaches("~/project/extra.inc", home, cwd));
    assert!(include_reaches("/home/tester/project/extra.inc", home, cwd));
    assert!(include_reaches("/home/tester/Project/extra.inc", home, cwd));
    assert!(include_reaches("project/extra.inc", home, cwd));
    assert!(include_reaches("../tester/project/extra.inc", home, cwd));
    assert!(include_reaches("~other/extra.inc", home, cwd));
    assert!(!include_reaches("~/.gitconfig-work", home, cwd));
    assert!(!include_reaches("/etc/gitconfig-extra", home, cwd));
}
