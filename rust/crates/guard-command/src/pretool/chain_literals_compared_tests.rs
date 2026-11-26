use super::super::super::project;
use super::super::DISPLAY_VALUE;
use std::cell::RefCell;

fn projected(command: &str) -> Option<String> {
    project(command, |_| true)
}

#[test]
fn a_value_compared_as_a_string_takes_the_display_stand_in() {
    let v = DISPLAY_VALUE;
    for (command, expected) in [
        (
            "[ -n \"$(git status --porcelain)\" ] && echo dirty || echo clean",
            format!("[ -n \"{v}\" ] && echo dirty || echo clean"),
        ),
        (
            "[ -z \"$(git status --porcelain)\" ] && echo clean",
            format!("[ -z \"{v}\" ] && echo clean"),
        ),
        (
            "if [ -n \"$(git status --porcelain)\" ]; then echo dirty; fi",
            format!("if [ -n \"{v}\" ]; then echo dirty; fi"),
        ),
        (
            "[ \"$(git rev-parse HEAD)\" = \"$(git rev-parse HEAD~1)\" ] && echo same || echo differ",
            format!("[ \"{v}\" = \"{v}\" ] && echo same || echo differ"),
        ),
        (
            "test \"$(git rev-parse HEAD)\" = \"$(git rev-parse HEAD~1)\" && echo same",
            format!("test \"{v}\" = \"{v}\" && echo same"),
        ),
        (
            "[ \"$(git branch --show-current)\" = main ] && echo on-main",
            format!("[ \"{v}\" = main ] && echo on-main"),
        ),
        (
            "[ main != \"$(git branch --show-current)\" ] || echo on-main",
            format!("[ main != \"{v}\" ] || echo on-main"),
        ),
        (
            "git fetch -q; [ \"$(git rev-parse HEAD)\" == \"$(git rev-parse '@{u}')\" ] && echo current",
            format!("git fetch -q; [ \"{v}\" == \"{v}\" ] && echo current"),
        ),
        (
            "[ \"$(git status --porcelain)\" ] || echo clean",
            format!("[ \"{v}\" ] || echo clean"),
        ),
        (
            "! [ -z \"$(git status --short)\" ] && echo dirty",
            format!("! [ -z \"{v}\" ] && echo dirty"),
        ),
    ] {
        assert_eq!(projected(command), Some(expected), "{command}");
    }
}

#[test]
fn a_test_this_slot_does_not_read_keeps_the_substitution_opaque() {
    for command in [
        // Split and globbed.
        "[ -n $(git status --porcelain) ] && echo dirty",
        "[ \"x$(git status --porcelain)\" = x ] && echo clean",
        // Numeric operands are arithmetic in zsh; file tests read a path.
        "[ \"$(git rev-list --count HEAD)\" -gt 1 ] && echo many",
        "[ \"$(git rev-list --count HEAD)\" -eq 1 ] && echo one",
        "[ -f \"$(git rev-parse --show-toplevel)\" ] && echo file",
        "test -d \"$(git rev-parse --show-toplevel)\" && echo dir",
        "[ -v \"$(git branch --show-current)\" ] && echo set",
        // `[[` matches patterns and evaluates arithmetic.
        "[[ \"$(git branch --show-current)\" == main ]] && echo on-main",
        // More words than a single comparison.
        "[ \"$(git branch --show-current)\" = main -o x = y ] && echo on-main",
        "[ \"$(git branch --show-current)\" = main ] extra && echo x",
        "[ \"$(git branch --show-current)\" = main && echo x",
        // An operand the shell expands.
        "[ \"$(git branch --show-current)\" = $BRANCH ] && echo x",
        "[ \"$(git branch --show-current)\" = ~ ] && echo x",
        "[ \"$(git branch --show-current)\" = ma* ] && echo x",
        "[ \"$(git branch --show-current)\" = =main ] && echo x",
        // The value lands somewhere other than the test.
        "[ -n \"$(git status --porcelain)\" ] > out.txt",
        "[ -n \"$(git status --porcelain)\" ] < in.txt",
        "( [ -n \"$(git status --porcelain)\" ] ) && echo dirty",
        "{ [ -n \"$(git status --porcelain)\" ]; } && echo dirty",
        "cat \"$(git status --porcelain)\"",
        // Something ahead steers what the inner command reads.
        "cd /tmp && [ -n \"$(git status --porcelain)\" ] && echo dirty",
        "GIT_DIR=/tmp/other; [ -n \"$(git status --porcelain)\" ] && echo dirty",
        "alias git=rm; [ -n \"$(git status --porcelain)\" ] && echo dirty",
        // The test runs again in a loop.
        "while [ -n \"$(git status --porcelain)\" ]; do sleep 1; done",
        // Quoting and comments this scan does not read.
        "[ -n \"$(git status --porcelain)\" ] # dirty?",
        "[ -n \"$(git status --porcelain)\" ] && echo $'a'",
        // A body that expands or nests.
        "[ -n \"$(cat $HOME/.ssh/id_rsa)\" ] && echo key",
        "[ -n \"$(git log $(git rev-parse HEAD))\" ] && echo x",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}

#[test]
fn each_compared_command_is_judged_on_its_own() {
    let seen = RefCell::new(Vec::new());
    let projection = project(
        "[ \"$(git rev-parse HEAD)\" = \"$(git rev-parse origin/main)\" ] && echo current",
        |body| {
            seen.borrow_mut().push(body.to_owned());
            true
        },
    );
    assert!(projection.is_some());
    assert_eq!(
        seen.into_inner(),
        vec!["git rev-parse HEAD", "git rev-parse origin/main"]
    );
    // One refused read refuses the whole chain.
    assert_eq!(
        project("[ -n \"$(cat ~/.ssh/id_rsa)\" ] && echo key", |body| !body
            .contains(".ssh")),
        None
    );
}
