use super::{in_git_command, stand_in, standalone, COMMIT_VALUE};
use crate::shell_structure::extract_command_substitution_spans;

#[test]
fn hash_lookups_print_a_commit() {
    for body in [
        "git rev-parse HEAD",
        "git rev-parse HEAD~1",
        "git rev-parse @^2",
        "git rev-parse --short HEAD",
        "git rev-parse --short=8 origin/main",
        "git rev-parse --verify -q feature/x",
        "git log -1 --format=%h -- README.md",
        "git log -1 --pretty=format:%H main -- docs/PRD.md",
        "git log -n1 --format=%h --first-parent",
        "git merge-base HEAD origin/main",
    ] {
        assert_eq!(stand_in(body), Some(COMMIT_VALUE), "{body}");
    }
}

#[test]
fn lookups_that_can_print_other_text_stay_opaque() {
    for body in [
        // A bare rev-parse echoes an operand it cannot resolve.
        "git rev-parse .env",
        "git rev-parse origin/main",
        "git rev-parse --abbrev-ref HEAD",
        "git rev-parse --show-toplevel",
        "git rev-parse --output=x HEAD",
        "git rev-parse --verify HEAD main",
        // Without -1 a log prints many hashes; other formats print text.
        "git log --format=%h",
        "git log -1 --format=%s",
        "git log -1 --format=%h%n%s",
        "git log -1 --oneline",
        "git log -1 --format=%h --output=x",
        "git log -1 --format=%h -- -x",
        "git log -1 --format=%h HEAD..main",
        "git merge-base --all HEAD main",
        "git merge-base HEAD",
        "git -C .. rev-parse HEAD",
        "git rev-parse HEAD; id",
        "git show HEAD",
    ] {
        assert_eq!(stand_in(body), None, "{body}");
    }
}

fn git_command(command: &str) -> bool {
    let chars: Vec<char> = command.chars().collect();
    let spans = extract_command_substitution_spans(command);
    let last = spans.last().expect("a substitution");
    in_git_command(&chars, &spans, last.start)
}

#[test]
fn the_value_is_read_only_inside_a_git_command() {
    assert!(git_command("git show --stat $(git rev-parse HEAD)"));
    assert!(git_command(
        "cd src && git diff $(git merge-base HEAD main) --stat"
    ));
    assert!(git_command(
        "git diff $(git merge-base HEAD main) $(git rev-parse HEAD)"
    ));
    assert!(!git_command("grep -r TODO $(git rev-parse HEAD)"));
    assert!(!git_command("cat $(git rev-parse HEAD)"));
    assert!(!git_command("echo 'git x;' $(git rev-parse HEAD)"));
    assert!(!git_command("echo \"; git show\" $(git rev-parse HEAD)"));
    assert!(!git_command("FOO=1 git show $(git rev-parse HEAD)"));
    assert!(git_command(
        "git diff \"$(git merge-base HEAD main)\" --stat"
    ));
}

fn own_word(command: &str) -> bool {
    let chars: Vec<char> = command.chars().collect();
    let spans = extract_command_substitution_spans(command);
    standalone(&chars, spans.last().expect("a substitution"))
}

#[test]
fn the_value_stands_in_only_for_a_whole_word_or_a_range_end() {
    for command in [
        "git show $(git rev-parse HEAD)",
        "git diff $(git merge-base HEAD main) --stat",
        "git log $(git merge-base HEAD main)..HEAD",
        "git log main..$(git rev-parse HEAD)",
        "git diff \"$(git merge-base HEAD main)\" --stat",
        "(git show $(git rev-parse HEAD))",
        "git show \"$(git rev-parse HEAD)\"; git status",
        "(git show \"$(git rev-parse HEAD)\")",
        "git show $(git rev-parse HEAD); git status",
    ] {
        assert!(own_word(command), "{command}");
    }
    for command in [
        // An empty value would turn glued text into an option or a name.
        "git diff $(git rev-parse HEAD)--output=../out.txt",
        "git show HEAD:.$(git rev-parse HEAD)env",
        "git show x$(git rev-parse HEAD)",
        "git show \"HEAD:$(git rev-parse HEAD)\"",
        "git show \"x $(git rev-parse HEAD) y\"",
        "git show \"$(git rev-parse HEAD)\"env",
        "git log \"$(git rev-parse HEAD)\"..HEAD",
    ] {
        assert!(!own_word(command), "{command}");
    }
}

#[test]
fn the_command_with_an_empty_lookup_is_judged_too() {
    let command = "git show --stat $(git rev-parse HEAD)";
    let projected = super::super::project(command, |_| true);
    assert_eq!(projected, Some(format!("git show --stat {COMMIT_VALUE}")));
    // Refusing what runs when the lookup prints nothing refuses the stand-in.
    assert_eq!(
        super::super::project(command, |text| text != "git show --stat "),
        None
    );
}
