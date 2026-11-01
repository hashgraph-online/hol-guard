//! An `fd` names the program its `--exec` runs in the command text, the way a
//! `find -exec` does, so an ordinary walk keeps the approval a review offers.
use super::fd_exec::{fd_exec_programs, text_outside_fd_exec_arguments};
use super::named_fd_exec;
use super::tests::{controls, decision, github};
use std::collections::BTreeSet;

const FAILED: &str = "native_command_extension_evaluation_failed";

fn programs(text: &str) -> Option<Vec<String>> {
    fd_exec_programs(text).map(|programs| programs.into_iter().collect())
}

#[test]
fn a_walk_that_starts_nothing_reads_as_an_empty_set() {
    for text in [
        "fd -e ts",
        "fd -e ts | xargs wc -l",
        "fd -e ts -0 | xargs -0 wc -l",
        // `fd` here is the pattern another program searches for, or a word it
        // prints. Neither position starts the walk.
        "rg fd src",
        "echo fd -x rm",
        "git ls-files",
    ] {
        assert_eq!(programs(text), Some(Vec::new()), "{text}");
    }
}

#[test]
fn an_exec_that_names_its_program_reads_that_program() {
    for (text, expected) in [
        ("fd -e ts -x wc -l", vec!["wc"]),
        ("fd -e ts -X wc -l", vec!["wc"]),
        ("fd -e ts --exec cat", vec!["cat"]),
        ("fd -e ts --exec-batch wc -l", vec!["wc"]),
        ("fd . src -x /usr/bin/wc -l", vec!["wc"]),
        ("fd -e ts -x wc -l; fd -e rs -x rg TODO", vec!["rg", "wc"]),
        // A bundled exec still names its program in the next word.
        ("fd -e ts -HX wc -l", vec!["wc"]),
        // The shell strips the quotes before fd reads the option.
        ("fd -e ts \"-x\" echo sh", vec!["echo"]),
        // The second `-x` is echo's argument, not another walk.
        ("fd -e ts -x echo -x sh", vec!["echo"]),
        // `--` ends the options, so `-x` is the pattern to search for.
        ("fd -- -x src", vec![]),
        // An option's value is not read as an option.
        ("fd --exclude -x SKILL.md src", vec![]),
        ("fd --type f --exec wc -l", vec!["wc"]),
    ] {
        let expected: Vec<String> = expected.into_iter().map(str::to_string).collect();
        assert_eq!(programs(text), Some(expected), "{text}");
    }
}

#[test]
fn an_exec_that_names_no_program_stays_unbounded() {
    for text in [
        // The operand runs whatever it reads.
        "fd -e ts -x sh -c cat",
        "fd -e ts -x fd",
        // fd's own placeholder for the path it found, and an operand built
        // from an expansion or a glob: none of them is a program name.
        "fd -e ts -x {}",
        // A placeholder anywhere in the walk builds the child's arguments by
        // substitution, so the command a review would show is not the one
        // that runs.
        "fd -X rm {}",
        "fd -a SKILL.md ~/.codex/skills -d 1 -x sed -i '1,180p' {}",
        "fd -e ts -x wc -l {.}",
        "fd -e ts -x $TOOL",
        "fd -e ts -x ./bin/*",
        // No operand at all.
        "fd -e ts -x",
        // A batch script whose body nobody has read.
        "fd -e ts -x ./bin/report.cmd",
        // A launcher this reader does not read past starts the walk, so the
        // text that reaches `fd` is text nobody bound. The shell strips the
        // quotes before it looks the launcher up, so a quoted one launches
        // the walk just the same.
        "sudo fd -x rm",
        "cat list.txt | xargs fd -x rm",
        "\"nohup\" fd -x rm",
        // fd takes the program attached to the option as readily as in a word
        // of its own. This walk never isolates an attached one, so it refuses
        // the piece instead of reading a walk it has not bound.
        "fd -e sh -xbash",
        "fd -e sh -HXsh",
        "fd -e sh --exec=bash",
        "fd -e sh --exec-batch=bash",
    ] {
        assert_eq!(programs(text), None, "{text}");
    }
}

#[test]
fn the_words_after_the_program_an_exec_names_are_its_arguments() {
    // `fd -e ts -x echo sh` prints the word `sh`; reading it as a command
    // position refused ordinary work over a literal that starts nothing.
    assert_eq!(
        text_outside_fd_exec_arguments("fd -e ts -x echo sh"),
        "fd -e ts -x echo"
    );
    assert_eq!(
        text_outside_fd_exec_arguments("fd -e ts -x wc -l; git status"),
        "fd -e ts -x wc\ngit status"
    );
    // The words after the program are its arguments even when one of them
    // spells an exec option.
    assert_eq!(
        text_outside_fd_exec_arguments("fd -e ts -x echo -x sh"),
        "fd -e ts -x echo"
    );
}

#[test]
fn a_named_walk_is_reviewable_structure_and_an_unnamed_one_is_not() {
    for text in ["fd -e ts -x wc -l", "fd -e ts --exec-batch wc -l"] {
        assert!(named_fd_exec(text), "{text}");
    }
    for text in [
        // Nothing to name: this walk starts no program of fd's own, and the
        // pipeline's own reader bounds whatever follows it.
        "fd -e ts",
        "fd -e ts | xargs wc -l",
        // Unbounded, and a redirect the structure reader judges elsewhere.
        "fd -e ts -x sh -c cat",
        "fd -e ts -x wc -l > out.txt",
    ] {
        assert!(!named_fd_exec(text), "{text}");
    }
}

#[test]
fn an_unmodeled_walk_reaches_a_review_a_user_can_approve() {
    // Naming `fd` reached an evaluation failure, which blocks outright with no
    // approval row, while the same walk spelled `find` was reviewed.
    let controls = controls(github("enabled", None), false);
    for command in [
        "fd -e ts | xargs wc -l",
        "fd -e ts -0 | xargs -0 wc -l",
        "fd -e ts -x wc -l",
        "fd -e ts -X wc -l",
        "fd -e ts --exec wc -l",
        "fd -e ts --exec-batch wc -l",
        "fd . src -x wc -l",
        "rg fd src | xargs wc -l",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_ne!(action, "block", "{command}: {code}");
    }
}

#[test]
fn a_walk_that_names_no_program_keeps_its_evaluation_failure() {
    let controls = controls(github("enabled", None), false);
    for command in ["fd -e ts -x sh -c 'cat {}'", "fd -e ts -x $TOOL"] {
        let (action, code) = decision(&controls, command);
        assert_eq!(code, FAILED, "{command}");
        assert_eq!(action, "block", "{command}");
    }
}

#[test]
fn an_exec_that_removes_files_still_reaches_a_review() {
    // `rm`'s owner supplies the floor the walk itself no longer refuses, the
    // way `find . -exec rm -f {} \;` and `cat list.txt | xargs rm -f` already
    // behave.
    let controls = controls(github("enabled", None), false);
    for command in ["fd -e tmp -x rm -f", "fd -e tmp | xargs rm -f"] {
        let (action, code) = decision(&controls, command);
        assert_ne!(action, "allow", "{command}: {code}");
    }
}

/// The set this reader hands the caller is the same shape `find -exec` hands
/// it, so the owners of a walk's program are read once for both spellings.
#[test]
fn the_read_programs_are_basenames() {
    let expected: BTreeSet<String> = ["wc".to_string()].into_iter().collect();
    assert_eq!(
        fd_exec_programs("fd . src -x /usr/bin/wc.exe -l"),
        Some(expected)
    );
}

/// A brace is a placeholder only where there is a child to build arguments
/// for. A search runs nothing and substitutes nothing, so a brace in its own
/// regex or glob is ordinary text.
#[test]
fn a_brace_in_a_walk_that_runs_nothing_is_ordinary_text() {
    for text in [
        "fd '[0-9]{4}' src",
        "fd -g '*.{ts,js}'",
        "fd '[0-9]{4}' src | xargs wc -l",
    ] {
        assert_eq!(programs(text), Some(Vec::new()), "{text}");
    }
}

/// `\;` ends one body and starts whatever fd reads after it. The split this
/// reader walks over cuts the piece at that terminator, so a second walk lands
/// where nothing reads it as fd's: naming only the first program would call
/// `fd -x echo \; -x gh pr merge` bounded while `gh` runs unseen.
#[test]
fn a_body_that_ends_at_an_escaped_terminator_stays_unbounded() {
    for text in [
        r"fd -e ts -x echo \; -x gh pr merge",
        r"fd -e ts -x wc -l \;",
    ] {
        assert_eq!(programs(text), None, "{text}");
    }
}

/// The shell joins adjacent literals and drops their quotes before fd reads
/// the word, so an option reaches it in a spelling this walk does not find.
/// Missing the `-x` in `''-x` would call the walk bounded while fd runs `rm`.
#[test]
fn an_option_the_shell_joins_leaves_the_walk_unbounded() {
    for text in [
        "fd -e ts ''-x rm",
        "fd -e ts \"\"-x rm",
        "fd -e ts -'x' rm",
        r"fd -e ts \-x rm",
    ] {
        assert_eq!(programs(text), None, "{text}");
    }
    // A quote inside an option's value is fd's own text, not another option.
    assert_eq!(programs("fd --exclude='*.ts' -e ts"), Some(Vec::new()));
}
