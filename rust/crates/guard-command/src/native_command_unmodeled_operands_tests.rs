//! An interpreter's name in an operand position runs nothing, so the command
//! that holds it keeps an approval to give.
use super::operands::text_in_command_positions;
use super::tests::{controls, decision, github};

const FAILED: &str = "native_command_extension_evaluation_failed";

/// An unmodeled program reaches this reader, and the name it is handed decided
/// whether the user got an approval card or an outright refusal. `foo bar`
/// reviewed; `foo env` blocked with nothing to approve, over a word `foo` runs
/// no more than it runs `bar`.
#[test]
fn an_interpreter_named_in_an_operand_keeps_its_approval() {
    let controls = controls(github("enabled", None), false);
    let plain = decision(&controls, "foo bar | xargs wc -l");
    assert_ne!(plain.1, FAILED, "the plain operand is the control");
    for command in [
        "foo env | xargs wc -l",
        "foo node | xargs cat",
        "foo watch | xargs head -n 1",
        "foo fd | xargs wc -c",
        "foo source | xargs wc -w",
        "foo parallel | xargs basename",
        "foo deno | xargs wc -l",
        "foo expect | xargs wc -l",
        // A path spelling is still an operand.
        "foo ./node | xargs wc -l",
    ] {
        assert_eq!(decision(&controls, command), plain, "{command}");
    }
}

/// Only a bare literal is read as an operand. A spelling that can still expand
/// into a program, and a launcher that runs the words it is handed, keep the
/// evaluation failure this reader is not entitled to lift.
#[test]
fn a_word_that_may_still_name_a_program_keeps_its_evaluation_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "foo node* | xargs wc -l",
        "foo FOO=node | xargs cat",
        "foo 'node' | xargs head -n 1",
        "foo $NODE | xargs wc -l",
        "foo --exec=node | xargs wc -w",
        // The word after an option is the value that option names, and an
        // option this reader does not know may name a program.
        "foo -n node | xargs wc -l",
        "foo --pre node PATTERN | xargs wc -l",
        // The piece's own program runs what it is given, so none of its words
        // are operands.
        "sudo foo node | xargs wc -c",
        "timeout 5 foo node | xargs wc -l",
        "foo | xargs env rm",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

#[test]
fn only_a_bare_operand_leaves_the_command_positions() {
    for (command, kept) in [
        ("rg env src", "rg"),
        // The word after an option is the value that option names.
        ("rg -n env src", "rg -n env"),
        ("foo --pre node PATTERN README.md", "foo --pre node"),
        ("foo ./node", "foo"),
        // A piece whose own program runs what it is handed keeps every word.
        ("sh -c node", "sh -c node"),
        ("xargs rm", "xargs rm"),
        // A privilege wrapper and a launcher run their first operand too, and
        // neither stands among the interpreters.
        ("pkexec bash -c wc", "pkexec bash -c wc"),
        ("run0 node app.js", "run0 node app.js"),
        ("coproc node app.js", "coproc node app.js"),
        (
            "runuser -u build node app.js",
            "runuser -u build node app.js",
        ),
        ("rg $NODE src", "rg $NODE"),
        ("rg FOO=node src", "rg FOO=node"),
        ("rg 'node' src", "rg 'node'"),
        // The option word is what tells the scan a nested executor is there at
        // all; the body's own words are operands the `-exec` reader bounds.
        (r"find src -exec sh -c cat", "find -exec sh -c cat"),
        // `xargs` is the program `-exec` runs; dropping it would hide the
        // unbounded `xargs` the piece is refused for. Its own operand follows
        // no option, so it leaves with the other bare words; `wc` names no
        // owner, and the refusal rests on the `xargs` that stays.
        (r"find . -exec xargs wc", "find -exec xargs"),
    ] {
        assert_eq!(text_in_command_positions(command), kept, "{command}");
    }
}
