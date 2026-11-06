//! Tests for which shell options leave an inline `-c` script the whole command.

use super::tests::parse;

#[test]
fn inert_option_letters_keep_the_script_the_whole_command() {
    for command in [
        "bash -ec 'npm test'",
        "bash -e -c 'npm test'",
        "bash -eu -c 'npm test'",
        "bash -euxc 'npm test'",
        // `-c` takes the next word wherever it sits in the bundle.
        "bash -ce 'npm test'",
        "sh -x -c 'npm test'",
        // `-o` with a name that leaves the script's words as written.
        "bash -o pipefail -c 'npm test'",
        "bash -euo pipefail -c 'npm test'",
        "bash -eu -o pipefail -c 'npm test'",
        "bash -o errexit -o nounset -c 'npm test'",
        "sh -o noclobber -ec 'npm test'",
        // Startup files bash would skip anyway for a `-c` script.
        "bash --norc -c 'npm test'",
        "bash --noprofile --norc -euo pipefail -c 'npm test'",
        // Options that change how a glob matches, or how the shell reports
        // a failure, leave every program the words name as written.
        "bash -o noglob -c 'npm test'",
        "bash -f -c 'npm test'",
        "bash -O extglob -c 'npm test'",
        "bash -O globstar -O failglob -c 'npm test'",
        "bash -eO extglob -c 'npm test'",
        "bash +O extglob -c 'npm test'",
        "bash +o pipefail -c 'npm test'",
        "bash +e -c 'npm test'",
        "bash -ET -o errtrace -c 'npm test'",
        // A shell that does not know an option stops with an error before
        // the script runs, so the script is still the most the text runs.
        "dash --norc -c 'npm test'",
        "sh --noprofile -c 'npm test'",
        "ash --noprofile -c 'npm test'",
        "dash -o pipefail -c 'npm test'",
        "sh -euo pipefail -c 'npm test'",
        "sh -O extglob -c 'npm test'",
    ] {
        assert_eq!(
            super::inline_shell_script(command).as_deref(),
            Some("npm test"),
            "{command}"
        );
    }
}

#[test]
fn a_widened_option_keeps_every_floor_the_script_reaches() {
    // The options read here only change how a glob matches or a failure is
    // reported, so the destructive script is still the command modelled and
    // reaches the floor its own words reach.
    for command in [
        "bash -O extglob -c 'rm -rf ~'",
        "bash -o noglob -c 'rm -rf ~'",
        "dash --norc -c 'rm -rf ~'",
        "sh -euo pipefail -c 'rm -rf ~'",
    ] {
        let model = parse(command);
        assert_eq!(model.confidence, "exact", "{command}");
        assert!(!model.exact_raw_text, "{command}");
        assert_eq!(
            model.segments[0].executable.as_deref(),
            Some("rm"),
            "{command}"
        );
    }
}

#[test]
fn an_option_the_shell_reads_differently_keeps_the_wrapper_path() {
    for command in [
        // A login or interactive shell reads startup files first, so the
        // script is not the whole command.
        "bash -lc 'npm test'",
        "bash -l -c 'npm test'",
        "bash -ic 'npm test'",
        // zsh reads `~/.zshenv` whatever option it is given.
        "zsh -c 'npm test'",
        "zsh -ec 'npm test'",
        // The script arrives on stdin, or an option changes what a word
        // runs: `-a` exports every assignment to the programs after it,
        // `-k` turns a later `NAME=value` operand into the environment,
        // `expand_aliases`, `extdebug` and POSIX mode run something the
        // words never name, and `nullglob` lets the word after an empty glob become
        // the program.
        "bash -s -c 'npm test'",
        "bash -a -c 'npm test'",
        "bash -o allexport -c 'npm test'",
        "bash -k -c 'npm test'",
        "bash -o keyword -c 'npm test'",
        "bash -O expand_aliases -c 'npm test'",
        "bash -O nullglob -c 'npm test'",
        "bash -O extdebug -c 'npm test'",
        "bash -o posix -c 'npm test'",
        "bash --posix -c 'npm test'",
        "bash -o vi -c 'npm test'",
        // `-o` and `-O` need their name as the next word, `-c` in the same
        // bundle leaves which word is which to the shell, and a `+` bundle
        // never carries the script.
        "bash -o -c 'npm test'",
        "bash -O -c 'npm test'",
        "bash -oc pipefail 'npm test'",
        "bash -oe pipefail -c 'npm test'",
        "bash -cO extglob 'npm test'",
        "bash -Oe extglob -c 'npm test'",
        "bash +c 'npm test'",
        "bash +ec 'npm test'",
        "bash -O",
        // bash reads a long option only before the short ones, and these
        // read a startup file or change the shell.
        "bash -e --norc -c 'npm test'",
        "bash --login -c 'npm test'",
        "bash --rcfile ./rc -c 'npm test'",
        "bash --init-file ./rc -c 'npm test'",
        "bash --debugger -c 'npm test'",
        "bash -- -c 'npm test'",
        // No `-c` at all, and no script to model.
        "bash -e 'npm test'",
        "bash -ec",
        "bash -ec ''",
    ] {
        assert!(super::inline_shell_script(command).is_none(), "{command}");
    }
}

#[test]
fn a_refused_shell_offers_plain_dash_c_only_when_guard_reads_it() {
    for command in [
        "bash -lc 'ls'",
        "bash -l -c 'git status'",
        "bash --login -c 'ls'",
        "bash --posix -c 'ls'",
        "bash -O nullglob -c 'ls *.txt'",
        "bash -ic 'npm test'",
        "zsh -c 'git status'",
        "zsh -lc 'ls'",
    ] {
        assert!(super::refused_inline_shell(command), "{command}");
    }
    for command in [
        // Guard already reads these, so they are reviewed, not refused.
        "bash -c 'ls'",
        "sh -ec 'npm test'",
        // A plain `-c` would not read these either, so it is no recovery.
        "bash -lc 'echo $HOME'",
        "bash -lc 'ls' > out.txt",
        "bash -lc \"echo 'x'\"",
        "bash -lc ''",
        "fish -c 'ls'",
        "bash script.sh",
        "bash -lc 'ls' arg0",
    ] {
        assert!(!super::refused_inline_shell(command), "{command}");
    }
}
