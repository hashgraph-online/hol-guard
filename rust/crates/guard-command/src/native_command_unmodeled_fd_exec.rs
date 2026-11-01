//! Reading the program an `fd --exec` runs out of the command text.
use super::xargs::{command_index, plain_program};
use super::{command_basename, INTERPRETERS};
use std::collections::BTreeSet;

/// fd's options that run a program named by the words after them.
pub(super) const FD_EXEC_ACTIONS: &[&str] = &["-x", "-X", "--exec", "--exec-batch"];

/// The programs every `fd` in the text runs, by basename, or `None` when one
/// of them is not named here.
///
/// `fd` is find's walk with another spelling, and `fd -e ts -x wc -l` hands
/// the paths it found to the `wc` the text already shows. An empty set is the
/// ordinary answer: `fd -e ts` and `fd -e ts | xargs wc -l` start no program
/// of fd's own, and the pipeline's own reader bounds the `xargs`. Before this
/// read, naming `fd` anywhere in an unmodeled command reached an evaluation
/// failure and blocked outright, with no approval left to give it, because
/// `fd` stands among the interpreters for the `-x` it may carry. An `-x`
/// whose operand is itself an interpreter (`fd -x sh -c ...`), one built from
/// an expansion or a glob, and one with no operand at all run whatever they
/// read, so those stay unbounded, as does an `fd` a launcher this reader does
/// not read past would start: `sudo fd -x rm` and `xargs fd -x rm` keep their
/// evaluation failure. An `fd` that is another program's operand runs nothing,
/// so `rg fd src` and `echo fd -x rm` are the ordinary empty answer.
pub(super) fn fd_exec_programs(shell: &str) -> Option<BTreeSet<String>> {
    let mut programs = BTreeSet::new();
    for piece in shell.split(['\n', ';', '&', '|', '(', ')', '`']) {
        let words: Vec<&str> = piece.split_whitespace().collect();
        let names_fd = words.iter().any(|word| command_basename(word) == "fd");
        let Some(command) = command_index(&words) else {
            // A piece with no command position starts nothing of its own, so
            // an `fd` among its words belongs to the piece before it. One
            // this reader cannot place stays unbound.
            if names_fd {
                return None;
            }
            continue;
        };
        if command_basename(words[command]) != "fd" {
            // The piece runs something else, and an `fd` among its operands
            // is that program's argument: `rg fd src` searches for the text.
            // A launcher is not read past, so `sudo fd -x rm` and
            // `xargs fd -x rm` stay unbounded under their own names.
            if names_fd && runs_something_else(words[command]) {
                return None;
            }
            continue;
        }
        // The piece's own program. A further `fd` among its operands is a
        // pattern or a path, not another walk: `fd fd src` searches for the
        // name, and an `--exec` operand spelling `fd` is refused below with
        // every other interpreter.
        let actions: Vec<usize> = words
            .iter()
            .enumerate()
            .filter(|(_, word)| FD_EXEC_ACTIONS.contains(*word))
            .map(|(index, _)| index)
            .collect();
        for action in actions {
            let operand = *words.get(action + 1)?;
            // `{}`, `{.}`, `{/}`, `{//}` and `{/.}` are fd's own placeholders
            // for the path it found, and `\;` ends a body: neither names a
            // program.
            if operand.contains(['{', '}']) || matches!(operand, "+" | "\\") {
                return None;
            }
            // A trailing escape may join the next whitespace-separated word;
            // that is not a complete executable word this reader can bind.
            if !plain_program(operand) || operand.ends_with('\\') {
                return None;
            }
            // Only executable positions run programs, and a prefix launcher
            // stays unbounded: naming `nohup` does not bind the command it
            // launches.
            if runs_something_else(operand) {
                return None;
            }
            let program = command_basename(&operand.replace('\\', ""));
            // A `.cmd` is a batch script, and its body is not read here:
            // naming it after its stem would claim `./bin/report.cmd` runs
            // the program `report` and hand the review that program's owners
            // for text nobody has seen.
            if program.ends_with(".cmd") || command_basename(operand).ends_with(".cmd") {
                return None;
            }
            programs.insert(program);
        }
    }
    Some(programs)
}

/// Whether the word runs something other than itself, read the way the shell
/// reads it.
///
/// Check both path spelling and shell-unescaped spelling: `s\h` runs `sh`,
/// while `\ls` still names `ls`. Callers pass executable words only.
fn runs_something_else(word: &str) -> bool {
    let unescaped = word.replace('\\', "");
    [command_basename(word), command_basename(&unescaped)]
        .iter()
        .any(|name| {
            INTERPRETERS.contains(&name.as_str())
                || matches!(name.as_str(), "nohup" | "command" | "builtin" | "time")
        })
}

/// The text with each `fd --exec` body's arguments removed, keeping the
/// option and the program it names.
///
/// `fd` starts no shell: it runs the program the option names and hands it
/// the paths it found, so the remaining body words are that program's argv.
/// `fd -e ts -x echo sh` prints the word `sh`, and reading it as a command
/// position refused ordinary work over a literal nothing runs. Callers use
/// this only once `fd_exec_programs` has proven every option names a program
/// that is not itself a launcher.
pub(super) fn text_outside_fd_exec_arguments(shell: &str) -> String {
    let mut pieces: Vec<String> = Vec::new();
    for piece in shell.split(['\n', ';', '&', '|', '(', ')', '`']) {
        let words: Vec<&str> = piece.split_whitespace().collect();
        let mut kept: Vec<&str> = Vec::new();
        let mut index = 0;
        while index < words.len() {
            let word = words[index];
            kept.push(word);
            index += 1;
            if !FD_EXEC_ACTIONS.contains(&word) {
                continue;
            }
            // The operand names the program, and it stays: it is what the
            // option runs.
            if index < words.len() {
                kept.push(words[index]);
                index += 1;
            }
            // fd ends a body at the end of the command or at an escaped `;`,
            // and the split above already ended the piece at an unquoted one.
            while index < words.len() && words[index] != "\\" {
                index += 1;
            }
            // The terminator itself names nothing.
            index += 1;
        }
        pieces.push(kept.join(" "));
    }
    pieces.join("\n")
}
