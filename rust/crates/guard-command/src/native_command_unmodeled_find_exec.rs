//! Reading the program a `find -exec` runs out of the command text.
use super::xargs::{command_index, plain_program};
use super::{command_basename, INTERPRETERS};
use std::collections::BTreeSet;

/// find's actions that run a program named by the words after them.
pub(super) const EXEC_ACTIONS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// The programs every `-exec` action in the text names, by basename, or
/// `None` when one of them names none.
///
/// `find` hands the paths it found to the program the text already shows, the
/// way standard input hands `xargs` its operands, and those paths come from
/// the roots this same text names. So `find src -type f -exec basename {} \;`
/// runs the `basename` the text shows and owns what `basename` owns. An
/// `-exec` whose operand is itself an interpreter (`find . -exec sh -c ...`),
/// one built from an expansion or a glob, and one with no operand at all run
/// whatever they read, so those stay unbounded. An `-exec` that belongs to
/// something other than a `find` this text names as its own command, as in
/// `echo -exec rm`, is not read either.
pub(super) fn find_exec_programs(shell: &str) -> Option<BTreeSet<String>> {
    let mut programs = BTreeSet::new();
    let mut found = false;
    // find ends an `-exec` body at an unquoted `;`, so splitting on it leaves
    // the action and the program it names together in the same piece.
    for piece in shell.split(['\n', ';', '&', '|', '(', ')', '`']) {
        let words: Vec<&str> = piece.split_whitespace().collect();
        let actions: Vec<usize> = words
            .iter()
            .enumerate()
            .filter(|(_, word)| EXEC_ACTIONS.contains(*word))
            .map(|(index, _)| index)
            .collect();
        if actions.is_empty() {
            // A piece that runs no `-exec` still runs. `find src -exec
            // basename x \; ; sh -c '...'` names `basename` for the find and
            // runs an unbounded shell straight after it, so reading the find
            // alone would bound the half of the text that was never the
            // uncertainty.
            if command_index(&words).is_some_and(|index| runs_something_else(words[index])) {
                return None;
            }
            continue;
        }
        found = true;
        // A wrapper, an option or a redirect `command_index` does not read
        // past could leave a `find` unrecognized while another piece's one
        // made the text look bounded, so an unrecognized piece stays unread.
        if command_index(&words).map(|index| command_basename(words[index]))
            != Some("find".to_owned())
        {
            return None;
        }
        for action in actions {
            let operand = *words.get(action + 1)?;
            // `{}` is find's own placeholder for the path it found, and `+`
            // and `;` end the body: neither names a program.
            if operand.contains(['{', '}']) || matches!(operand, "+" | "\\") {
                return None;
            }
            // A trailing escape may join the next whitespace-separated word;
            // that is not a complete executable word this reader can bind.
            if !plain_program(operand) || operand.ends_with('\\') {
                return None;
            }
            // Only executable positions run programs. `echo sh` and a grep
            // pattern containing backslashes are ordinary arguments. Prefix
            // launchers remain unbounded here: naming `nohup` does not bind
            // the command it launches, including an absolute-path launcher.
            if runs_something_else(operand) {
                return None;
            }
            let program = command_basename(&operand.replace('\\', ""));
            // A `.exe` suffix names the same program `command_basename`
            // already strips it from. A `.cmd` is a batch script, and its
            // body is not read here: naming it after its stem would claim
            // `./bin/report.cmd` runs the program `report` and hand the
            // review that program's owners for text nobody has seen.
            if program.ends_with(".cmd") || command_basename(operand).ends_with(".cmd") {
                return None;
            }
            programs.insert(program);
        }
    }
    found.then_some(programs)
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
