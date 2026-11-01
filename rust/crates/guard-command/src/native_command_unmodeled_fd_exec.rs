//! Reading the program an `fd --exec` runs out of the command text.
use super::xargs::{command_index, plain_program};
use super::{command_basename, INTERPRETERS};
use std::collections::BTreeSet;

/// fd's long options that take their value as the next word.
///
/// The list is the one [`crate::parser_executables::fd_arguments_execute_command`]
/// walks with, because the two readers have to agree on where an option's
/// value ends: a word this walk skips as a value while that one reads it as
/// `-x` would bound a walk the parser still calls a nested command executor.
const LONG_VALUE_OPTIONS: &[&str] = &[
    "--base-directory",
    "--changed-after",
    "--changed-before",
    "--changed-within",
    "--color",
    "--exact-depth",
    "--exclude",
    "--extension",
    "--format",
    "--ignore-file",
    "--max-depth",
    "--max-results",
    "--min-depth",
    "--owner",
    "--path-separator",
    "--search-path",
    "--size",
    "--threads",
    "--type",
];

/// fd's short options that take their value as the next word when the letter
/// ends the cluster, and as the rest of the cluster when it does not.
const VALUE_LETTERS: &[char] = &['c', 'd', 'E', 'e', 'j', 'o', 'S', 't'];

/// One `--exec` body: the word that names the program, and the end of the
/// argument run fd hands that program.
struct FdExecSite {
    program: usize,
    body_end: usize,
}

/// The word with one layer of matching shell quotes removed.
///
/// The shell strips them before fd sees the word, so `fd "-x" echo` runs
/// `echo` and `"nohup" fd -x rm` launches the walk through `nohup`. Reading
/// the raw token missed both.
fn unquote(word: &str) -> &str {
    let mut characters = word.chars();
    match (characters.next(), characters.next_back()) {
        (Some(first), Some(last)) if first == last && matches!(first, '\'' | '"') => {
            characters.as_str()
        }
        _ => word,
    }
}

/// Whether the word may carry an option this walk has not read.
///
/// The shell joins adjacent literals and drops their quotes before fd sees the
/// word, so `''-x`, `-'x'` and `\-x` all reach fd as `-x`. Reading the raw
/// token finds no option in any of them, and a walk that misses an `--exec`
/// would be called bounded while fd runs whatever that option names. A quote
/// inside an option's value is fd's to read, not an option of its own, so
/// `--exclude='*.ts'` stays readable.
fn hides_an_option(word: &str) -> bool {
    if word.starts_with('-') {
        let name = word.split('=').next().unwrap_or(word);
        return name.contains(['\'', '"', '\\']);
    }
    word.chars()
        .find(|character| !matches!(character, '\'' | '"' | '\\'))
        .is_some_and(|character| character == '-')
}

/// Every `--exec` body one `fd` piece runs, or `None` when a word leaves the
/// walk unreadable.
///
/// fd takes its options the way clap reads them, so an exec can be spelled
/// `-x`, `-X`, `--exec`, `--exec-batch`, bundled into a cluster (`-HX sh`),
/// or carrying its program attached to the option (`-xbash`, `--exec=rm`).
/// The attached spellings keep the program out of a word of its own, so this
/// walk refuses them rather than naming a program it has not isolated, and
/// the piece stays unbounded. An option whose value is a separate word is
/// stepped over, so `fd --exclude -x SKILL.md` names no exec at all, and the
/// words after a program are its arguments, so the second `-x` in
/// `fd -x echo -x sh` is echo's argument rather than another walk.
fn fd_exec_sites(words: &[&str], start: usize) -> Option<Vec<FdExecSite>> {
    let mut sites: Vec<FdExecSite> = Vec::new();
    let mut index = start;
    while index < words.len() {
        let word = unquote(words[index]);
        index += 1;
        if hides_an_option(word) {
            // An option this walk cannot read may be the `-x` that makes the
            // walk run something, so the piece stays unbounded.
            return None;
        }
        if word == "--" {
            // Every remaining word is a pattern or a path: `fd -- -x src`
            // searches for the text `-x`.
            break;
        }
        if word == "--exec" || word == "--exec-batch" {
            let site = exec_site(words, index)?;
            index = (site.body_end + 1).min(words.len());
            sites.push(site);
            continue;
        }
        if word.starts_with("--exec=") || word.starts_with("--exec-batch=") {
            // The program is attached to the option, so it never stands in a
            // word of its own for this reader to bind.
            return None;
        }
        if word.starts_with("--") {
            // A long option's value is attached by `=` or stands in the next
            // word. An option named nowhere here takes no value, which is the
            // reading the parser's own fd walk already uses.
            if !word.contains('=') && LONG_VALUE_OPTIONS.contains(&word) {
                index += 1;
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-').filter(|rest| !rest.is_empty()) else {
            // A positional: the pattern, or a path to walk.
            continue;
        };
        for (offset, letter) in cluster.char_indices() {
            let letter_ends_cluster = offset + letter.len_utf8() == cluster.len();
            if matches!(letter, 'x' | 'X') {
                if !letter_ends_cluster {
                    // `-xbash` carries the program inside the option word.
                    return None;
                }
                let site = exec_site(words, index)?;
                index = (site.body_end + 1).min(words.len());
                sites.push(site);
                break;
            }
            if VALUE_LETTERS.contains(&letter) {
                if letter_ends_cluster {
                    index += 1;
                }
                // Anything further in the cluster is this option's value.
                break;
            }
        }
    }
    Some(sites)
}

/// The body that starts at `program`, ending where fd ends one: at an escaped
/// `;` or at the end of the command.
///
/// The caller split the text at every unquoted `;` already, so a terminator
/// reaches this walk as a lone backslash.
fn exec_site(words: &[&str], program: usize) -> Option<FdExecSite> {
    if program >= words.len() {
        return None;
    }
    let mut body_end = program + 1;
    while body_end < words.len() && unquote(words[body_end]) != "\\" {
        body_end += 1;
    }
    Some(FdExecSite { program, body_end })
}

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
        let names_fd = words
            .iter()
            .any(|word| command_basename(unquote(word)) == "fd");
        let Some(command) = command_index(&words) else {
            // A piece with no command position starts nothing of its own, so
            // an `fd` among its words belongs to the piece before it. One
            // this reader cannot place stays unbound.
            if names_fd {
                return None;
            }
            continue;
        };
        if command_basename(unquote(words[command])) != "fd" {
            // The piece runs something else, and an `fd` among its operands
            // is that program's argument: `rg fd src` searches for the text.
            // A launcher is not read past, so `sudo fd -x rm` and
            // `xargs fd -x rm` stay unbounded under their own names.
            if names_fd && runs_something_else(unquote(words[command])) {
                return None;
            }
            continue;
        }
        // The piece's own program. A further `fd` among its operands is a
        // pattern or a path, not another walk: `fd fd src` searches for the
        // name, and an `--exec` operand spelling `fd` is refused below with
        // every other interpreter.
        //
        // A placeholder anywhere in a walk that execs keeps it unbounded, the
        // rule `read_only_fanout_fd` already reads the same shape by: `{}`, `{/}`,
        // `{//}`, `{.}` and `{/.}` make fd build the child's arguments by
        // substitution instead of appending the path it found, so the command
        // a review would show is not the command that runs. `fd -X rm {}` and
        // `fd -a SKILL.md ~/.codex/skills -d 1 -x sed -i '1,180p' {}` keep
        // their evaluation failure under this reader. A walk that runs nothing
        // substitutes nothing, so a brace in its pattern is ordinary text:
        // `fd '[0-9]{4}' src` and `fd -g '*.{ts,js}'` search and stop.
        let sites = fd_exec_sites(&words, command + 1)?;
        if !sites.is_empty()
            && words[command + 1..]
                .iter()
                .any(|word| word.contains(['{', '}']))
        {
            return None;
        }
        for site in sites {
            if site.body_end < words.len() {
                // A `\;` ended this body, and the split above moved whatever
                // fd runs next into a piece this walk never reads as fd's:
                // `fd -x echo \; -x gh pr merge` would name only `echo`.
                return None;
            }
            let operand = unquote(words[site.program]);
            // `\;` and `+` end a body rather than naming a program.
            if matches!(operand, "+" | "\\") {
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
        let sites = command_index(&words)
            .filter(|command| command_basename(unquote(words[*command])) == "fd")
            .and_then(|command| fd_exec_sites(&words, command + 1));
        let Some(sites) = sites else {
            pieces.push(words.join(" "));
            continue;
        };
        let mut is_argument = vec![false; words.len()];
        for site in sites {
            for word_is_argument in &mut is_argument[site.program + 1..site.body_end] {
                *word_is_argument = true;
            }
        }
        let kept: Vec<&str> = words
            .iter()
            .enumerate()
            .filter(|(position, _)| !is_argument[*position])
            .map(|(_, word)| *word)
            .collect();
        pieces.push(kept.join(" "));
    }
    pieces.join("\n")
}
