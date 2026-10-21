//! `source .venv/bin/activate && pytest -q` is the first thing a Python
//! project runs, and the canonical parser models no part of it: the shell's
//! `source` builtin is a nested command executor, so the whole chain carried
//! an evaluation failure and the floor could lift it no higher than review.
//! Every ordinary test, lint and type-check run behind an activation paid for
//! that with an approval row.
//!
//! Activating an environment runs a generated script whose whole effect is
//! the settings it exports, so the command after it carries the verdict, the
//! way an inert environment prefix does. The projection earns that reading
//! three times over: the file has to resolve to a real activation script of a
//! marked environment (PEP 405 puts `pyvenv.cfg` directly above `bin`), its
//! text has to bound the programs it can run, and the word the command runs
//! next is rewritten to the environment's own `bin` when that is what the
//! activated `PATH` would reach. Anything else keeps the command unprojected.

use crate::cloud_scrub_shell::shell_tokens;
use crate::pretool::PathContext;
use std::path::Path;

#[path = "venv_activation_commands.rs"]
mod commands;

const MAX_PROJECTED_CHARS: usize = 8_192;

/// Characters a plain, literal path is written with. An expansion, a glob or
/// a quote builds the name at run time, and a name this scan cannot read is
/// not an activation script it has proven anything about.
fn plain_path(value: &str) -> bool {
    !value.is_empty()
        && value.contains('/')
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '+'))
}

/// Whether the activated environment's own `bin` holds a program of this
/// name, which is what the activated `PATH` would reach first.
fn environment_program(binaries: &Path, word: &str) -> bool {
    if word.is_empty()
        || word.contains('/')
        || word.contains('=')
        || word.starts_with('-')
        || !word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
    {
        return false;
    }
    binaries.join(word).is_file()
}

/// Names a generated activation script assigns. A script that sets anything
/// else — `LD_PRELOAD`, `BASH_ENV`, `PYTHONPATH`, `GIT_SSH_COMMAND` — decides
/// what the command after it runs, which is exactly the reading this
/// projection hands to that command.
fn activation_setting(name: &str) -> bool {
    matches!(
        name,
        "VIRTUAL_ENV"
            | "VIRTUAL_ENV_PROMPT"
            | "VIRTUAL_ENV_DISABLE_PROMPT"
            | "PATH"
            | "PS1"
            | "PYTHONHOME"
            | "SCRIPT_PATH"
    ) || name.starts_with("_OLD_")
}

/// The name a word assigns, or `None` when the word is not an assignment.
/// `NAME+=value` appends, which is an assignment the shell runs like any
/// other, so the name in front of it is the one to judge.
fn assigned_name(word: &str) -> Option<&str> {
    let (head, _) = word.split_once('=')?;
    let name = head.strip_suffix('+').unwrap_or(head);
    let mut characters = name.chars();
    let first = characters.next()?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(name)
}

/// Whether a word's text before its `=` reads as a variable's name without
/// being one this scan can judge, which is a name it must not skip over.
fn unreadable_assignment(word: &str) -> bool {
    word.split_once('=')
        .is_some_and(|(head, _)| head.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
        && assigned_name(word).is_none()
}

/// The saved copy a `$_OLD_…` reference reads back, or `None` when the value
/// is anything else. A restore is exactly the reference: a value with more
/// after it puts whatever that is into the variable too.
fn saved_reference(value: &str) -> Option<&str> {
    let rest = value.strip_prefix('$')?;
    let name = match rest.strip_prefix('{') {
        Some(inner) => inner.strip_suffix('}')?.trim_end_matches([':', '-']),
        None => rest,
    };
    (name.starts_with("_OLD_") && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then_some(name)
}

/// Whether a `_OLD_…` assignment saves the current value of the variable it
/// is named for, which is all a generated script writes one for. A saved copy
/// holding anything else is a place the restore would later install.
fn saves_current(name: &str, value: &str) -> bool {
    let saved = name.strip_prefix("_OLD_").unwrap_or(name);
    let saved = saved.strip_prefix("VIRTUAL_").unwrap_or(saved);
    [
        format!("${saved}"),
        format!("${{{saved}}}"),
        format!("${{{saved}-}}"),
        format!("${{{saved}:-}}"),
    ]
    .iter()
    .any(|form| form == value)
}

/// What an assignment's value is worth reading as: the rest of its line up to
/// a separator, without the quotes the shell splices out. Reading only the
/// word would cut `$(cd "$(dirname "$0")/.." && pwd)` in half.
fn assigned_value(line: &str, from: usize) -> String {
    line[from..]
        .split(';')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| *c != '"' && *c != '\'')
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The words of a line with the offset each one starts at. A shell separator
/// ends a word the way whitespace does, so `true;source other` and
/// `export VIRTUAL_ENV;PYTHONPATH=/elsewhere` are read as the two commands
/// the shell runs rather than as one word that assigns nothing.
fn words(line: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let mut word = None;
    for (index, character) in line.char_indices() {
        if character.is_whitespace() || matches!(character, ';' | '&' | '|' | '(' | ')') {
            if let Some(start) = word.take() {
                words.push((start, &line[start..index]));
            }
        } else if word.is_none() {
            word = Some(index);
        }
    }
    if let Some(start) = word {
        words.push((start, &line[start..]));
    }
    words
}

/// Whether a `PATH` segment is the shell's own `PATH` rather than a place of
/// its own. `${PATH:+:$PATH}` splits into pieces that are punctuation alone.
fn inherited_path(segment: &str) -> bool {
    let bare = segment.trim_matches(|c| matches!(c, '{' | '}' | '+' | '-' | '$' | ':'));
    bare.is_empty() || bare == "PATH"
}

/// `$HOME` is the one name an activation script can name a place with whose
/// value this scan already holds, so a value that starts with it is read as
/// the place it stands for.
fn with_home(value: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return value.to_owned();
    };
    for prefix in ["${HOME}", "$HOME"] {
        let Some(rest) = value.strip_prefix(prefix) else {
            continue;
        };
        if prefix == "$HOME" && rest.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
            break;
        }
        return format!("{home}{rest}");
    }
    value.to_owned()
}

/// Which directory an activation's `PATH` assignment puts in front.
enum Prepended {
    /// The saved path going back, which puts nothing in front.
    Restored,
    /// This environment's own `bin`, written out.
    Binaries,
    /// This environment's own `bin` by way of `$VIRTUAL_ENV`, which is the
    /// environment root only if the script's own `VIRTUAL_ENV` says so.
    ByEnvironment,
}

fn path_assignment(value: &str, binaries: &Path, home: Option<&str>) -> Option<Prepended> {
    if saved_reference(value).is_some() {
        return Some(Prepended::Restored);
    }
    let mut segments = value.split(':');
    let first = segments.next()?;
    if !segments.all(inherited_path) {
        return None;
    }
    let directory = binaries.file_name()?.to_str()?;
    if first == format!("$VIRTUAL_ENV/{directory}")
        || first == format!("${{VIRTUAL_ENV}}/{directory}")
    {
        return Some(Prepended::ByEnvironment);
    }
    (std::fs::canonicalize(with_home(first, home)).ok()? == binaries).then_some(Prepended::Binaries)
}

/// The absolute places a value names, which is where it could point the
/// variable other than at this environment.
fn places(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|c: char| c.is_whitespace() || matches!(c, '(' | ')'))
        // `$(dirname "$0")/..` leaves a piece that is a step rather than a
        // place: only one with a name of its own points anywhere.
        .filter(|piece| piece.starts_with('/') && piece.chars().any(|c| c != '/' && c != '.'))
}

/// Where a `VIRTUAL_ENV` assignment leaves the variable: `Some(true)` at this
/// environment's root, `Some(false)` somewhere that does not exist, `None`
/// derived from the value already there. A value naming another place refuses
/// the projection outright, because the `PATH` built from it would put that
/// place in front of the command.
/// The whole of what a generated script writes `VIRTUAL_ENV` from the value
/// it already holds: `uv` and `virtualenv` pass `-u`, the standard library's
/// `venv` does not, and `assigned_value` has taken the quotes out.
const CONVERSIONS: &[&str] = &[
    "$(cygpath -u $VIRTUAL_ENV)",
    "$(cygpath -u ${VIRTUAL_ENV})",
    "$(cygpath $VIRTUAL_ENV)",
    "$(cygpath ${VIRTUAL_ENV})",
];

fn environment_assignment(value: &str, root: &Path, home: Option<&str>) -> Option<Option<bool>> {
    let value = &with_home(value, home);
    // A relative step is the script walking up out of its own `bin`; more
    // than one would walk out of the environment.
    if value.matches("..").count() > 1 {
        return None;
    }
    if value.contains("$VIRTUAL_ENV") || value.contains("${VIRTUAL_ENV") {
        // The one reassignment a generated script builds on the value it has
        // already left: the conversion a Windows shell needs. Any other one
        // names a place of its own that this scan cannot check, because a
        // piece such as `$VIRTUAL_ENV/lib` or `${VIRTUAL_ENV}x` carries no
        // absolute path for `places` to resolve and would pass unread.
        return CONVERSIONS.contains(&value.as_str()).then_some(None);
    }
    if value.contains("dirname") || value.contains("SCRIPT_PATH") || value.contains("BASH_SOURCE") {
        // The script locating itself. Every absolute place it names has to be
        // this environment, including one that is not there to check.
        return places(value)
            .all(|piece| {
                std::fs::canonicalize(piece)
                    .map(|path| path == root)
                    .unwrap_or(false)
            })
            .then_some(Some(true));
    }
    if value.is_empty() || value.contains('$') || value.contains('`') {
        return None;
    }
    match std::fs::canonicalize(value) {
        Ok(path) if path == root => Some(Some(true)),
        Ok(_) => None,
        // A moved environment still activates; its `PATH` reaches nothing.
        Err(_) => Some(Some(false)),
    }
}

/// Whether the script's whole effect is the settings a generated activation
/// script writes, and whether the `PATH` it leaves reaches this environment's
/// own `bin`. `None` refuses the projection: a script that sets a name this
/// scan does not model, puts another directory in front of `PATH`, or reads
/// another file into the shell, decides what the command after it runs.
fn activation_settings(
    text: &str,
    binaries: &Path,
    root: &Path,
    home: Option<&str>,
) -> Option<bool> {
    let mut written = false;
    let mut by_environment = false;
    let mut environment_here = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        for (start, word) in words(line) {
            // Another file read into the shell carries settings this scan
            // never saw, and `eval` builds them where it cannot read them.
            if matches!(word, "." | "source" | "eval") {
                return None;
            }
            let Some(name) = assigned_name(word) else {
                if unreadable_assignment(word) {
                    return None;
                }
                continue;
            };
            if !activation_setting(name) {
                return None;
            }
            let value = assigned_value(line, start + word.find('=')? + 1);
            match name {
                "PATH" => match path_assignment(&value, binaries, home)? {
                    Prepended::Restored => {}
                    Prepended::Binaries => written = true,
                    // `PATH="$VIRTUAL_ENV/bin:$PATH"` reaches this
                    // environment only if the lines before it left
                    // `VIRTUAL_ENV` naming this environment.
                    Prepended::ByEnvironment => by_environment |= environment_here,
                },
                "VIRTUAL_ENV" => {
                    if let Some(here) = environment_assignment(&value, root, home)? {
                        environment_here = here;
                    }
                }
                // Restoring the saved home is what a generated script does
                // with it; setting one chooses the interpreter's own library.
                "PYTHONHOME" => {
                    saved_reference(&value)?;
                }
                // The path the script reads its own place out of, which it
                // takes from the shell rather than naming.
                "SCRIPT_PATH" => {
                    if !value.contains("BASH_SOURCE") && !value.contains("$0") {
                        return None;
                    }
                }
                // A saved copy holds what the variable had. One holding
                // anything else is a place the restore would install.
                saved if saved.starts_with("_OLD_") => {
                    if !saves_current(saved, &value) {
                        return None;
                    }
                }
                _ => {}
            }
        }
    }
    Some(written || (by_environment && environment_here))
}

/// The command without its leading activation, or `None` when the activation
/// is not one this scan can read through.
pub(super) fn project(command: &str, context: PathContext<'_>) -> Option<String> {
    let home = context.home_dir;
    if !command.is_ascii() || command.len() > MAX_PROJECTED_CHARS {
        return None;
    }
    let characters: Vec<char> = command.chars().collect();
    let tokens = shell_tokens(&characters)?;
    let [sourcing, target, separator, rest @ ..] = tokens.as_slice() else {
        return None;
    };
    if sourcing.is_control || !matches!(sourcing.value.as_str(), "." | "source") {
        return None;
    }
    if target.is_control || !plain_path(&target.value) {
        return None;
    }
    // `source x && y` hands the whole verdict to `y`. `source x; y` and
    // `source x | y` do not: the first runs `y` whatever the activation did,
    // and the second carries the activation's own bytes into it.
    if !separator.is_control || separator.value != "&&" {
        return None;
    }
    let first = rest.first().filter(|token| !token.is_control)?;
    let (script, text) = crate::pretool::activation_script_text(&target.value, context)?;
    if !crate::native_command_controls::bounds_its_owners(&text, command) {
        return None;
    }
    let binaries = script.parent()?;
    // The file is a set of settings only if every name it writes is one a
    // generated activation script writes. `reaches` says whether the `PATH`
    // those settings leave behind finds this environment's own programs.
    let reaches = activation_settings(&text, binaries, binaries.parent()?, home)?;
    // A file can write exactly those settings and still bind a name the rest
    // of the command runs to a program of its own choosing. A function the
    // file defines wins the lookup wherever the shell makes it, so every word
    // left in the command counts, not only the first.
    let words: Vec<&str> = rest
        .iter()
        .filter(|token| !token.is_control)
        .map(|token| token.value.as_str())
        .collect();
    if !commands::runs_settings_only(&text, &words) {
        return None;
    }
    // Only the word the command runs next is rewritten. A later word the
    // environment also holds would run a different program once the
    // activation has set `PATH`, and this projection does not answer for it.
    if rest
        .iter()
        .skip(1)
        .any(|token| !token.is_control && environment_program(binaries, &token.value))
    {
        return None;
    }
    let remainder: String = characters[first.start..].iter().collect();
    if remainder.trim().is_empty() {
        return None;
    }
    let (written, _) = target.value.rsplit_once('/')?;
    if reaches && environment_program(binaries, &first.value) {
        return Some(format!("{written}/{remainder}"));
    }
    Some(remainder)
}

#[cfg(test)]
#[path = "venv_activation_projection_tests.rs"]
mod tests;
