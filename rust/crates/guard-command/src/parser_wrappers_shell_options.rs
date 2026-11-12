//! The options a shell may carry in front of an inline `-c` script and still
//! run only that script, read for `parser_wrappers::inline_shell_script`.

/// The words after the one carrying `-c`, when every other option in front of
/// the script is one the shell reads without changing which programs the
/// script names.
///
/// `bash -ec 'npm test'`, `bash -ce 'npm test'` and `bash -e -c 'npm test'`
/// all run the script `bash -c 'npm test'` runs: a bundled word sets each of
/// its letters, and `-c` takes the script as the next word wherever in the
/// bundle it sits. A `+` bundle clears the same letters and never carries the
/// script. `-o` takes the next word as a `set` option name and `-O` takes a
/// `shopt` name, so `bash -euo pipefail -c 'npm test'` and
/// `bash -O extglob -c 'npm test'` are read only when that letter ends its
/// bundle and the name is one of [`INERT_SET_OPTIONS`] or
/// [`INERT_SHOPT_OPTIONS`]. `--norc` and `--noprofile` come before the short
/// options, the only place bash reads a long option.
///
/// The options are not checked against the shell that reads them. `dash
/// --norc -c 'ls'` and `sh -O extglob -c 'ls'` stop with an error where that
/// shell does not know the option, before the script runs, so the script
/// stays the most the text can run: reading it as the command keeps every
/// floor its words reach, where refusing it blocked outright with nothing to
/// approve. The walk refuses anything else, so `-l`, `-i`, `-s`, `-a`, `-k`
/// and a name outside those lists keep the paths they have.
pub(super) fn carries_script(words: &[String]) -> Option<&[String]> {
    let mut index = 0;
    let mut short_seen = false;
    loop {
        let word = words.get(index)?;
        index += 1;
        if let Some(long) = word.strip_prefix("--") {
            if short_seen || !INERT_LONG_OPTIONS.contains(&long) {
                return None;
            }
            continue;
        }
        let (word, sets) = match (word.strip_prefix('-'), word.strip_prefix('+')) {
            (Some(word), _) => (word, true),
            (None, Some(word)) => (word, false),
            (None, None) => return None,
        };
        short_seen = true;
        if word.is_empty() {
            return None;
        }
        let (flags, closes) = match word.find('c') {
            Some(_) if !sets => return None,
            Some(position) => (
                format!("{}{}", &word[..position], &word[position + 1..]),
                true,
            ),
            None => (word.to_string(), false),
        };
        let (flags, names) = match flags.chars().last() {
            Some('o') if !closes => (&flags[..flags.len() - 1], Some(INERT_SET_OPTIONS)),
            Some('O') if !closes => (&flags[..flags.len() - 1], Some(INERT_SHOPT_OPTIONS)),
            _ => (flags.as_str(), None),
        };
        if !flags.chars().all(|flag| INERT_SHELL_FLAGS.contains(flag)) {
            return None;
        }
        if let Some(names) = names {
            if !names.contains(&words.get(index)?.as_str()) {
                return None;
            }
            index += 1;
        }
        if closes {
            return Some(&words[index..]);
        }
    }
}

/// The option letters a shell reads without changing which words the script
/// is or what the shell reads before running it: stop at the first failure,
/// refuse an unset parameter, trace or echo what runs, leave globs as written,
/// refuse to overwrite a file through `>`, and carry `ERR`, `DEBUG` and
/// `RETURN` traps into functions. `-a` exports every assignment, so
/// `LD_PRELOAD=x.so; ls` would hand `ls` a loader hook the words never give
/// it, and `-k` turns a later `NAME=value` operand into the program's
/// environment; both stay out.
const INERT_SHELL_FLAGS: &str = "euxvfCET";

/// The `set -o` names of those letters, plus `pipefail`, which only changes
/// the status a pipeline reports. `posix` stays out: POSIX mode expands
/// aliases in a script, as `expand_aliases` does.
const INERT_SET_OPTIONS: &[&str] = &[
    "errexit",
    "nounset",
    "xtrace",
    "verbose",
    "noglob",
    "noclobber",
    "errtrace",
    "functrace",
    "pipefail",
];

/// The `shopt` names that change only how far a glob reaches or how a failure
/// is reported. An extended pattern is not plain shell text, so a script that
/// uses one already fails its own parse and keeps the wrapper's uncertainty.
/// `nullglob` drops a glob that matches nothing, so the word after it would
/// become the program: `nomatch* rm -rf ~` runs `rm`. It stays out with
/// `expand_aliases`, `extdebug` and the rest, which change what a word runs
/// or read another file.
const INERT_SHOPT_OPTIONS: &[&str] = &[
    "extglob",
    "globstar",
    "failglob",
    "inherit_errexit",
    "lastpipe",
];

/// The bash long options that only stop it reading a startup file.
const INERT_LONG_OPTIONS: &[&str] = &["norc", "noprofile"];
