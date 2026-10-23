//! Scheduling and buffering prefixes that run the program the text names.
//!
//! `nice -n 10 npm run build` runs `npm run build`, as this user and in this
//! directory, with one scheduling number changed, and `stdbuf -oL pytest -q`
//! changes how the same child's standard streams are buffered. Neither picks a
//! different program, a different user or a different root, so the owners of
//! the wrapped command are the owners of the command itself - the reading
//! `timeout` and `time` already get.
//!
//! Without that reading the prefix stayed the executable, and a transparent
//! wrapper in that position leaves the whole command unmodelled: ordinary work
//! such as `nice -n 10 cargo build` and `stdbuf -oL pytest -q` reached review
//! with nothing proven about it, while the same words without the prefix
//! modelled exactly.
//!
//! Each prefix is walked through its own documented option grammar, because
//! the program is not at a fixed offset: `nice -n 10 cargo`, `nice -10 cargo`
//! and `stdbuf -oL -e0 cargo` each put it somewhere else. A word that grammar
//! does not cover, a value outside the shape the prefix documents, or no
//! program at all leaves the prefix in place and the command as uncertain as
//! it is today. `nice +10 cargo` is one of those: GNU `nice` reads only `-N` as
//! an adjustment, so `+10` is the program it runs and the word is left to
//! name it.
//!
//! The shell's `exec` reads the same way. `exec npm test` runs exactly what
//! `npm test` runs, as this user and in this directory; it only replaces the
//! shell process instead of forking one, and writes nothing of its own. It
//! documents no option this grammar covers, so `exec -a name prog`,
//! `exec -c prog` and `exec -l bash` leave the program unread, as does an
//! `exec` that names no program at all and only moves the shell's own file
//! descriptors. Without this reading an ordinary `exec npm test` was a nested
//! executor with nothing proven about it, and reached a refusal its owners
//! could not approve, while an `exec` in front of a command a registered
//! extension governs never reached that extension's rule at all.
//!
//! Two look-alikes are not here. `setsid` detaches the program into a session
//! of its own rather than only scheduling it. `nohup` also keeps the program
//! past a hangup, but when its standard output is a terminal it appends the
//! output to `nohup.out`, a file the text never names; reading only the program
//! behind it would grant that program's decision to a command that also writes.
//! A prefix spelled as a path (`./nice`, `/tmp/tools/stdbuf`) is a program of
//! the user's own that shares a launcher's name, so it is not read as one, and
//! a `PATH=` assignment in front of the command is tracked on the segment as
//! it is for every other program.

/// One prefix's option grammar: the short letters that carry a value, the long
/// spellings that carry one, whether a bare number is its own option, and
/// whether the prefix refuses to run without at least one option.
struct Grammar {
    prefix: &'static str,
    short_values: &'static str,
    long_values: &'static [&'static str],
    numeric_flag: bool,
    option_required: bool,
}

const GRAMMARS: [Grammar; 3] = [
    Grammar {
        prefix: "exec",
        // `exec` documents no option that still runs the named program.
        short_values: "",
        long_values: &[],
        numeric_flag: false,
        option_required: false,
    },
    Grammar {
        prefix: "nice",
        short_values: "n",
        long_values: &["adjustment"],
        // `nice -10 cargo build` is the adjustment spelled on its own.
        numeric_flag: true,
        option_required: false,
    },
    Grammar {
        prefix: "stdbuf",
        short_values: "ioe",
        long_values: &["input", "output", "error"],
        numeric_flag: false,
        // `stdbuf npm test` is an error, not a run of `npm test`: the prefix
        // exists to set a buffering mode and exits when given none.
        option_required: true,
    },
];

/// Where the program stands behind a launcher at `index`, when every word in
/// between is one this launcher documents and a program follows it.
///
/// The program must also be one the scan can name. A path, a script file, an
/// interpreter and a prefix this module does not read each hand the run to a
/// program whose own text was never opened, so `nice ./deploy.sh` and
/// `stdbuf -oL python3 deploy.py` keep the unmodelled failure they arrive
/// with rather than reaching an owner as though `deploy.sh` were a program the
/// text names.
pub(crate) fn launcher_program(tokens: &[String], index: usize) -> Option<usize> {
    let name = tokens.get(index)?;
    if name.contains(['/', '\\']) {
        return None;
    }
    let grammar = GRAMMARS.iter().find(|grammar| grammar.prefix == name)?;
    let mut next = index + 1;
    let mut options = 0;
    while let Some(word) = tokens.get(next) {
        if word == "--" {
            next += 1;
            break;
        }
        if !word.starts_with('-') {
            break;
        }
        // A lone `-` is no option of these three.
        if word == "-" {
            return None;
        }
        next += 1 + option_words(grammar, tokens, next)?;
        options += 1;
    }
    if grammar.option_required && options == 0 {
        return None;
    }
    let program = tokens.get(next)?;
    if program.is_empty() || program.starts_with('-') || crate::assignment_name(program).is_some() {
        return None;
    }
    let words: Vec<&str> = tokens[index..].iter().map(String::as_str).collect();
    (!crate::native_command_controls::prefix_reads_a_program_file(&words)).then_some(next)
}

/// How many further words this option word carries, or `None` when the
/// launcher does not document it or its value is outside the shape it takes.
fn option_words(grammar: &Grammar, tokens: &[String], index: usize) -> Option<usize> {
    let word = tokens.get(index)?;
    if let Some(long) = word.strip_prefix("--") {
        let (name, inline) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (long, None),
        };
        if !grammar.long_values.contains(&name) {
            return None;
        }
        return match inline {
            Some(value) => value_safe(grammar, value).then_some(0),
            None => value_safe(grammar, tokens.get(index + 1)?).then_some(1),
        };
    }
    let cluster = word.strip_prefix('-')?;
    if grammar.numeric_flag && adjustment(cluster) {
        return Some(0);
    }
    // Every short option here carries a value, so the letter is the whole
    // cluster or stands in front of the value glued to it.
    let letter = cluster.chars().next()?;
    if !grammar.short_values.contains(letter) {
        return None;
    }
    let glued = &cluster[letter.len_utf8()..];
    if glued.is_empty() {
        return value_safe(grammar, tokens.get(index + 1)?).then_some(1);
    }
    value_safe(grammar, glued).then_some(0)
}

/// Whether a value is the one its launcher documents: a scheduling adjustment
/// for `nice`, a buffering mode for `stdbuf`.
fn value_safe(grammar: &Grammar, value: &str) -> bool {
    match grammar.prefix {
        "nice" => adjustment(value.strip_prefix(['-', '+']).unwrap_or(value)),
        "stdbuf" => buffering_mode(value),
        // `exec` takes no value, so a word that looks like one is not its own.
        _ => false,
    }
}

/// A scheduling number: `nice` reads -20 through 19, so two digits bound it.
fn adjustment(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// A buffering mode: line buffered, unbuffered, or a size such as `1024`,
/// `4K` or `1MB`.
fn buffering_mode(value: &str) -> bool {
    if matches!(value, "L" | "0") {
        return true;
    }
    let digits = value.trim_end_matches(|byte: char| byte.is_ascii_alphabetic());
    let unit = &value[digits.len()..];
    !digits.is_empty()
        && digits.len() <= 10
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(unit, "" | "K" | "KB" | "M" | "MB" | "G" | "GB")
}

#[cfg(test)]
#[path = "parser_launchers_tests.rs"]
mod tests;
