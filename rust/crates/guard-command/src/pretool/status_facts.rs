//! Asking the machine how busy it is and who is on it.
//!
//! A session that is about to build something looks at the host first: how
//! much memory is free, which processes are hot, whether the service it needs
//! came up, who else is logged in. `uptime`, `df` and `ps` already read past
//! review; `w`, `who`, `last`, `vm_stat`, `iostat` and `top` ask the same kind
//! of question and did not, so a status check stopped the session.
//!
//! Every name here prints a counter or a table. None of them opens a file the
//! caller names, writes one, or starts another program -- with two exceptions,
//! which is why each screen is written per name rather than as one list:
//!
//! * `last -f FILE` reads an alternate accounting file, so the file-bearing
//!   options refuse the proof and only the record-count limits are admitted.
//! * `top` is an interactive program by default, and the interactive screen
//!   renices and signals the processes it lists. Only the logging modes are
//!   admitted: macOS `-l N` and Linux `-b`, which print the samples and exit.
//!
//! `systemctl` is deliberately absent. Reporting on a unit is a privileged
//! system read rather than a workspace one, and the command corpus authors it
//! that way, so it keeps its review.
//!
//! Values are read as the word after their option, and an option this screen
//! does not know refuses the whole line rather than being skipped, so a value
//! can never be read as a file name.

/// A status reader that prints counters, samples or login sessions.
pub(super) fn safe_status_fact(basename: &str, arguments: &[String]) -> bool {
    match basename {
        "w" => flags_only(arguments, &["-h", "-i", "-n", "-s", "-f", "-u", "-o"]),
        "who" => who_arguments(arguments),
        "last" | "lastb" => last_arguments(arguments),
        "vm_stat" | "vmstat" => sampling_arguments(
            arguments,
            &[
                "-c", "-a", "-d", "-f", "-h", "-m", "-n", "-S", "-s", "-t", "-w",
            ],
        ),
        "iostat" => sampling_arguments(
            arguments,
            &[
                "-c", "-C", "-d", "-h", "-I", "-j", "-K", "-k", "-m", "-N", "-n", "-o", "-p", "-T",
                "-t", "-U", "-w", "-x", "-y", "-z",
            ],
        ),
        "mpstat" | "pidstat" => sampling_arguments(
            arguments,
            &[
                "-A", "-d", "-h", "-I", "-P", "-p", "-r", "-s", "-T", "-t", "-u", "-V", "-w",
            ],
        ),
        "top" => top_arguments(arguments),
        _ => false,
    }
}

/// Every word is one of the listed flags.
fn flags_only(arguments: &[String], flags: &[&str]) -> bool {
    arguments
        .iter()
        .all(|argument| flags.contains(&argument.as_str()))
}

/// `who`, its report flags, and the `who am i` spelling of `whoami`.
fn who_arguments(arguments: &[String]) -> bool {
    if arguments.len() == 2 && arguments[0] == "am" && arguments[1].eq_ignore_ascii_case("i") {
        return true;
    }
    flags_only(
        arguments,
        &[
            "-a",
            "-b",
            "-d",
            "-H",
            "-l",
            "-m",
            "-p",
            "-q",
            "-r",
            "-s",
            "-T",
            "-t",
            "-u",
            "-w",
            "--all",
            "--boot",
            "--count",
            "--heading",
            "--users",
        ],
    )
}

/// `last`, a record limit, and the login names or terminals to report on.
///
/// `-f`, `-F` and the other file-bearing options are absent from the flag
/// list, so a spelling that names an accounting file keeps its review.
fn last_arguments(arguments: &[String]) -> bool {
    let mut remaining = arguments;
    while let Some((word, rest)) = remaining.split_first() {
        if word == "-n" {
            let Some((value, tail)) = rest.split_first() else {
                return false;
            };
            if !number(value) {
                return false;
            }
            remaining = tail;
            continue;
        }
        if let Some(count) = word.strip_prefix('-') {
            if !number(count) && !matches!(word.as_str(), "-R" | "-w" | "-x" | "-a" | "-i") {
                return false;
            }
            remaining = rest;
            continue;
        }
        if !account_name(word) {
            return false;
        }
        remaining = rest;
    }
    true
}

/// A sampler: its own report flags in any order, and plain-word operands.
///
/// Which of these flags take a value differs between the macOS and Linux
/// spellings of the same name -- `vm_stat -c 3` and `iostat -w 1` take one,
/// `vmstat -s`, `iostat -x` and `mpstat -A` take none -- so the screen does not
/// try to tell them apart. Every word that is not one of the name's own flags
/// has to be a plain keyword, which rules out a path separator, an assignment
/// and another option, so an interval and an option value are screened the same
/// way and neither can name a file.
fn sampling_arguments(arguments: &[String], flags: &[&str]) -> bool {
    arguments
        .iter()
        .all(|word| flags.contains(&word.as_str()) || keyword(word))
}

/// `top` in a logging mode, which prints a bounded number of samples and exits.
///
/// Without `-l` on macOS or `-b` on Linux the program takes over the terminal
/// and its interactive keys renice and signal the processes it lists, so the
/// batch flag has to be there before anything else is read. The count has to
/// be there too and has to be positive: `top -l 0` samples forever, and Linux
/// `top -b` with no `-n` does the same, so either would hold the agent's shell
/// step until it timed out.
fn top_arguments(arguments: &[String]) -> bool {
    let mut logging = false;
    let mut background = false;
    let mut iterations = false;
    let mut remaining = arguments;
    while let Some((word, rest)) = remaining.split_first() {
        match word.as_str() {
            "-l" | "-n" | "-s" | "-d" | "-o" | "-O" | "-U" | "-u" | "-p" | "-pid" | "-ncols"
            | "-stats" | "-w" => {
                let Some((value, tail)) = rest.split_first() else {
                    return false;
                };
                if !keyword(value) {
                    return false;
                }
                match word.as_str() {
                    "-l" => {
                        if !positive(value) {
                            return false;
                        }
                        logging = true;
                    }
                    "-n" => {
                        if !positive(value) {
                            return false;
                        }
                        iterations = true;
                    }
                    _ => {}
                }
                remaining = tail;
            }
            "-b" | "-H" | "-i" | "-c" | "-S" | "-E" | "-e" | "-a" | "-r" | "-R" | "-F" | "-f"
            | "-t" | "-q" => {
                if word == "-b" {
                    background = true;
                }
                remaining = rest;
            }
            _ => {
                let Some(count) = word.strip_prefix("-n") else {
                    return false;
                };
                if !positive(count) {
                    return false;
                }
                iterations = true;
                remaining = rest;
            }
        }
    }
    logging || (background && iterations)
}

/// A count that bounds a sampling run: decimal and not zero.
fn positive(word: &str) -> bool {
    number(word) && word.chars().any(|character| character != '0')
}

/// A login name or terminal: no separator, so no path and no option.
fn account_name(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 64
        && word
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// A decimal count or interval.
fn number(word: &str) -> bool {
    !word.is_empty() && word.len() <= 12 && word.chars().all(|character| character.is_ascii_digit())
}

/// An option value: a plain word, never a path and never another option.
///
/// A leading `-` or `+` is refused. Several of these programs read a `+`
/// word as an option of their own, so a word spelled that way cannot be
/// treated as the interval or the keyword the screen expects.
fn keyword(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 64
        && !word.starts_with('-')
        && !word.starts_with('+')
        && word.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ',' | '+')
        })
}

#[cfg(test)]
#[path = "status_facts_tests.rs"]
mod status_facts_tests;
