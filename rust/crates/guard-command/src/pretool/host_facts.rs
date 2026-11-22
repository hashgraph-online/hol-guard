//! Scalars that print a fact about the host, the user or the terminal.
//!
//! Each command here answers a question an agent asks before it starts work --
//! how many cores to build with, which macOS this is, which account the shell
//! runs as, how wide the terminal is -- and none of them opens a file operand
//! or runs another program. `uname` and `whoami` are proven beside them in
//! `segment_proof.rs` already; these are the rest of that family.
//!
//! The option screens are deliberately narrow. Several of these names are
//! read-only in one spelling and a mutation in another: `hostname NAME` sets
//! the system name, `arch -x86_64 CMD` execs `CMD`, `stty -echo` reconfigures
//! the terminal, and `bc FILE` opens a file. Only the reading spelling proves.
//! `ulimit` with a value raises or lowers a limit, `sysctl key=value` sets
//! kernel state, and both keep their review.

/// Whether `basename` with `arguments` prints a host fact and does nothing else.
pub(super) fn safe_host_fact(basename: &str, arguments: &[String]) -> bool {
    match basename {
        // `nproc` prints the processor count. `--all` prints the installed
        // count instead of the available one; both are the same scalar.
        "nproc" => flags_only(arguments, &["--all"]),
        // `sw_vers` prints the macOS product name, version and build. Each
        // flag selects one of those three lines.
        "sw_vers" => flags_only(
            arguments,
            &[
                "-productName",
                "-productVersion",
                "-productVersionExtra",
                "-buildVersion",
                "--json",
            ],
        ),
        // Bare `arch` prints the architecture. Every other spelling --
        // `arch -x86_64 cmd`, `arch -arch arm64e cmd` -- runs `cmd` under a
        // chosen architecture, so only the empty form is a fact.
        "arch" => arguments.is_empty(),
        // `hostname` prints the system name; `hostname NAME` sets it. An
        // operand is therefore never a read, and only the short/long display
        // flags prove.
        "hostname" => flags_only(arguments, &["-s", "-f", "-d"]),
        // `id` and `groups` print the account the shell already runs as, or
        // the public uid/gid record of a named account. Neither reads a
        // credential: `/etc/passwd` holds no password on any supported host.
        "id" => identity_arguments(arguments, "ugGnrpPaz"),
        "groups" => identity_arguments(arguments, ""),
        // `locale` prints the locale settings in effect, `-a` the installed
        // locales, `-m` the charmaps. A keyword operand (`LC_TIME`) selects
        // one line of the same output.
        "locale" => arguments.iter().all(|argument| {
            matches!(argument.as_str(), "-a" | "-m" | "-c" | "-k" | "-v") || keyword(argument)
        }),
        // `cal` prints a calendar for the month or year it is given. Its
        // operands are numbers, so no spelling of it names a file.
        "cal" => calendar_arguments(arguments),
        // `tty` prints the terminal the shell is attached to. `-s` prints
        // nothing and answers in the exit status instead.
        "tty" => flags_only(arguments, &["-s"]),
        // `ulimit` prints a resource limit; a value operand raises or lowers
        // it, so only the flags prove and any operand keeps the review.
        "ulimit" => {
            !arguments.is_empty()
                && arguments.iter().all(|argument| {
                    matches!(
                        argument.as_str(),
                        "-a" | "-c"
                            | "-d"
                            | "-f"
                            | "-l"
                            | "-m"
                            | "-n"
                            | "-s"
                            | "-t"
                            | "-u"
                            | "-v"
                            | "-H"
                            | "-S"
                    )
                })
        }
        // `sysctl` prints kernel state. `sysctl -w key=value` and
        // `sysctl key=value` set it and `-p` loads settings from a file, so
        // an operand proves only as a bare dotted key with no `=`.
        "sysctl" => sysctl_arguments(arguments),
        // `getconf` prints one configuration value, or the whole table with
        // `-a`. The two-operand `getconf NAME PATH` form queries a path and
        // is left out.
        "getconf" => getconf_arguments(arguments),
        // `tput` reads one capability out of the terminfo entry. The named
        // capabilities print a number or a string and leave the terminal as
        // it is; `tput init`, `tput reset` and `tput clear` write control
        // sequences that change it, so they are not listed.
        "tput" => {
            !arguments.is_empty()
                && arguments.iter().all(|argument| {
                    matches!(argument.as_str(), "cols" | "lines" | "colors" | "longname")
                })
        }
        // `stty size`, `-a` and `-g` print the terminal settings. Every other
        // argument assigns one.
        "stty" => matches!(arguments, [only] if matches!(only.as_str(), "size" | "-a" | "-g")),
        // `seq` prints a range of numbers. The operands are the bounds, and
        // `-s`/`-t` take a literal separator, so nothing here reads a path.
        "seq" => seq_arguments(arguments),
        // `expr` evaluates its operands and prints the result. It opens no
        // file and starts no process, whatever the expression says.
        "expr" => !arguments.is_empty(),
        // `bc` and `col` read standard input. A `bc` file operand opens that
        // file, so only the flag forms prove; `col` takes no operand at all.
        "bc" => flags_only(
            arguments,
            &["-l", "--mathlib", "-q", "--quiet", "-s", "--standard"],
        ),
        "col" => flags_only(arguments, &["-b", "-f", "-p", "-x", "-h"]),
        _ => false,
    }
}

/// Whether every argument is one of `allowed`.
fn flags_only(arguments: &[String], allowed: &[&str]) -> bool {
    arguments
        .iter()
        .all(|argument| allowed.contains(&argument.as_str()))
}

/// Flags drawn from `letters`, plus at most one account name.
fn identity_arguments(arguments: &[String], letters: &str) -> bool {
    let mut names = 0;
    for argument in arguments {
        if let Some(flags) = argument.strip_prefix('-') {
            if letters.is_empty()
                || flags.is_empty()
                || !flags.chars().all(|letter| letters.contains(letter))
            {
                return false;
            }
        } else if names == 0 && keyword(argument) {
            names += 1;
        } else {
            return false;
        }
    }
    true
}

/// `seq [-w] [-s SEP] [-t SEP] FIRST [INCREMENT] LAST`, with numeric bounds.
fn seq_arguments(arguments: &[String]) -> bool {
    let mut bounds = 0;
    let mut expect_separator = false;
    for argument in arguments {
        if expect_separator {
            expect_separator = false;
            continue;
        }
        match argument.as_str() {
            "-w" | "--equal-width" => {}
            "-s" | "-t" | "--separator" => expect_separator = true,
            value if number(value) => bounds += 1,
            _ => return false,
        }
    }
    !expect_separator && (1..=3).contains(&bounds)
}

/// A decimal number, which `seq` reads as a bound rather than an option.
fn number(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty()
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && digits.bytes().filter(|byte| *byte == b'.').count() <= 1
        && digits.bytes().any(|byte| byte.is_ascii_digit())
}

/// A plain word: an account name or a locale keyword, never a path.
fn keyword(argument: &str) -> bool {
    !argument.is_empty()
        && !argument.starts_with('-')
        && argument.len() <= 64
        && argument
            .chars()
            .all(|letter| letter.is_ascii_alphanumeric() || "._-".contains(letter))
}

/// `cal`, `cal 2026`, `cal 11 2026` and the display flags. Every operand is a
/// number, so none of them is a path.
fn calendar_arguments(arguments: &[String]) -> bool {
    let mut operands = 0;
    for argument in arguments {
        if matches!(argument.as_str(), "-y" | "-3" | "-j" | "-h" | "-m" | "-w") {
            continue;
        }
        if !number(argument) {
            return false;
        }
        operands += 1;
        if operands > 2 {
            return false;
        }
    }
    true
}

/// The reading spellings of `sysctl`: the display flags and bare dotted keys.
/// An `=` anywhere is an assignment, and `-w` and `-p` write.
fn sysctl_arguments(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        matches!(argument.as_str(), "-a" | "-n" | "-e" | "-A" | "-X")
            || (!argument.starts_with('-') && sysctl_key(argument))
    })
}

/// A sysctl key is a dotted name: letters, digits, `_` and `.` only.
fn sysctl_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_'))
}

/// `getconf -a`, or one configuration name. The `getconf NAME PATH` form
/// takes a path operand and is not admitted here.
fn getconf_arguments(arguments: &[String]) -> bool {
    match arguments {
        [only] if only == "-a" => true,
        [name] => keyword(name),
        _ => false,
    }
}

#[cfg(test)]
#[path = "host_facts_tests.rs"]
mod host_facts_tests;
