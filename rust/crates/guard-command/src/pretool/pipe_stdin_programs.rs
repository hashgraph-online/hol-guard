//! Whether a shell or interpreter at the end of a pipe takes its program from
//! standard input.
//!
//! Each interpreter family reads its own options. A flag that names the
//! program (`python3 -c`, `perl -e`) or only prints or lints it (`php -l`)
//! makes stdin data. A flag that takes a value (`python3 -W ignore`, `ruby -r
//! lib`) skips that value, and a version or help flag exits before reading
//! anything. The first operand ends the options: `-` is standard input and
//! anything else is a script file, except after PHP's `--`, where the words are
//! arguments to a program read from stdin. Syntax-check flags still count as
//! running the program, because `perl -c` runs `BEGIN` blocks.

use super::program;

/// How one interpreter family reads its options.
struct Options {
    /// Short flags that give the program some other way, or never run it.
    no_stdin: &'static str,
    /// Short flags whose value is the rest of the word or the next word.
    value: &'static str,
    /// Short flags whose optional value can only be the rest of the word.
    attached: &'static str,
    /// Words that print something and exit.
    exits: &'static [&'static str],
    /// Words after `--` are arguments to a program read from stdin.
    args_after_dashdash: bool,
    /// Long options that leave stdin as the program, and whether a value can
    /// be the next word. `--name=value` is accepted for any of them.
    long: &'static [(&'static str, bool)],
}

const PYTHON: Options = Options {
    no_stdin: "cm",
    value: "WX",
    attached: "",
    exits: &["-V", "-VV", "-h", "-?"],
    args_after_dashdash: false,
    long: &[("--check-hash-based-pycs", true)],
};
const PERL: Options = Options {
    no_stdin: "eE",
    value: "IMm",
    attached: "il0FCdDx",
    exits: &["-v", "-V", "-h"],
    args_after_dashdash: false,
    long: &[],
};
const RUBY: Options = Options {
    no_stdin: "e",
    value: "ICEr",
    attached: "0FiKTWx",
    exits: &["-h"],
    args_after_dashdash: false,
    long: &[],
};
const NODE: Options = Options {
    no_stdin: "ep",
    value: "rC",
    attached: "",
    exits: &["-v", "-h"],
    args_after_dashdash: false,
    long: &[
        ("--require", true),
        ("--import", true),
        ("--loader", true),
        ("--experimental-loader", true),
        ("--input-type", true),
        ("--conditions", true),
        ("--title", true),
        ("--env-file", true),
        ("--max-old-space-size", false),
        ("--stack-size", false),
        ("--no-warnings", false),
        ("--no-deprecation", false),
        ("--trace-warnings", false),
        ("--trace-uncaught", false),
        ("--enable-source-maps", false),
        ("--experimental-vm-modules", false),
        ("--preserve-symlinks", false),
    ],
};
const PHP: Options = Options {
    no_stdin: "rBREfFlswim",
    value: "cdz",
    attached: "",
    exits: &["-v", "-h"],
    args_after_dashdash: true,
    long: &[
        ("--php-ini", true),
        ("--no-php-ini", false),
        ("--define", true),
    ],
};
// Bun and Deno keep the original rule: only single-dash flags that name no
// program, so `deno run -` and similar subcommands stay unclaimed.
const OTHER: Options = Options {
    no_stdin: "cemprxE",
    value: "",
    attached: "",
    exits: &[],
    args_after_dashdash: false,
    long: &[],
};

/// A shell or interpreter that takes its program from standard input.
pub(super) fn runs_stdin_program(words: &[String]) -> bool {
    let Some(name) = program(words) else {
        return false;
    };
    let arguments = &words[1..];
    if matches!(
        name,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" | "mksh" | "fish"
    ) {
        return shell_reads_stdin(name == "bash", arguments);
    }
    let options = if name.starts_with("python") {
        &PYTHON
    } else if name.starts_with("perl") {
        &PERL
    } else if name.starts_with("ruby") {
        &RUBY
    } else if matches!(name, "node" | "nodejs") {
        &NODE
    } else if name == "php" {
        &PHP
    } else if matches!(name, "bun" | "deno") {
        &OTHER
    } else {
        return false;
    };
    interpreter_reads_stdin(options, arguments)
}

fn interpreter_reads_stdin(options: &Options, arguments: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if argument == "-" {
            return true;
        }
        if argument == "--" {
            return options.args_after_dashdash
                || arguments.get(index).is_none_or(|next| next == "-");
        }
        if options.exits.contains(&argument.as_str())
            || matches!(argument.as_str(), "--version" | "--help")
        {
            return false;
        }
        // Unknown long options, and options missing the value the
        // interpreter needs, are left to the ordinary review rather than
        // claimed as an attack.
        if argument.starts_with("--") {
            let (name, attached) = argument
                .split_once('=')
                .map_or((argument.as_str(), false), |(name, _)| (name, true));
            match options.long.iter().find(|(long, _)| *long == name) {
                Some((_, true)) if !attached => {
                    if arguments.get(index).is_none() {
                        return false;
                    }
                    index += 1;
                    continue;
                }
                Some(_) => continue,
                None => return false,
            }
        }
        let Some(flags) = argument.strip_prefix('-') else {
            // A script file: standard input is that script's data.
            return false;
        };
        let flags: Vec<char> = flags.chars().collect();
        for (position, flag) in flags.iter().enumerate() {
            if options.no_stdin.contains(*flag) {
                return false;
            }
            if options.value.contains(*flag) {
                if position + 1 == flags.len() {
                    if arguments.get(index).is_none() {
                        return false;
                    }
                    index += 1;
                }
                break;
            }
            if options.attached.contains(*flag) {
                break;
            }
        }
    }
    true
}

fn shell_reads_stdin(bash: bool, arguments: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "-s" || argument == "-" {
            return true;
        }
        // `-O` (shopt) and `--rcfile` are Bash-only; other shells reject them.
        if matches!(argument.as_str(), "-o" | "+o")
            || (bash && matches!(argument.as_str(), "-O" | "+O"))
        {
            index += 2;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            match long {
                // An operand after `--` is a script file, except `-`, which
                // still names standard input.
                "" => return arguments.get(index + 1).is_none_or(|next| next == "-"),
                "version" | "help" => return false,
                "rcfile" | "init-file" if bash => index += 1,
                _ => {}
            }
        } else if argument.starts_with(['-', '+']) {
            if argument.contains('c') {
                return false;
            }
            if argument.starts_with('-') && argument.contains('s') {
                return true;
            }
        } else {
            // A script file operand: stdin is that script's input.
            return false;
        }
        index += 1;
    }
    true
}
