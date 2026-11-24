//! The commands of one shell command line a Python program hands to a
//! shell, and whether any of them signals processes, writes Git
//! configuration or lists the root directory.

use std::sync::LazyLock;

use regex::Regex;

/// Commands that list, copy or enter what a root-directory operand names.
const ROOT_COMMANDS: &[&str] = &[
    "ls", "find", "du", "tree", "grep", "rg", "cat", "rm", "cp", "mv", "chmod", "chown", "tar",
    "stat", "cd", "pushd",
];
const SIGNAL_COMMANDS: &[&str] = &["kill", "pkill", "killall"];
const GIT_CONFIG_READS: &[&str] = &["--get", "--get-all", "--get-regexp", "--list", "-l"];
/// Words that run a command named later on the line, after their own
/// options, option values and operands, including the shells' `-c`.
const COMMAND_PREFIXES: &[&str] = &[
    "env",
    "sudo",
    "doas",
    "pkexec",
    "nohup",
    "exec",
    "command",
    "builtin",
    "time",
    "nice",
    "ionice",
    "chrt",
    "taskset",
    "prlimit",
    "timeout",
    "setsid",
    "stdbuf",
    "flock",
    "xargs",
    "parallel",
    "watch",
    "chroot",
    "unshare",
    "nsenter",
    "su",
    "sg",
    "runuser",
    "fakeroot",
    "systemd-run",
    "strace",
    "ltrace",
    "unbuffer",
    "script",
    "caffeinate",
    "busybox",
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "fish",
];
/// Reserved words and grouping that may come before a command without being
/// one: `if true; then kill 1; fi` runs `kill`.
const CONTROL_WORDS: &[&str] = &[
    "if", "then", "else", "elif", "do", "while", "until", "!", "{", "(", "time",
];
/// Options of a command after which a later word runs as a command.
const COMMAND_OPTIONS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// Whether a word is an environment assignment such as `LC_ALL=C`.
fn assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// How many words a redirection at the start of `words` takes: one for
/// `>/dev/null` or `2>&1`, two for `>` followed by its target, none when
/// the first word is not a redirection.
fn redirection(words: &[String]) -> usize {
    let Some(word) = words.first() else {
        return 0;
    };
    let operator = word.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
    if !operator.starts_with(['<', '>']) {
        return 0;
    }
    if operator.trim_start_matches(['<', '>', '&', '|']).is_empty() {
        2.min(words.len())
    } else {
        1
    }
}

/// A shell word with its quotes and backslashes removed, as the shell
/// reads it: `'kill'`, `k""ill` and `\kill` are all `kill`.
pub(super) fn unquote(word: &str) -> String {
    word.chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect()
}

fn command_name(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// The positions in one shell command's words where a command may start:
/// the first word past assignments, redirections and reserved words, and
/// when that word is a wrapper, or after `find -exec`, every later word. A
/// wrapper's options can take a value or an operand (`env -u NAME`,
/// `sudo -u USER`, `chroot DIR`), so any of the words after it may be the
/// one that runs.
fn command_starts(words: &[String]) -> Vec<usize> {
    let mut first = 0;
    while first < words.len() {
        let skipped = redirection(&words[first..]);
        if skipped > 0 {
            first += skipped;
        } else if assignment(&words[first]) || CONTROL_WORDS.contains(&words[first].as_str()) {
            first += 1;
        } else {
            break;
        }
    }
    let mut starts = vec![first];
    let wrapped = words
        .get(first)
        .is_some_and(|word| COMMAND_PREFIXES.contains(&command_name(word)));
    let launched = if wrapped {
        Some(first)
    } else {
        words
            .iter()
            .position(|word| COMMAND_OPTIONS.contains(&word.as_str()))
    };
    if let Some(launcher) = launched {
        starts.extend(launcher + 1..words.len());
    }
    starts
}

/// Whether a word is what `kill` takes to name a process: a signal option,
/// a process or group number, a job, or a value expanded at run time.
fn names_process(word: &str) -> bool {
    word.starts_with(['-', '%', '$', '`']) || word.chars().all(|c| c.is_ascii_digit())
}

/// Whether a signal command appears anywhere among the words with an
/// operand of its own: `kill` followed by what names a process, `pkill` or
/// `killall` followed by anything. A launcher the wrapper list does not know
/// cannot hide it.
fn signals_anywhere(words: &[String]) -> bool {
    words.windows(2).any(|pair| match command_name(&pair[0]) {
        "kill" => names_process(&pair[1]),
        "pkill" | "killall" => true,
        _ => false,
    })
}

/// Whether `git config` with these words only reads. Only the words before
/// `--` are options; a `--get` after it is a value.
pub(super) fn git_config_reads<'a>(words: impl IntoIterator<Item = &'a str>) -> bool {
    words
        .into_iter()
        .take_while(|word| *word != "--")
        .any(|word| GIT_CONFIG_READS.contains(&word))
}

/// Whether one shell command signals processes, writes Git configuration or
/// lists the root directory.
pub(super) fn command_reaches(command: &str) -> bool {
    let words: Vec<String> = command.split_whitespace().map(unquote).collect();
    signals_anywhere(&words)
        || command_starts(&words).into_iter().any(|start| {
            let Some(first) = words.get(start) else {
                return false;
            };
            let name = command_name(first);
            let rest = || words[start + 1..].iter().map(String::as_str);
            SIGNAL_COMMANDS.contains(&name)
                || (name == "git"
                    && rest().any(|word| word == "config")
                    && !git_config_reads(rest()))
                || (ROOT_COMMANDS.contains(&name) && rest().any(|word| word == "/"))
        })
}

/// The rest of an argument list for `git ... config`.
static GIT_CONFIG_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"["']git["']\s*,\s*(?:["'][^"'\n]*["']\s*,\s*)*?["']config["']"#,
        r#"((?:\s*,\s*["'][^"'\n]*["'])*)"#,
    ))
    .unwrap()
});

static QUOTED_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']([^"'\n]*)["']"#).unwrap());

/// Whether a Python argument list runs `git config` with words that write.
pub(super) fn git_config_list_writes(code: &str) -> bool {
    GIT_CONFIG_LIST.captures_iter(code).any(|captures| {
        let words: Vec<&str> = QUOTED_WORD
            .captures_iter(&captures[1])
            .filter_map(|word| word.get(1).map(|word| word.as_str()))
            .collect();
        !git_config_reads(words)
    })
}
