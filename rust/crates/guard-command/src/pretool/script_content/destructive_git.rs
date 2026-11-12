//! Inline programs that run a git command which discards work.
//!
//! The workspace sandbox lets a contained program write and delete workspace
//! files, so a program that shells out to `git reset --hard`, `git clean -fdx`
//! or `git checkout -- .` loses uncommitted work inside the sandbox just as it
//! would outside it. The same command typed at the shell keeps its review; a
//! program that spells it from its own string literals keeps the same review
//! instead of running contained. Only inline source and programs fed on
//! standard input are read; a script file keeps its own route.

use std::sync::LazyLock;

use regex::Regex;

use super::{assess_programs, code_lines, sent_model, structure, Language, PathContext};
use crate::CanonicalCommandV1;
use guard_contracts::PreToolResultV1;

/// One quoted literal: single, double or backtick quoted, on one line.
const LITERAL: &str = r#"(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`)"#;

/// A bracketed or parenthesized list made only of literals: an argv array
/// (`["git", "reset", "--hard"]`) or a call's literal arguments
/// (`system("git", "checkout", "--", ".")`).
static LITERAL_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"[\[(]\s*({LITERAL}(?:\s*,\s*{LITERAL})*)\s*,?\s*[\])]"
    ))
    .unwrap()
});

/// A program name followed by its argument array, as Node's
/// `spawnSync('git', ['reset', '--hard'])` and Python's
/// `os.execvp('git', ['git', 'clean', '-fdx'])` pass them.
static NAME_THEN_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"({LITERAL})\s*,\s*\[\s*({LITERAL}(?:\s*,\s*{LITERAL})*)\s*,?\s*\]"
    ))
    .unwrap()
});

/// Ruby's word arrays: `%w[git checkout -- .]`.
static WORD_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"%[wW](?:\[([^\]]*)\]|\(([^)]*)\)|\{([^}]*)\}|<([^>]*)>)").unwrap()
});

static ONE_LITERAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(LITERAL).unwrap());

/// Interpreters whose inline source this check reads beside Python and Node,
/// with the options that take that source.
const OTHER_INTERPRETERS: &[(&str, &[&str])] =
    &[("ruby", &["-e"]), ("perl", &["-e", "-E"]), ("php", &["-r"])];

/// Git options that take their value as the next word.
const GIT_VALUE_OPTIONS: &[&str] = &["-C", "-c", "--git-dir", "--work-tree", "--namespace"];

fn unquote(literal: &str) -> &str {
    &literal[1..literal.len() - 1]
}

fn literals(list: &str) -> Vec<String> {
    ONE_LITERAL
        .find_iter(list)
        .map(|found| unquote(found.as_str()).to_owned())
        .collect()
}

/// The command lines `code` spells: each literal list, each word array, and
/// each single literal read as a shell line split at its separators.
fn spelled_commands(code: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for captures in NAME_THEN_LIST.captures_iter(code) {
        let mut argv = vec![unquote(&captures[1]).to_owned()];
        argv.extend(literals(&captures[2]));
        commands.push(argv);
    }
    for captures in LITERAL_LIST.captures_iter(code) {
        commands.push(literals(&captures[1]));
    }
    for captures in WORD_ARRAY.captures_iter(code) {
        let words = (1..=4).find_map(|group| captures.get(group));
        if let Some(words) = words {
            commands.push(
                words
                    .as_str()
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
            );
        }
    }
    for found in ONE_LITERAL.find_iter(code) {
        for line in unquote(found.as_str()).split(['&', '|', ';', '\n']) {
            let words: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
            if !words.is_empty() {
                commands.push(words);
            }
        }
    }
    commands
}

fn is_git(word: &str) -> bool {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    matches!(name, "git" | "git.exe")
}

/// Whether a short-option cluster such as `-fdx` holds `letter`.
fn short_cluster_has(word: &str, letter: char) -> bool {
    word.strip_prefix('-')
        .is_some_and(|rest| !rest.starts_with('-') && rest.contains(letter))
}

/// Whether `argv` (a git invocation, starting at `git`) discards work.
fn discards_work(argv: &[String]) -> bool {
    let mut words = argv.iter().skip(1).map(String::as_str);
    let subcommand = loop {
        let Some(word) = words.next() else {
            return false;
        };
        if GIT_VALUE_OPTIONS.contains(&word) {
            words.next();
        } else if !word.starts_with('-') {
            break word;
        }
    };
    let rest: Vec<&str> = words.collect();
    let has = |flag: &str| rest.contains(&flag);
    match subcommand {
        "reset" => has("--hard") || has("--merge") || has("--keep"),
        "clean" => !rest
            .iter()
            .any(|word| *word == "--dry-run" || short_cluster_has(word, 'n')),
        "checkout" => {
            has("--")
                || has(".")
                || has("--force")
                || rest.iter().any(|word| short_cluster_has(word, 'f'))
        }
        "restore" => {
            let staged_only = rest
                .iter()
                .any(|word| *word == "--staged" || short_cluster_has(word, 'S'));
            let worktree = rest
                .iter()
                .any(|word| *word == "--worktree" || short_cluster_has(word, 'W'));
            !staged_only || worktree
        }
        "stash" => rest
            .first()
            .is_some_and(|verb| matches!(*verb, "drop" | "clear")),
        "branch" => rest.iter().any(|word| short_cluster_has(word, 'D')),
        _ => false,
    }
}

/// A literal naming a repository's `.git` directory: `.git`, `./.git`,
/// `repo/.git` or `.git/`.
static GIT_DIRECTORY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'`](?:[^"'`\s]*/)?\.git/?["'`]"#).unwrap());

/// Calls that remove a file or a directory tree.
static REMOVAL_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:rmSync|rmdirSync|rm_rf|rm_r|rmtree|remove_dir_all|remove_entry_secure|rmdir|rimraf|deleteSync|unlinkSync)\b").unwrap()
});

fn names_git_directory(word: &str) -> bool {
    let word = word.trim_end_matches('/');
    word == ".git" || word.ends_with("/.git")
}

/// Whether a spelled `rm` line removes a `.git` directory.
fn removes_git_directory(argv: &[String]) -> bool {
    argv.first()
        .is_some_and(|word| word.rsplit('/').next() == Some("rm"))
        && argv.iter().skip(1).any(|word| names_git_directory(word))
}

/// Whether program source `code` spells a git command that discards work, or
/// removes a repository's `.git` directory.
pub(super) fn spells_destructive_git(code: &str) -> bool {
    if REMOVAL_CALL.is_match(code) && GIT_DIRECTORY.is_match(code) {
        return true;
    }
    // Only a line that starts with the command counts, so a message that
    // mentions one ("run git reset --hard to undo") is not read as running it.
    spelled_commands(code).iter().any(|argv| {
        removes_git_directory(argv)
            || (argv.first().is_some_and(|word| is_git(word)) && discards_work(argv))
    })
}

/// Inline source given to an interpreter the shared program reader does not
/// model (`ruby -e`, `perl -e`, `php -r`).
fn other_inline_sources(model: &CanonicalCommandV1, context: PathContext<'_>) -> Vec<String> {
    let Some((_, segments)) = structure(model, context) else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    for segment in &segments {
        let Some(executable) = segment.executable.as_deref() else {
            continue;
        };
        let name = super::super::executable_basename(executable);
        let name = name.strip_suffix(".exe").unwrap_or(name);
        let Some((_, options)) = OTHER_INTERPRETERS
            .iter()
            .find(|(interpreter, _)| name == *interpreter)
        else {
            continue;
        };
        let mut words = segment.arguments.iter();
        while let Some(word) = words.next() {
            if options.contains(&word.as_str()) {
                if let Some(source) = words.next() {
                    sources.push(source.clone());
                }
            }
        }
    }
    sources
}

fn programs_spell_destructive_git(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    let modeled = assess_programs(model, context, false).iter().any(|found| {
        found.sources.iter().any(|source| {
            // The language is not kept with the source, so a command counts
            // only when it survives both comment styles being removed.
            spells_destructive_git(&code_lines(Language::Python, source))
                && spells_destructive_git(&code_lines(Language::Node, source))
        })
    });
    modeled
        || other_inline_sources(model, context)
            .iter()
            .any(|source| spells_destructive_git(source))
}

/// Whether an inline program the POSIX shell text `command` launches spells a
/// git command that discards work, for a caller that judges a projection with
/// the program's heredoc or input redirect removed.
pub(in crate::pretool) fn text_spells_destructive_git(
    command: &str,
    context: PathContext<'_>,
) -> bool {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .is_ok_and(|model| programs_spell_destructive_git(&model, context))
}

/// Keeps the review of a command whose inline program runs a git command
/// that discards work.
pub(in crate::pretool) fn keeps_destructive_git_review(
    result: &mut PreToolResultV1,
    model: &CanonicalCommandV1,
    command_text: Option<&str>,
    context: PathContext<'_>,
) -> bool {
    let spelled = |model: &CanonicalCommandV1| programs_spell_destructive_git(model, context);
    if !spelled(model) && !sent_model(model, command_text).is_some_and(|sent| spelled(&sent)) {
        return false;
    }
    result.reason = concat!(
        "HOL Guard needs your review because this program runs a git command ",
        "that discards uncommitted work, which Guard's sandbox does not protect."
    )
    .into();
    true
}

#[cfg(test)]
#[path = "destructive_git_tests.rs"]
mod tests;
