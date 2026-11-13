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

use super::{assess_programs, sent_model, structure, Language, PathContext};
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

/// Two or more literals joined into one string: by `+` (Python, Node,
/// Ruby), `.` or `..` (PHP, Perl, Lua), or by Python's implicit
/// concatenation of adjacent literals.
static CONCATENATED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"{LITERAL}(?:\s*(?:\+|\.\.?)?\s*{LITERAL})+")).unwrap());

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
    let joined = CONCATENATED
        .find_iter(code)
        .map(|found| literals(found.as_str()).concat());
    let single = ONE_LITERAL
        .find_iter(code)
        .map(|found| unquote(found.as_str()).to_owned());
    for text in joined.chain(single) {
        for line in text.split(['&', '|', ';', '\n']) {
            let words = shell_words(line);
            if !words.is_empty() {
                commands.push(words);
            }
        }
    }
    commands
}

/// The words of one shell command line with its quotes removed, so
/// `git -C 'my repo' reset --hard` names the directory `my repo`.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => word.push(ch),
            None if matches!(ch, '\'' | '"') => {
                quote = Some(ch);
                started = true;
            }
            None if ch.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            None => {
                word.push(ch);
                started = true;
            }
        }
    }
    if started {
        words.push(word);
    }
    words
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
            // `git checkout <tree> <path>` replaces the path from the tree,
            // and `git checkout src/app.py` restores a file from the index.
            // A lone bare word is read as a branch switch, which keeps local
            // edits; one shaped like a path (a dot, a slash, a glob or a
            // `:` pathspec) may name a file, so it keeps its review.
            let creates_branch = rest.iter().any(|word| {
                matches!(*word, "-b" | "-B" | "--orphan") || word.starts_with("--orphan=")
            });
            let operands: Vec<&str> = rest
                .iter()
                .copied()
                .filter(|word| !word.starts_with('-'))
                .collect();
            let path_shaped =
                |word: &str| word.starts_with(':') || word.contains(['.', '/', '*', '?', '[']);
            has("--")
                || has(".")
                || has("--force")
                || rest.iter().any(|word| short_cluster_has(word, 'f'))
                || (!creates_branch
                    && (operands.len() >= 2 || operands.iter().any(|word| path_shaped(word))))
        }
        "switch" => rest.iter().any(|word| {
            matches!(*word, "--discard-changes" | "--force") || short_cluster_has(word, 'f')
        }),
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
pub(super) fn other_inline_sources(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Vec<String> {
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

/// `source` with each comment that starts outside a string literal removed:
/// `#` comments for Python, `//` and `/* */` comments for Node. A marker
/// inside a quoted string is kept, so `os.system("git reset --hard # note")`
/// still reads the whole command.
///
/// String state carries across lines. A Python triple-quoted string or a
/// backtick template stays open over line ends, and an escaped line end joins
/// the next line, as the interpreter does. A string that spans lines is
/// written back as one `"`-quoted line (inner `"` as `'`, line ends as `;`)
/// so the one-line literal readers pair its quotes the way the interpreter
/// does and still see each command inside it.
pub(super) fn without_comments(language: Language, source: &str) -> String {
    let mut code = String::with_capacity(source.len());
    let mut quote: Option<&'static str> = None;
    let mut in_block = false;
    let mut in_line_comment = false;
    let mut chars = source.char_indices();
    while let Some((at, ch)) = chars.next() {
        let rest = &source[at..];
        if let Some(close) = quote {
            let spans_lines = close.len() == 3 || close == "`";
            if ch == '\\' {
                match chars.next() {
                    // A line continuation inside a string adds nothing.
                    Some((_, '\n')) => {}
                    Some((_, '"')) if spans_lines => code.push_str("\\'"),
                    Some((_, escaped)) => {
                        code.push(ch);
                        code.push(escaped);
                    }
                    None => code.push(ch),
                }
            } else if rest.starts_with(close) {
                code.push_str(if spans_lines { "\"" } else { close });
                // Delimiters are ASCII, one char per byte.
                for _ in 1..close.len() {
                    chars.next();
                }
                quote = None;
            } else if spans_lines {
                code.push(match ch {
                    '\n' => ';',
                    '"' => '\'',
                    other => other,
                });
            } else if ch == '\n' {
                // A one-quote string cannot span a bare line end.
                quote = None;
                code.push(ch);
            } else {
                code.push(ch);
            }
            continue;
        }
        if ch == '\n' {
            in_line_comment = false;
            code.push(ch);
            continue;
        }
        if in_line_comment {
            continue;
        }
        if in_block {
            if rest.starts_with("*/") {
                chars.next();
                in_block = false;
            }
            continue;
        }
        match language {
            Language::Python if ch == '#' => {
                in_line_comment = true;
                continue;
            }
            Language::Node if rest.starts_with("//") => {
                in_line_comment = true;
                continue;
            }
            Language::Node if rest.starts_with("/*") => {
                chars.next();
                in_block = true;
                continue;
            }
            _ => {}
        }
        let opened = match ch {
            '"' if language == Language::Python && rest.starts_with("\"\"\"") => Some("\"\"\""),
            '\'' if language == Language::Python && rest.starts_with("'''") => Some("'''"),
            '"' => Some("\""),
            '\'' => Some("'"),
            '`' => Some("`"),
            _ => None,
        };
        if let Some(open) = opened {
            let spans_lines = open.len() == 3 || open == "`";
            code.push_str(if spans_lines { "\"" } else { open });
            for _ in 1..open.len() {
                chars.next();
            }
            quote = Some(open);
            continue;
        }
        code.push(ch);
    }
    code
}

fn programs_spell_destructive_git(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    let modeled = assess_programs(model, context, false).iter().any(|found| {
        found.sources.iter().any(|source| match found.language {
            Some(language) => spells_destructive_git(&without_comments(language, source)),
            None => spells_destructive_git(source),
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
