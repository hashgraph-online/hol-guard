//! Text a Git search matches: `git grep` patterns, the `-S`, `-G` and
//! `--grep` values of `git log`, and the `--match` and `--exclude` ref globs
//! of `git describe`. Git compares them against content, messages and ref
//! names and never opens them, so a pattern such as `process.env`, `.ssh/`
//! or `v*` names no path. Every other token still meets the sensitive-text
//! and path screens, and a credential keyword in a pattern still reads as a
//! credential search.

use crate::{CanonicalCommandV1, CommandSegmentV1};

/// Positions in `arguments`, the tokens after `git`, that hold search text
/// or the closed `git grep` options around it.
pub(super) fn pattern_positions(arguments: &[String]) -> Vec<usize> {
    let Some(start) = subcommand_position(arguments) else {
        return Vec::new();
    };
    let rest = &arguments[start + 1..];
    let positions = match arguments[start].as_str() {
        "grep" => grep_patterns(rest),
        "log" => log_patterns(rest),
        "describe" => super::git_history_reads::describe_pattern_positions(rest),
        _ => Vec::new(),
    };
    positions
        .into_iter()
        .map(|position| position + start + 1)
        .collect()
}

/// Whether `text`, the whole command or one of its segments, trips the
/// sensitive-text floor. `without_patterns` is the same text with its Git
/// search patterns left out: only a credential keyword in a pattern counts.
pub(super) fn sensitive_beyond_patterns(text: &str, without_patterns: Option<String>) -> bool {
    match without_patterns {
        Some(rest) => super::credential_keyword_text(text) || super::sensitive_command(&rest),
        None => super::sensitive_command(text),
    }
}

/// The command's text with each Git search pattern left out, or `None` when
/// no segment holds one.
pub(super) fn command_without_patterns(model: &CanonicalCommandV1) -> Option<String> {
    let mut masked = false;
    let parts = model
        .segments
        .iter()
        .map(|segment| match segment_without_patterns(segment) {
            Some(text) => {
                masked = true;
                text
            }
            None => segment.text.clone(),
        })
        .collect::<Vec<_>>();
    masked.then(|| parts.join(" ; "))
}

/// One segment's tokens with its Git search patterns left out, or `None`
/// when it is not a plain `git` search holding a pattern.
pub(super) fn segment_without_patterns(segment: &CommandSegmentV1) -> Option<String> {
    let executable = segment.executable.as_deref()?;
    if super::executable_basename(executable) != "git"
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.tokens.len() != segment.arguments.len() + 1
    {
        return None;
    }
    let positions = pattern_positions(&segment.arguments);
    if positions.is_empty() {
        return None;
    }
    let kept = segment
        .arguments
        .iter()
        .enumerate()
        .filter(|(index, _)| !positions.contains(index))
        .map(|(_, argument)| argument.as_str());
    Some(
        std::iter::once(segment.tokens[0].as_str())
            .chain(kept)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn subcommand_position(arguments: &[String]) -> Option<usize> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" => index += 2,
            value if value.starts_with('-') => index += 1,
            _ => return Some(index),
        }
    }
    None
}

/// Everything before the revisions and pathspecs of a `git grep` inside the
/// closed grammar: closed options, counts and patterns.
fn grep_patterns(rest: &[String]) -> Vec<usize> {
    super::git_grep::targets(rest).map_or_else(Vec::new, |targets| {
        (0..rest.len() - targets.len()).collect()
    })
}

/// `git log` options that take the next token as their value.
const LOG_VALUE_OPTIONS: &[&str] = &[
    "-n",
    "--max-count",
    "--skip",
    "--since",
    "--after",
    "--until",
    "--before",
    "--author",
    "--committer",
];

/// `git log` options that take no value.
const LOG_FLAGS: &[&str] = &[
    "--oneline",
    "--all",
    "-p",
    "-u",
    "--patch",
    "-s",
    "--no-patch",
    "--stat",
    "--shortstat",
    "--numstat",
    "--name-only",
    "--name-status",
    "--graph",
    "--reverse",
    "--follow",
    "--merges",
    "--no-merges",
    "--first-parent",
    "--abbrev-commit",
    "--decorate",
    "--no-decorate",
    "--color",
    "--no-color",
    "-i",
    "--regexp-ignore-case",
    "-E",
    "--extended-regexp",
    "-F",
    "--fixed-strings",
    "--all-match",
    "--invert-grep",
    "--pickaxe-all",
    "--pickaxe-regex",
];

/// `git log` options whose value is attached after `=`.
const LOG_ATTACHED: &[&str] = &[
    "--format=",
    "--pretty=",
    "--date=",
    "--decorate=",
    "--max-count=",
    "--skip=",
    "--since=",
    "--after=",
    "--until=",
    "--before=",
    "--author=",
    "--committer=",
];

/// The `-S`, `-G` and `--grep` values before `--`. Every option must belong
/// to the closed grammar above: an option this does not know might take the
/// next token as its value, so the command's tokens keep every screen.
fn log_patterns(rest: &[String]) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut index = 0;
    while let Some(argument) = rest.get(index) {
        let value = argument.as_str();
        if value == "--" {
            break;
        }
        if matches!(value, "-S" | "-G" | "--grep") {
            if index + 1 < rest.len() {
                positions.push(index + 1);
            }
            index += 2;
            continue;
        }
        if LOG_VALUE_OPTIONS.contains(&value) {
            index += 2;
            continue;
        }
        if (value.len() > 2 && (value.starts_with("-S") || value.starts_with("-G")))
            || value.starts_with("--grep=")
        {
            positions.push(index);
        } else if value.starts_with('-') && !log_option(value) {
            return Vec::new();
        }
        index += 1;
    }
    positions
}

fn log_option(value: &str) -> bool {
    let count = value
        .strip_prefix("-n")
        .or_else(|| value.strip_prefix('-'))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));
    count
        || LOG_FLAGS.contains(&value)
        || LOG_ATTACHED.iter().any(|prefix| value.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::pattern_positions;

    fn positions(command: &str) -> Vec<usize> {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        pattern_positions(&arguments)
    }

    #[test]
    fn grep_patterns_and_log_search_values_are_found() {
        assert_eq!(positions("grep -n process.env -- src"), vec![1, 2]);
        assert_eq!(positions("-C repo grep -ln -e .env src"), vec![3, 4, 5]);
        assert_eq!(positions("log --oneline -S process.env -- a.ts"), vec![3]);
        assert_eq!(positions("log -G.env --grep=.ssh/ HEAD"), vec![1, 2]);
        assert_eq!(positions("log --grep .env -- .env"), vec![2]);
        assert_eq!(positions("log -5 --author me -n 3 -S .env"), vec![7]);
        assert_eq!(positions("log --since=2.weeks -S x --format=%h"), vec![3]);
        assert_eq!(positions("describe --match v* --dirty=-wip"), vec![2]);
        assert_eq!(
            positions("describe --match=v* --exclude nightly*"),
            vec![1, 3]
        );
        assert_eq!(
            positions("describe --tags --candidates 10 --match v*"),
            vec![5]
        );
    }

    #[test]
    fn paths_revisions_and_other_operations_keep_their_screens() {
        assert!(positions("grep -f .env -- src").is_empty());
        assert!(positions("grep --no-index .env").is_empty());
        assert!(positions("show HEAD:.env").is_empty());
        assert!(positions("log -p -- .env").is_empty());
        assert!(positions("diff -S .env").is_empty());
        assert!(positions("log -p --author -S .env").is_empty());
        assert!(positions("log --committer -G .env -p").is_empty());
        assert!(positions("log --output out -S x").is_empty());
        assert_eq!(positions("grep foo .env -- src"), vec![1]);
        assert!(positions("describe --tags HEAD").is_empty());
        assert!(positions("describe --textconv --match v*").is_empty());
        assert!(positions("describe --match").is_empty());
        assert_eq!(positions("describe --match v* -- .env"), vec![2]);
    }
}
