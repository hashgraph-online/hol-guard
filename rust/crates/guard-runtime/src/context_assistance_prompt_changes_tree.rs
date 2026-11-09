//! What `git status` and `git diff --check` add to the changes note: the
//! files Git does not track, and the whitespace errors in the changes. An
//! agent asked to review a session's changes ran both before anything else,
//! though the note already held the diff and the files not committed yet.
use super::labels::Named;
use super::{commit_id, Git, DIFF, GLOBAL, MIN_LEFT};
use crate::git_execution_safety_probe::{ProbeOutput, Prober};
use std::time::Instant;

/// The most untracked files read through Guard's screen; the rest are
/// counted.
pub(super) const MAX_UNTRACKED: usize = 8;
/// The most whitespace errors listed; the rest are counted.
const MAX_PROBLEMS: usize = 6;
const MAX_PROBLEM_CHARS: usize = 200;
/// How `git diff --check` words each error, after `path:line: `.
const PROBLEMS: [&str; 6] = [
    "trailing whitespace.",
    "space before tab in indent.",
    "indent with spaces.",
    "tab in indent.",
    "new blank line at EOF.",
    "leftover conflict marker",
];

impl Git {
    /// What Git prints for `arguments`, whatever its exit code.
    pub(super) fn output(&self, arguments: &[&str], until: Instant) -> Option<ProbeOutput> {
        if until.saturating_duration_since(Instant::now()) < MIN_LEFT {
            return None;
        }
        let all: Vec<&str> = GLOBAL.iter().chain(arguments).copied().collect();
        let prober = Prober {
            git: &self.path,
            cwd: &self.root,
            environment: &self.environment,
        };
        prober.run_offline(&all)
    }
}

/// The files Git does not track and does not ignore. A folder holding only
/// untracked files is one entry.
pub(super) fn untracked(git: &Git, until: Instant) -> Option<Vec<String>> {
    let listed = git.run(
        &[
            "ls-files",
            "--others",
            "--exclude-standard",
            "--directory",
            "--no-empty-directory",
        ],
        until,
    )?;
    Some(
        listed
            .lines()
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// Which files are untracked, and what `git diff --check` finds in the
/// changes against `against`. Untracked files and errors are
/// named only in files Guard's read accepted (`readable`); the others are
/// counted. Nothing is said of what Git could not tell.
pub(super) fn status(
    git: &Git,
    against: &[&str],
    untracked: Option<&[String]>,
    readable: &[&str],
    until: Instant,
) -> String {
    let mut out = String::new();
    if let Some(untracked) = untracked {
        let files = Named::new(untracked, readable).text();
        out.push_str(&if files.is_empty() {
            "\n\nUntracked files: none.".to_owned()
        } else {
            format!("\n\nUntracked files, in no diff here: {files}.")
        });
    }
    if let Some(check) = check(git, against, readable, until) {
        out.push_str(&check);
    }
    out
}

/// What `git diff --check` finds: a statement that it finds nothing, or the
/// errors by file and line, never the lines themselves.
fn check(git: &Git, against: &[&str], readable: &[&str], until: Instant) -> Option<String> {
    if against.is_empty() {
        return None;
    }
    let arguments: Vec<&str> = ["diff", "--check"]
        .into_iter()
        .chain(DIFF)
        .chain(against.iter().copied())
        .collect();
    let output = git.output(&arguments, until)?;
    let short: Vec<&str> = (against.iter())
        .map(|at| if commit_id(at) { &at[..7] } else { at })
        .collect();
    let command = format!("git diff --check {}", short.join(" "));
    let text = output.text()?;
    if output.success() {
        return text
            .is_empty()
            .then(|| format!("\n\n`{command}` finds no whitespace errors."));
    }
    // A content line starts with `+`; an error line with its path.
    let found: Vec<(&str, &str, &str)> = (text.lines())
        .filter(|line| !line.starts_with('+'))
        .filter_map(problem)
        .collect();
    if found.is_empty() || output.code.is_none() {
        return None;
    }
    let (shown, others): (Vec<_>, Vec<_>) =
        (found.into_iter()).partition(|(path, _, _)| readable.contains(path));
    let mut out = format!("\n\n`{command}` finds:");
    for (path, number, problem) in shown.iter().take(MAX_PROBLEMS) {
        let line: String = format!("{path}:{number}: {problem}")
            .chars()
            .take(MAX_PROBLEM_CHARS)
            .collect();
        out.push_str(&format!("\n{line}"));
    }
    let more = others.len() + shown.len().saturating_sub(MAX_PROBLEMS);
    if more > 0 {
        let errors = if more == 1 { "error" } else { "errors" };
        out.push_str(&format!("\n({more} more {errors} left out)"));
    }
    Some(out)
}

/// A `git diff --check` error line as path, line number and error.
fn problem(line: &str) -> Option<(&str, &str, &str)> {
    let error = PROBLEMS.into_iter().find(|error| line.ends_with(error))?;
    let place = line[..line.len() - error.len()].strip_suffix(": ")?;
    let (path, number) = place.rsplit_once(':')?;
    let digits = !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit());
    (digits && !path.is_empty()).then_some((path, number, error))
}
