//! What changed in the project since a session's first prompt, for a prompt
//! that asks about changes: each changed file with the definitions or
//! sections the changes fall in, at their current lines, then each commit
//! made since that prompt, newest first. An agent reviewing a teammate's push
//! opens those lines instead of running `git` and reading each file. A small
//! commit's diff is shown too when the prompt is about someone else's push or
//! a failure, since then the diff itself is what the agent needs; otherwise
//! the agent made the changes and already has them in its session.
//!
//! This is the one part of prompt context that runs a program. Only a Git
//! Guard trusts runs (never one from the project, the home folder or a temp
//! folder), with no environment besides `PATH`, so no global configuration,
//! and with flags that keep repository configuration from starting other
//! programs: no external diff, textconv, signature check, fsmonitor, pager
//! or optional lock. Comparing the working tree runs clean filters, so the
//! uncommitted part is left out when the repository configures a filter. Git
//! runs offline: no transport is allowed and a partial clone fetches nothing,
//! so a part whose objects are not on disk is left out. Every
//! changed file goes through the checks Guard's own read applies, and a file
//! that fails them is left out. The diff holds lines no file has any more, so
//! each part shown and each commit subject is also scanned for secrets, and
//! one that has any is left out.
use super::seen::Session;
use crate::context_assistance_engine::screened_texts;
use crate::git_execution_safety_binary::resolve_trusted_git;
use crate::git_execution_safety_config::Environment;
use crate::git_execution_safety_probe::Prober;
use labels::{render, Commit};
use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The most this note adds to a prompt, commit diffs included.
const BUDGET: usize = 2_000;
/// The longest commit diff shown.
const MAX_SHOWN_DIFF: usize = 1_500;
const MAX_COMMITS: &str = "8";
const MAX_SUBJECT_CHARS: usize = 80;
const MAX_SESSIONS: usize = 64;
/// A Git call starts only with at least this much of the wait left.
const MIN_LEFT: Duration = Duration::from_millis(150);
/// The longest one secret scan of a part or subject may take.
const SCAN_TIME: Duration = Duration::from_millis(50);
const GLOBAL: [&str; 4] = [
    "--no-pager",
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
];
const DIFF: [&str; 7] = [
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "--no-relative",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--ignore-submodules=all",
];
const WORDS: [&str; 8] = [
    "change", "changed", "changes", "pushed", "teammate", "review", "diff", "broke",
];
/// Words for a prompt about a change the agent did not make, or one that
/// broke something: then a commit's own diff is worth showing.
const OTHERS: [&str; 5] = ["teammate", "pushed", "broke", "broken", "failing"];

/// Whether `prompt` asks about what changed.
pub(super) fn about_changes(prompt: &str) -> bool {
    let lower = prompt.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    words
        .iter()
        .any(|word| WORDS.contains(word) || word.starts_with("regress"))
        || words.windows(2).any(|pair| pair == ["this", "session"])
}

/// Whether `prompt` is about someone else's change or a failure.
pub(super) fn about_others(prompt: &str) -> bool {
    prompt
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| {
            OTHERS.contains(&word) || word.starts_with("fail") || word.starts_with("regress")
        })
}

/// Records the commit `session` started at, on its first prompt, and for a
/// prompt about changes returns what changed since then.
pub(super) fn since_start(
    guard_home: &Path,
    home: &Path,
    root: &Path,
    app: &str,
    session: Option<&Session>,
    prompt: &str,
    until: Instant,
) -> Option<String> {
    let mut git = None;
    let mut base = session.and_then(recorded);
    if let (Some(session), None) = (session, &base) {
        git = Git::find(root, home);
        base = git.as_ref().and_then(|git| started(session, git, until));
    }
    if !about_changes(prompt) {
        return None;
    }
    let git = git.or_else(|| Git::find(root, home))?;
    changes(
        &git,
        base.as_deref(),
        about_others(prompt),
        until,
        |paths| screened_texts(guard_home, root, app, paths, paths.len(), until),
    )
}

/// A trusted Git, run in one project with a bare environment.
pub(super) struct Git {
    path: PathBuf,
    root: PathBuf,
    environment: Environment,
}

impl Git {
    pub(super) fn find(root: &Path, home: &Path) -> Option<Self> {
        let mut environment = Environment::new();
        if let Ok(path) = std::env::var("PATH") {
            environment.insert("PATH".into(), path);
        }
        let path = resolve_trusted_git(root, &environment, home, groups()?)?;
        Some(Self {
            path,
            root: root.to_path_buf(),
            environment,
        })
    }

    fn run(&self, arguments: &[&str], until: Instant) -> Option<String> {
        if until.saturating_duration_since(Instant::now()) < MIN_LEFT {
            return None;
        }
        let all: Vec<&str> = GLOBAL.iter().chain(arguments).copied().collect();
        let prober = Prober {
            git: &self.path,
            cwd: &self.root,
            environment: &self.environment,
        };
        let output = prober.run_offline(&all)?;
        output
            .success()
            .then(|| output.text().map(str::to_owned))
            .flatten()
    }
}

fn groups() -> Option<&'static [u32]> {
    static GROUPS: OnceLock<Option<Vec<u32>>> = OnceLock::new();
    GROUPS.get_or_init(crate::edge_git_push::groups).as_deref()
}

type Bases = Mutex<VecDeque<(Session, String)>>;

fn bases() -> &'static Bases {
    static BASES: OnceLock<Bases> = OnceLock::new();
    BASES.get_or_init(Default::default)
}

/// The commit `session` started at, recorded on its first prompt. Only this
/// process remembers, for a bounded number of sessions.
fn started(session: &Session, git: &Git, until: Instant) -> Option<String> {
    if let Some(base) = recorded(session) {
        return Some(base);
    }
    let head = git.run(&["rev-parse", "--verify", "--quiet", "HEAD"], until)?;
    let head = head.trim();
    if !commit_id(head) {
        return None;
    }
    let mut bases = bases().lock().ok()?;
    if let Some((_, base)) = bases.iter().find(|(known, _)| known == session) {
        return Some(base.clone());
    }
    while bases.len() >= MAX_SESSIONS {
        bases.pop_front();
    }
    bases.push_back((session.clone(), head.to_owned()));
    Some(head.to_owned())
}

fn recorded(session: &Session) -> Option<String> {
    let bases = bases().lock().ok()?;
    bases
        .iter()
        .find(|(known, _)| known == session)
        .map(|(_, base)| base.clone())
}

fn commit_id(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// What the repository's configuration lets this read do.
#[derive(Debug, PartialEq)]
enum Allowed {
    Nothing,
    CommitsOnly,
    Everything,
}

fn allowed(git: &Git, until: Instant) -> Allowed {
    let listed = [
        "config",
        "--list",
        "--includes",
        "--show-scope",
        "--name-only",
    ];
    let Some(names) = git.run(&listed, until) else {
        return Allowed::Nothing;
    };
    // A filter the administrator configured is a program they installed; one
    // the repository configures is not.
    let names: Vec<String> = names
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(scope, _)| *scope != "system")
        .map(|(_, name)| name.to_ascii_lowercase())
        .collect();
    if names.iter().any(|name| name.starts_with("filter.")) {
        Allowed::CommitsOnly
    } else {
        Allowed::Everything
    }
}

/// One changed part of one file: where it starts in the new text, and its
/// lines without the `@@` header.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Hunk {
    pub(super) path: String,
    pub(super) start: usize,
    pub(super) body: String,
}

/// The changed parts of a unified diff. Line counts in each `@@` header end
/// the part, so a removed line that reads like a file header stays in it.
/// Deleted files, quoted names and combined merge diffs give nothing.
pub(super) fn hunks(diff: &str) -> Vec<Hunk> {
    let mut found = Vec::new();
    let mut path: Option<String> = None;
    let mut left = (0usize, 0usize);
    let mut current: Option<Hunk> = None;
    for line in diff.lines() {
        if let Some(hunk) = current.as_mut() {
            if consumed(&mut left, line) {
                hunk.body.push_str(line);
                hunk.body.push('\n');
                continue;
            }
            found.extend(current.take());
        }
        if line.starts_with("diff --git ") {
            path = None;
        } else if let Some(name) = line.strip_prefix("+++ ") {
            path = name
                .strip_prefix("b/")
                .filter(|name| !name.starts_with('"'))
                .map(str::to_owned);
        } else if let (Some(path), Some(header)) = (&path, line.strip_prefix("@@ -")) {
            if let Some((counts, start)) = header_counts(header) {
                left = counts;
                current = Some(Hunk {
                    path: path.clone(),
                    start,
                    body: String::new(),
                });
            }
        }
    }
    found.extend(current);
    found
}

/// Whether `line` belongs to the part being read, with `left` the old and
/// new lines it still holds; a no-newline marker always does.
fn consumed(left: &mut (usize, usize), line: &str) -> bool {
    match line.as_bytes().first() {
        Some(b'\\') => true,
        _ if *left == (0, 0) => false,
        Some(b' ') | None => {
            *left = (left.0.saturating_sub(1), left.1.saturating_sub(1));
            true
        }
        Some(b'-') => {
            left.0 = left.0.saturating_sub(1);
            true
        }
        Some(b'+') => {
            left.1 = left.1.saturating_sub(1);
            true
        }
        Some(_) => false,
    }
}

/// The old and new line counts and the new start of `-a,b +c,d @@`.
fn header_counts(header: &str) -> Option<((usize, usize), usize)> {
    let (old, rest) = header.split_once(" +")?;
    let (new, _) = rest.split_once(" @@")?;
    let count = |range: &str| -> Option<(usize, usize)> {
        match range.split_once(',') {
            Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
            None => Some((range.parse().ok()?, 1)),
        }
    };
    let (_, old_count) = count(old)?;
    let (new_start, new_count) = count(new)?;
    Some(((old_count, new_count), new_start))
}

/// The changed definitions of each file changed since `base`, uncommitted
/// edits included, then each commit since `base`, newest first, with its
/// diff when `show_diffs` and it is small. `screen` returns the text of each
/// changed file Guard's read accepts; any other file is left out.
pub(super) fn changes(
    git: &Git,
    base: Option<&str>,
    show_diffs: bool,
    until: Instant,
    screen: impl FnOnce(&[String]) -> Vec<(String, String)>,
) -> Option<String> {
    let allowed = allowed(git, until);
    if allowed == Allowed::Nothing {
        return None;
    }
    let base = base.filter(|base| commit_id(base));
    // Comparing the working tree runs clean filters; with one configured,
    // only the commits are compared.
    let against: Vec<&str> = match (&allowed, base) {
        (Allowed::Everything, Some(base)) => vec![base],
        (Allowed::Everything, None) => vec!["HEAD"],
        (_, Some(base)) => vec![base, "HEAD"],
        (_, None) => Vec::new(),
    };
    let mut changed = Vec::new();
    if !against.is_empty() {
        let diff: Vec<&str> = ["diff", "-U0"]
            .into_iter()
            .chain(DIFF)
            .chain(against)
            .collect();
        if let Some(diff) = git.run(&diff, until) {
            changed = hunks(&diff);
        }
    }
    let commits = commits(git, base, until);
    let paths: Vec<String> = changed
        .iter()
        .map(|hunk| hunk.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let texts = if paths.is_empty() {
        Vec::new()
    } else {
        screen(&paths)
    };
    let mut listed: Vec<Commit> = Vec::new();
    let mut used = 0;
    for (commit, subject) in commits {
        let mut diff = None;
        if show_diffs && used < BUDGET {
            let show: Vec<&str> = ["show", "--format=", "--no-show-signature", "-U1"]
                .into_iter()
                .chain(DIFF)
                .chain([commit.as_str()])
                .collect();
            // Out of time, `run` returns at once.
            diff = git
                .run(&show, until)
                .filter(|diff| diff.len() <= MAX_SHOWN_DIFF && used + diff.len() <= BUDGET)
                .filter(|diff| shown_files(diff, &texts) && clean(diff));
            used += diff.as_ref().map_or(0, String::len);
        }
        listed.push(Commit {
            id: commit,
            subject,
            diff,
        });
    }
    render(base, &changed, &texts, &listed)
}

/// Whether every file `diff` changes is one Guard's read accepted.
fn shown_files(diff: &str, texts: &[(String, String)]) -> bool {
    let changed = hunks(diff);
    !changed.is_empty()
        && changed
            .iter()
            .all(|hunk| texts.iter().any(|(path, _)| *path == hunk.path))
}

/// The commits since `base`, newest first, leaving out merges.
fn commits(git: &Git, base: Option<&str>, until: Instant) -> Vec<(String, String)> {
    let Some(base) = base.filter(|base| commit_id(base)) else {
        return Vec::new();
    };
    let range = format!("{base}..HEAD");
    let log = [
        "log",
        "--no-show-signature",
        "--no-color",
        "--no-merges",
        "--format=%H %s",
        "-n",
        MAX_COMMITS,
        range.as_str(),
    ];
    let Some(listed) = git.run(&log, until) else {
        return Vec::new();
    };
    listed
        .lines()
        .filter_map(|line| {
            let (commit, subject) = line.split_once(' ').unwrap_or((line, ""));
            commit_id(commit).then(|| {
                let subject: String = subject
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_SUBJECT_CHARS)
                    .collect();
                let subject = if clean(&subject) {
                    subject
                } else {
                    String::new()
                };
                (commit.to_owned(), subject)
            })
        })
        .collect()
}

/// Whether Guard's secret scan finds nothing in `text`, having read it all.
fn clean(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let scan = guard_scanner::scan_text(
        text,
        true,
        false,
        text.len(),
        Some(Instant::now() + SCAN_TIME),
    );
    !scan.budget_exhausted && scan.bytes_scanned == text.len() && scan.matches.is_empty()
}

#[path = "context_assistance_prompt_changes_labels.rs"]
mod labels;

#[cfg(test)]
#[path = "context_assistance_prompt_changes_tests.rs"]
mod tests;
