//! What changed in the project since a session's first prompt, for a prompt
//! that asks about changes: each changed file with the definitions or
//! sections the changes fall in, at their current lines, then each commit
//! made since that prompt, newest first, and the whole diff when it is small.
//! An agent reviewing changes reads them here instead of running `git` and
//! reading each file. When the whole diff is too big, a small commit's diff is
//! shown when the prompt is about someone else's push or a failure.
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
use labels::{commits, render, uncommitted, Commit, Named, Since};
use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
pub(super) use used::Changed;

/// The most this note adds to a prompt, commit diffs included.
const BUDGET: usize = 2_000;
/// The longest commit diff shown.
const MAX_SHOWN_DIFF: usize = 1_500;
const MAX_SESSIONS: usize = 64;
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
const WORDS: &str =
    "change changed changes pushed teammate review diff broke commit commits committed recently";
/// Words for a prompt about a change the agent did not make, or one that
/// broke something: then a commit's own diff is worth showing.
const OTHERS: [&str; 5] = ["teammate", "pushed", "broke", "broken", "failing"];

/// Words that, just before a change word, say there is none to look at.
const NOT: [&str; 5] = ["no", "not", "without", "don", "dont"];

/// Whether `prompt` asks about what changed.
pub(super) fn about_changes(prompt: &str) -> bool {
    let lower = prompt.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    // "no code changes" or "don't change anything" rules changes out.
    let denied = |at: usize| {
        words[at.saturating_sub(2)..at]
            .iter()
            .any(|word| NOT.contains(word))
    };
    (words.iter().enumerate()).any(|(at, word)| {
        (WORDS.split(' ').any(|known| known == *word) || word.starts_with("regress")) && !denied(at)
    }) || words.windows(2).any(|pair| pair == ["this", "session"])
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
/// prompt about changes returns what changed since then. A prompt about
/// someone else's change or a failure gets the newest commit instead: what
/// was just pulled or pushed, not the session's own edits, which the agent
/// made and already holds.
pub(super) fn since_start(
    guard_home: &Path,
    home: &Path,
    root: &Path,
    app: &str,
    session: Option<&Session>,
    prompt: &str,
    until: Instant,
) -> Option<Changed> {
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
    let parent = newest(&git, prompt, until);
    let since = match (&parent, &base) {
        (Some(parent), _) => Since::Newest(parent),
        (None, Some(base)) => Since::Start(base),
        (None, None) => Since::Nothing,
    };
    changes(&git, since, about_others(prompt), until, |paths| {
        screened_texts(guard_home, root, app, paths, paths.len(), until)
    })
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

    /// Runs `git` with `arguments` while the note's share of the wait lasts.
    /// A call that starts is bounded by Git's own timeout. The share is short,
    /// so asking for part of it to be left let only the first calls start.
    fn run(&self, arguments: &[&str], until: Instant) -> Option<String> {
        if Instant::now() >= until {
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

/// The newest commit's parent, for a prompt about someone else's change or
/// a failure.
fn newest(git: &Git, prompt: &str, until: Instant) -> Option<String> {
    if !about_others(prompt) {
        return None;
    }
    let parent = git.run(&["rev-parse", "--verify", "--quiet", "HEAD^"], until)?;
    Some(parent.trim().to_owned()).filter(|parent| commit_id(parent))
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
/// edits included, then each commit since `base`, newest first, then the
/// whole diff when it is small, or else each commit's when `show_diffs`.
/// `screen` returns the text of each file Guard's read accepts; any other
/// file is left out, and counted rather than named.
pub(super) fn changes(
    git: &Git,
    since: Since,
    show_diffs: bool,
    until: Instant,
    screen: impl FnOnce(&[String]) -> Vec<(String, String)>,
) -> Option<Changed> {
    let allowed = allowed(git, until);
    if allowed == Allowed::Nothing {
        return None;
    }
    let since = since.checked();
    let base = since.base();
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
            .chain(against.iter().copied())
            .collect();
        if let Some(diff) = git.run(&diff, until) {
            changed = hunks(&diff);
        }
    }
    let commits = commits(git, base, until);
    // Which changes are committed is what an agent runs `git status` for.
    let pending = (allowed == Allowed::Everything && !commits.is_empty())
        .then(|| uncommitted(git, until))
        .flatten();
    let paths: BTreeSet<&str> = changed.iter().map(|hunk| hunk.path.as_str()).collect();
    // A file a commit or the working tree changes back is named too, when
    // Guard's read accepts it.
    let listed_names: BTreeSet<&String> =
        (commits.iter()).flat_map(|(_, _, names)| names).collect();
    let named: Vec<String> = (paths.iter().copied())
        .chain(
            commits
                .iter()
                .flat_map(|(_, _, names)| names.iter().map(String::as_str)),
        )
        .chain(pending.iter().flatten().map(String::as_str))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let read = if named.is_empty() {
        Vec::new()
    } else {
        screen(&named)
    };
    let readable: Vec<&str> = read.iter().map(|(path, _)| path.as_str()).collect();
    // Seen only in commits, a change that was undone reads as a leftover.
    let back: Vec<String> = (named.iter())
        .filter(|name| !paths.contains(name.as_str()) && listed_names.contains(*name))
        .cloned()
        .collect();
    let texts: Vec<(String, String)> = (read.iter())
        .filter(|(path, _)| paths.contains(path.as_str()))
        .cloned()
        .collect();
    let whole = labels::whole(git, &against, &texts, until);
    let mut listed: Vec<Commit> = Vec::new();
    let mut used = 0;
    for (commit, subject, names) in commits {
        let mut diff = None;
        if show_diffs && whole.is_none() && used < BUDGET {
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
            files: Named::new(&names, &readable),
            diff,
        });
    }
    let pending = pending.map(|names| Named::new(&names, &readable));
    let back = (!against.is_empty() && !back.is_empty()).then(|| Named::new(&back, &readable));
    let text = render(
        since,
        &changed,
        &texts,
        &listed,
        [pending.as_ref(), back.as_ref()],
        whole.as_ref(),
    )?;
    let names = used::names(&changed, &texts);
    Some(Changed { text, names })
}

/// Whether every file `diff` changes is one Guard's read accepted. A file
/// with a header but no part read here (deleted, binary, renamed, a quoted
/// name or a mode change) was never screened, so its diff is not shown.
fn shown_files(diff: &str, texts: &[(String, String)]) -> bool {
    let changed = hunks(diff);
    let headers = (diff.lines())
        .filter(|line| line.starts_with("diff --git "))
        .count();
    let paths: BTreeSet<&str> = changed.iter().map(|hunk| hunk.path.as_str()).collect();
    !paths.is_empty()
        && headers == paths.len()
        && (paths.iter()).all(|changed| texts.iter().any(|(path, _)| path == changed))
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

#[path = "context_assistance_prompt_changes_code.rs"]
mod code;
#[path = "context_assistance_prompt_changes_labels.rs"]
mod labels;
#[path = "context_assistance_prompt_changes_used.rs"]
pub(super) mod used;

#[cfg(test)]
#[path = "context_assistance_prompt_changes_tests.rs"]
mod tests;
