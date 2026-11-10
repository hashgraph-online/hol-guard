//! For a definition left to be written that the map shows, what the commit
//! that wrote its stub took out there. Asked to write a body again after a
//! refactor, an agent searched the history for the old one and read it; the
//! note shows that commit's change in the definition instead.
//!
//! Git runs as for the changes note, on commits only, so no filter runs. A
//! stub written where nothing was, or one not committed yet, gets nothing.
//! The change and the commit's subject are scanned for secrets, and nothing
//! is shown when either has one.

use super::super::map::STUB_MARKS;
use super::super::seen::Span;
use super::super::Rendered;
use super::{clean, commit_id, hunks, Git, DIFF};
use crate::context_assistance_engine::screened_texts;
use crate::context_assistance_prompt_words::test_file;
use std::path::Path;
use std::time::Instant;

/// The longest change shown; a longer one is named with the command that
/// shows it.
const MAX_REMOVED_CHARS: usize = 2_400;
const MAX_SUBJECT_CHARS: usize = 100;
/// Files of the map read again to find a stub in the code it shows.
const MAX_FILES: usize = 4;

/// `rendered` with the change that wrote the first stub it shows, or as it
/// is when there is none, Git is not trusted, or `until` passes.
pub(in super::super) fn added(
    rendered: Rendered,
    guard_home: &Path,
    home: &Path,
    root: &Path,
    app: &str,
    until: Instant,
) -> Rendered {
    let mut paths: Vec<String> = Vec::new();
    for span in &rendered.shown {
        if !test_file(&span.path) && !paths.contains(&span.path) && paths.len() < MAX_FILES {
            paths.push(span.path.clone());
        }
    }
    if paths.is_empty() {
        return rendered;
    }
    let texts = screened_texts(guard_home, root, app, &paths, paths.len(), until);
    let Some(stub) = first_stub(&rendered.shown, &texts) else {
        return rendered;
    };
    let note = Git::find(root, home).and_then(|git| removed(&git, &stub, until));
    match note {
        Some(note) => Rendered {
            text: format!("{}\n\n{note}", rendered.text),
            shown: rendered.shown,
        },
        None => rendered,
    }
}

/// A stub line in code the map shows whole: its file, its line and text,
/// and the lines of the definition holding it.
pub(super) struct Stub {
    pub(super) path: String,
    pub(super) line: usize,
    pub(super) text: String,
    pub(super) start: usize,
    pub(super) end: usize,
}

pub(super) fn first_stub(shown: &[Span], texts: &[(String, String)]) -> Option<Stub> {
    shown.iter().find_map(|span| {
        let (_, text) = texts.iter().find(|(path, _)| *path == span.path)?;
        let lines: Vec<&str> = text.lines().collect();
        let (start, end) = (
            usize::try_from(span.start).ok()?,
            usize::try_from(span.end).ok()?,
        );
        (start.max(1)..=end.min(lines.len())).find_map(|line| {
            let text = lines[line - 1];
            STUB_MARKS
                .iter()
                .any(|mark| text.contains(mark))
                .then(|| Stub {
                    path: span.path.clone(),
                    line,
                    text: text.to_owned(),
                    start,
                    end,
                })
        })
    })
}

/// The note for `stub`: the commit that wrote its line, when that commit
/// also took lines out of the definition.
pub(super) fn removed(git: &Git, stub: &Stub, until: Instant) -> Option<String> {
    let range = format!("{0},{0}", stub.line);
    let blame = [
        "blame",
        "--porcelain",
        "--no-textconv",
        "-L",
        range.as_str(),
        "HEAD",
        "--",
        stub.path.as_str(),
    ];
    let blamed = Blamed::read(&git.run(&blame, until)?)?;
    // An edit not committed yet moved the line, or wrote it.
    if blamed.text != stub.text {
        return None;
    }
    let spec = format!(":(top,literal){}", blamed.path);
    let mut diff = vec!["diff"];
    diff.extend(DIFF);
    diff.extend([
        "-U0",
        "--no-renames",
        blamed.parent.as_str(),
        blamed.commit.as_str(),
    ]);
    diff.extend(["--", spec.as_str()]);
    let changed = git.run(&diff, until)?;
    // The definition's lines in the commit, from where the stub line was then.
    let then = |line: usize| (line + blamed.line).checked_sub(stub.line);
    let (start, end) = (then(stub.start)?, then(stub.end)?);
    let mut body = String::new();
    let mut taken = 0;
    for hunk in hunks(&changed)
        .into_iter()
        .filter(|hunk| hunk.path == blamed.path)
    {
        let added = hunk
            .body
            .lines()
            .filter(|line| line.starts_with('+'))
            .count();
        let last = hunk.start + added.max(1) - 1;
        if hunk.start > end || last + 1 < start {
            continue;
        }
        taken += hunk
            .body
            .lines()
            .filter(|line| line.starts_with('-'))
            .count();
        body.push_str(&hunk.body);
    }
    if taken == 0 || !clean(&body) {
        return None;
    }
    let subject: String = blamed.subject.chars().take(MAX_SUBJECT_CHARS).collect();
    if !clean(&subject) {
        return None;
    }
    let short = &blamed.commit[..12];
    let at = format!("{}:{}", stub.path, stub.line);
    if body.len() > MAX_REMOVED_CHARS {
        return Some(format!(
            "Commit {short} (\"{subject}\") wrote the stub at {at} and took {taken} lines out \
of the definition there; `git show {short} -- {}` shows them.",
            blamed.path
        ));
    }
    Some(format!(
        "Commit {short} (\"{subject}\") wrote the stub at {at}. Its change in the definition, \
as `git show {short} -U0` prints it:\n{}",
        body.trim_end()
    ))
}

/// What `git blame --porcelain` says of one line.
struct Blamed {
    commit: String,
    parent: String,
    /// The line's number and file in that commit.
    line: usize,
    path: String,
    subject: String,
    text: String,
}

impl Blamed {
    fn read(porcelain: &str) -> Option<Self> {
        let mut lines = porcelain.lines();
        let mut head = lines.next()?.split(' ');
        let commit = head.next()?.to_owned();
        let line: usize = head.next()?.parse().ok()?;
        let mut parent: Option<(String, String)> = None;
        let mut path: Option<String> = None;
        let mut subject = String::new();
        for entry in lines {
            if let Some(text) = entry.strip_prefix('\t') {
                // The parent's file must be the commit's: a rename is not read.
                let path =
                    path.filter(|path| parent.as_ref().is_some_and(|(_, was)| was == path))?;
                let (parent, _) = parent?;
                return (commit_id(&commit) && commit_id(&parent)).then(|| Self {
                    commit,
                    parent,
                    line,
                    path,
                    subject,
                    text: text.trim_end_matches('\r').to_owned(),
                });
            }
            let (key, value) = entry.split_once(' ').unwrap_or((entry, ""));
            match key {
                "summary" => subject = value.to_owned(),
                "filename" => path = Some(value.to_owned()),
                "previous" => {
                    let (commit, was) = value.split_once(' ')?;
                    parent = Some((commit.to_owned(), was.to_owned()));
                }
                _ => {}
            }
        }
        None
    }
}

#[cfg(all(test, unix))]
#[path = "context_assistance_prompt_changes_removed_tests.rs"]
mod tests;
