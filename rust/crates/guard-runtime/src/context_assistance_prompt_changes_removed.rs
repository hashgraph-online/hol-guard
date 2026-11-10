//! For a definition left to be written that the map shows, how it read before
//! the commit that wrote its stub. Asked to write a body again after a
//! refactor, an agent searched the history for the old one and read it; the
//! note shows it instead.
//!
//! Git runs as for the changes note, on commits only, so no filter runs, and
//! each call is stopped at the hook's deadline. The old definition is found by
//! its own first line, which must appear once in each version of the file, and
//! ends where its indentation does. A stub written where nothing was, or one
//! not committed yet, gets nothing. The old definition and the commit's whole
//! subject are scanned for secrets, and nothing is shown when either has one.

use super::super::map::rename::STUB_MARKS;
use super::super::seen::Span;
use super::super::Rendered;
use super::{clean, commit_id, Git, GLOBAL};
use crate::context_assistance_engine::screened_texts;
use crate::context_assistance_prompt_words::test_file;
use crate::git_execution_safety_probe::Prober;
use guard_contracts::GuardHookEnvelopeV2;
use std::path::Path;
use std::time::Instant;

/// The longest old definition shown; a longer one is named with the command
/// that shows it.
const MAX_OLD_CHARS: usize = 2_400;
const MAX_SUBJECT_CHARS: usize = 100;
/// Files of the map read again to find a stub in the code it shows.
const MAX_FILES: usize = 4;

/// `rendered` with how the first stub it shows read before, or as it
/// is when there is none, Git is not trusted, or `until` passes.
pub(in super::super) fn added(
    rendered: Rendered,
    guard_home: &Path,
    envelope: &GuardHookEnvelopeV2,
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
    let home = Path::new(&envelope.source.home_dir);
    let note = Git::find(root, home).and_then(|git| before(&git, &stub, until));
    match note {
        Some(note) => Rendered {
            text: format!("{}\n\n{note}", rendered.text),
            shown: rendered.shown,
        },
        None => rendered,
    }
}

/// A stub line in code the map shows whole: its file, its line and text, and
/// the first line of the definition holding it.
pub(super) struct Stub {
    pub(super) path: String,
    pub(super) line: usize,
    pub(super) text: String,
    pub(super) header: String,
}

pub(super) fn first_stub(shown: &[Span], texts: &[(String, String)]) -> Option<Stub> {
    shown.iter().find_map(|span| {
        let (_, text) = texts.iter().find(|(path, _)| *path == span.path)?;
        let lines: Vec<&str> = text
            .lines()
            .map(|line| line.trim_end_matches('\r'))
            .collect();
        let (start, end) = (
            usize::try_from(span.start).ok()?,
            usize::try_from(span.end).ok()?,
        );
        let line = (start.max(1)..=end.min(lines.len()))
            .find(|&line| STUB_MARKS.iter().any(|mark| lines[line - 1].contains(mark)))?;
        let header = header(&lines, line - 1)?;
        (once(&lines, header)).then(|| Stub {
            path: span.path.clone(),
            line,
            text: lines[line - 1].to_owned(),
            header: header.to_owned(),
        })
    })
}

/// The nearest line above `at` that is indented less and does not close a
/// bracket: the definition's first line, or the last of its signature.
fn header<'a>(lines: &[&'a str], at: usize) -> Option<&'a str> {
    let below = indent(lines[at]);
    lines[..at].iter().rev().copied().find(|line| {
        !line.trim().is_empty()
            && indent(line) < below
            && !line.trim_start().starts_with([')', ']', '}'])
    })
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn once(lines: &[&str], header: &str) -> bool {
    lines.iter().filter(|line| **line == header).count() == 1
}

/// The definition starting at `header` in `text`: the lines after it that are
/// blank or indented more, and a closing bracket at its own indentation. A
/// closing line that also opens the body, such as `) -> int:` or `) {` after
/// a signature on several lines, ends the signature, not the definition.
fn definition(text: &str, header: &str) -> Option<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    if !once(&lines, header) {
        return None;
    }
    let at = lines.iter().position(|line| *line == header)?;
    let inside = |line: &str| line.trim().is_empty() || indent(line) > indent(header);
    let closes = |line: &&str| {
        indent(line) == indent(header) && line.trim_start().starts_with([')', ']', '}'])
    };
    let opens = |line: &str| line.trim_end().ends_with([':', '{']);
    let mut end = at + 1;
    loop {
        end += lines[end..].iter().take_while(|line| inside(line)).count();
        match lines.get(end).copied().filter(closes) {
            Some(line) => {
                end += 1;
                if !opens(line) {
                    break;
                }
            }
            None => {
                while end > at + 1 && lines[end - 1].trim().is_empty() {
                    end -= 1;
                }
                break;
            }
        }
    }
    (end > at + 1).then(|| lines[at..end].join("\n"))
}

/// The note for `stub`: the definition as it read before the commit that
/// wrote the stub line, when it had a body then.
pub(super) fn before(git: &Git, stub: &Stub, until: Instant) -> Option<String> {
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
    let blamed = Blamed::read(&git.run_by(&blame, until)?)?;
    // An edit not committed yet moved the line, or wrote it.
    if blamed.text != stub.text || !clean(&blamed.subject) {
        return None;
    }
    let blob = format!("{}:{}", blamed.parent, blamed.path);
    let old = git.run_by(&["cat-file", "blob", blob.as_str()], until)?;
    let old = definition(&old, &stub.header)?;
    if STUB_MARKS.iter().any(|mark| old.contains(mark)) || !clean(&old) {
        return None;
    }
    let subject: String = blamed.subject.chars().take(MAX_SUBJECT_CHARS).collect();
    let (short, parent) = (&blamed.commit[..12], &blamed.parent[..12]);
    let at = format!("{}:{}", stub.path, stub.line);
    if old.len() > MAX_OLD_CHARS {
        let shown = format!("{parent}:{}", blamed.path).replace('\'', "'\\''");
        return Some(format!(
            "Commit {short} (\"{subject}\") wrote the stub at {at}. The definition ran {} \
lines before it; `git show '{shown}'` shows the file then.",
            old.lines().count()
        ));
    }
    Some(format!(
        "Commit {short} (\"{subject}\") wrote the stub at {at}. Before it, in {parent}, \
the definition read:\n{old}"
    ))
}

impl Git {
    /// Like `Git::run`, but a call is stopped at `until`: this note is
    /// optional and must not hold the hook past its wait.
    fn run_by(&self, arguments: &[&str], until: Instant) -> Option<String> {
        if Instant::now() >= until {
            return None;
        }
        let all: Vec<&str> = GLOBAL.iter().chain(arguments).copied().collect();
        let prober = Prober {
            git: &self.path,
            cwd: &self.root,
            environment: &self.environment,
        };
        let output = prober.run_offline_until(&all, until)?;
        output
            .success()
            .then(|| output.text().map(str::to_owned))
            .flatten()
    }
}

/// What `git blame --porcelain` says of one line.
struct Blamed {
    commit: String,
    parent: String,
    /// The line's file in that commit.
    path: String,
    subject: String,
    text: String,
}

impl Blamed {
    fn read(porcelain: &str) -> Option<Self> {
        let mut lines = porcelain.lines();
        let commit = lines.next()?.split(' ').next()?.to_owned();
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
