//! Which tracked files hold the names a prompt writes as code, from Git's own
//! search, so the walk can read them. A large project has more files than the
//! walk visits in its time, and a constant, test or function named in the
//! prompt was often in a folder it never reached.
//!
//! Git runs as for the change lists: the trusted binary, offline, without
//! a pager, optional locks or a file monitor, and stopped at its deadline. A
//! search runs no filter or text conversion, and the walk still reads each
//! file it is given through its own checks.
use super::Git;
use crate::context_assistance_prompt_files::{named, walk_exact, Walk};
use crate::context_assistance_prompt_words::spellings;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Names searched for, at most; the earlier in the prompt the better.
const MAX_NAMES: usize = 4;
/// A name in more files than this places nothing: a common field or helper
/// says nothing about where the prompt's work is.
const MAX_HOLDING: usize = 8;
/// Names shorter than this are left to the walk.
const MIN_NAME: usize = 5;

/// The walk for `prompt`. While project context is on, Git searches for the
/// names it writes as code at the same time, for at most half of `budget`,
/// and the walk then reads the files Git found that it did not reach.
pub(crate) fn walk(
    home: &Path,
    root: &Path,
    prompt: &str,
    (words, quoted): (&[String], &[String]),
    budget: Duration,
    context_on: &dyn Fn() -> bool,
) -> Walk {
    let exact = spellings(prompt);
    let until = Instant::now() + budget / 2;
    let names = searched_names(&exact);
    let search = (!names.is_empty() && context_on())
        .then(|| start(home.to_path_buf(), root.to_path_buf(), names, until))
        .flatten();
    let searched = || {
        let wait = until.saturating_duration_since(Instant::now());
        (search.as_ref())
            .and_then(|answer| answer.recv_timeout(wait).ok())
            .unwrap_or_default()
    };
    walk_exact(
        root,
        words,
        quoted,
        &named(prompt),
        (&exact, &searched),
        budget,
    )
}

/// Starts the search on its own thread; its answer is dropped if late.
fn start(
    home: PathBuf,
    root: PathBuf,
    names: Vec<String>,
    until: Instant,
) -> Option<mpsc::Receiver<Vec<String>>> {
    let (send, answer) = mpsc::channel();
    std::thread::Builder::new()
        .name("cigar-prompt-search".into())
        .spawn(move || {
            let _ = send.send(holding(&home, &root, &names, until));
        })
        .ok()?;
    Some(answer)
}

/// The names worth a search: written as one word, long enough, each once.
fn searched_names(exact: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for name in exact {
        let word = (name.chars()).all(|c| c.is_alphanumeric() || matches!(c, '_' | '-'));
        if word
            && name.chars().count() >= MIN_NAME
            && !name.starts_with('-')
            && !names.contains(name)
            && names.len() < MAX_NAMES
        {
            names.push(name.clone());
        }
    }
    names
}

/// The tracked files under `root` that hold one of `names` as a whole word,
/// for each name held in at most [`MAX_HOLDING`] files, in the names' order,
/// while `until` lasts. Empty when `root` is not a Git work tree or no
/// trusted Git is found.
fn holding(home: &Path, root: &Path, names: &[String], until: Instant) -> Vec<String> {
    if names.is_empty() || Instant::now() >= until {
        return Vec::new();
    }
    let Some(git) = Git::find(root, home) else {
        return Vec::new();
    };
    // Only tracked files: no untracked or ignored file, no submodule, and no
    // search outside a repository even where configuration allows one. Each
    // match prints as `path NUL name`, so one pass answers every name.
    let mut arguments = vec![
        "-c",
        "grep.fallbackToNoIndex=false",
        "grep",
        "-o",
        "-z",
        "-I",
        "-F",
        "-w",
        "--no-color",
        "--no-recurse-submodules",
    ];
    for name in names {
        arguments.extend(["-e", name.as_str()]);
    }
    arguments.push("--");
    let Some(listed) = git.run(&arguments, until) else {
        return Vec::new();
    };
    let mut holders: Vec<Vec<&str>> = vec![Vec::new(); names.len()];
    for line in listed.lines() {
        let Some((file, matched)) = line.split_once('\0') else {
            continue;
        };
        if let Some(at) = names.iter().position(|name| name == matched) {
            if !holders[at].contains(&file) {
                holders[at].push(file);
            }
        }
    }
    let mut found: Vec<String> = Vec::new();
    for files in holders
        .into_iter()
        .filter(|files| files.len() <= MAX_HOLDING)
    {
        for file in files {
            if !found.iter().any(|known| known == file) {
                found.push(file.to_owned());
            }
        }
    }
    found
}

#[cfg(all(test, unix))]
#[path = "context_assistance_prompt_changes_grep_tests.rs"]
mod tests;
