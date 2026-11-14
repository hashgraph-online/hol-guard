use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// Attribute inspection never invokes clean/smudge/process filters. Check every
// tracked and untracked path, or only the `named` operands when the command
// reads nothing else; a global filter definition alone cannot execute.
#[allow(clippy::too_many_arguments)]
pub(super) fn unused(
    binary: &Path,
    leading: &[String],
    cwd: &Path,
    home: &Path,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    deadline: Instant,
    named: &[&str],
    repository_optional: bool,
) -> Option<bool> {
    let query = |arguments: &[&str], input: Option<Vec<u8>>, root: Option<&Path>| {
        let mut command = Command::new(binary);
        command.env_clear();
        #[cfg(windows)]
        for key in ["SYSTEMROOT", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        if let Some(directory) = environment.and_then(|value| value.xdg_config_home.as_deref()) {
            command.env("XDG_CONFIG_HOME", directory);
        } else if environment.is_none() {
            if let Some(directory) = std::env::var_os("XDG_CONFIG_HOME") {
                command.env("XDG_CONFIG_HOME", directory);
            }
        }
        if environment.is_some_and(|value| value.git_config_no_system) {
            command.env("GIT_CONFIG_NOSYSTEM", "1");
        }
        command
            .env("HOME", home)
            .env("USERPROFILE", home)
            .current_dir(cwd)
            .args(leading)
            .args([
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
            ]);
        if let Some(root) = root {
            command.arg("-C").arg(root);
        }
        command.args(arguments);
        bounded_output(command, input, deadline)
    };
    if !named.is_empty() {
        // Operands resolve against the caller's directory. A path outside the
        // work tree makes check-attr fail, which keeps the command reviewed.
        let mut batch = Vec::new();
        for path in named {
            if path.is_empty() || path.contains('\0') || path.len() > 4096 {
                return None;
            }
            batch.extend_from_slice(path.as_bytes());
            batch.push(0);
        }
        let attributes = query(
            &["check-attr", "-z", "--stdin", "filter"],
            Some(batch.clone()),
            None,
        )?;
        return filters_unset(&attributes, &batch);
    }
    let Some(root) = query(&["rev-parse", "--show-toplevel"], None, None) else {
        // `git status` outside any repository stops during repository setup,
        // before it reads attributes or starts a filter. Both discovery
        // queries failing is that case; a bare repository or a git directory
        // still answers `--git-dir` and stays unproven.
        // A probe cut off by the deadline proves nothing.
        return (repository_optional
            && Instant::now() < deadline
            && query(&["rev-parse", "--git-dir"], None, None).is_none()
            && query(&["rev-parse", "--is-inside-work-tree"], None, None).is_none())
        .then_some(true);
    };
    let root = std::str::from_utf8(&root).ok()?.strip_suffix('\n')?;
    if root.len() > 4096 || root.chars().any(char::is_control) {
        return None;
    }
    let root = std::fs::canonicalize(root).ok()?;
    let paths = query(
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        None,
        Some(&root),
    )?;
    if paths.is_empty() {
        return Some(true);
    }
    if paths.last() != Some(&0) {
        return None;
    }
    // Untracked nested repositories and linked worktrees are listed as `dir/`.
    // Status reports them as one untracked entry and never descends into them,
    // so they cannot run filters. Tracked gitlinks (mode 160000) are listed
    // without a trailing slash and can make status inspect another repository,
    // whose filter configuration this proof does not cover.
    let mut covered = Vec::with_capacity(paths.len());
    let mut candidates = Vec::new();
    for path in paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        if path.ends_with(b"/") {
            continue;
        }
        candidates.push(root.join(std::str::from_utf8(path).ok()?));
        covered.extend_from_slice(path);
        covered.push(0);
    }
    if covered.is_empty() {
        return Some(true);
    }
    // The attribute query and the populated-gitlink check read the same
    // listing and answer on their own, so the file checks run while Git
    // reports attributes. Together they used to take more than a hook's
    // whole budget in a checkout of a few tens of thousands of files.
    std::thread::scope(|scope| {
        let attributes = scope
            .spawn(|| filters_unset_in(&query, &covered, &root, deadline, ATTRIBUTE_BATCH_BYTES));
        let nested = populated_gitlink(&candidates, deadline);
        let attributes = attributes.join().ok()?;
        match nested? {
            true => Some(false),
            false => attributes,
        }
    })
}

/// Whether any listed path is a directory holding its own `.git`, which a
/// tracked gitlink checked out in place looks like. `None` past the deadline.
fn populated_gitlink(candidates: &[std::path::PathBuf], deadline: Instant) -> Option<bool> {
    for candidate in candidates {
        if Instant::now() >= deadline {
            return None;
        }
        if candidate.is_dir() && candidate.join(".git").exists() {
            return Some(true);
        }
    }
    Some(false)
}

// Attribute output repeats each path plus two fields, about twenty bytes more
// than the path. One query covers a checkout of a few hundred thousand files;
// half the output cap leaves room for longer values.
const ATTRIBUTE_BATCH_BYTES: usize = (super::super::git_probe::LISTING_LIMIT / 2) as usize;

/// A git invocation with optional standard input and working directory.
type GitQuery<'a> = dyn Fn(&[&str], Option<Vec<u8>>, Option<&Path>) -> Option<Vec<u8>> + Sync + 'a;

/// Whether no path in the NUL-separated `paths` has a filter attribute.
fn filters_unset_in(
    query: &GitQuery<'_>,
    paths: &[u8],
    root: &Path,
    deadline: Instant,
    batch_bytes: usize,
) -> Option<bool> {
    let mut offset = 0;
    let mut batches = 0;
    while offset < paths.len() {
        if Instant::now() >= deadline || batches >= 64 {
            return None;
        }
        let start = offset;
        let mut expected_bytes = 0;
        for path in paths[start..].split(|byte| *byte == 0) {
            if path.is_empty() {
                break;
            }
            let cost = path.len().checked_add(20)?;
            if cost > batch_bytes {
                return None;
            }
            if expected_bytes + cost > batch_bytes {
                break;
            }
            expected_bytes += cost;
            offset += path.len() + 1;
        }
        if offset == start {
            return None;
        }
        let batch = &paths[start..offset];
        let attributes = query(
            &["check-attr", "-z", "--stdin", "filter"],
            Some(batch.to_vec()),
            Some(root),
        )?;
        if !filters_unset(&attributes, batch)? {
            return Some(false);
        }
        batches += 1;
    }
    Some(true)
}

/// Parse `check-attr -z filter` output for exactly the paths in `batch`.
fn filters_unset(attributes: &[u8], batch: &[u8]) -> Option<bool> {
    let mut fields = attributes.split(|byte| *byte == 0);
    for path in batch
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        if fields.next()? != path || fields.next()? != b"filter" {
            return None;
        }
        if !matches!(fields.next()?, b"unspecified" | b"unset") {
            return Some(false);
        }
    }
    if fields.next()? != b"" || fields.next().is_some() {
        return None;
    }
    Some(true)
}

fn bounded_output(
    mut command: Command,
    input: Option<Vec<u8>>,
    deadline: Instant,
) -> Option<Vec<u8>> {
    const LIMIT: u64 = super::super::git_probe::LISTING_LIMIT;
    if Instant::now() >= deadline {
        return None;
    }
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (output_sender, output_receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout
            .take(LIMIT + 1)
            .read_to_end(&mut output)
            .ok()
            .and_then(|_| (output.len() <= LIMIT as usize).then_some(output));
        let _ = output_sender.send(result);
    });
    let writer = input.map(|input| {
        let mut stdin = child.stdin.take();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = stdin
                .as_mut()
                .and_then(|stdin| stdin.write_all(&input).ok());
            let _ = sender.send(result);
        });
        receiver
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let output = output_receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()??;
    if let Some(writer) = writer {
        writer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()??;
    }
    status?.success().then_some(output)
}

/// Whether an index comparison also reads the files on disk.
///
/// `git diff-index HEAD` compares the index against the working tree, so Git
/// runs a configured clean filter over every file it has to re-examine.
/// `--cached` (or `--staged`) compares the index against the named tree alone
/// and never opens a working-tree file, so that spelling consumes no filter.
/// `git diff` takes the same spellings, and its `--no-index` form compares
/// two paths on disk. `diff-files` always compares the index against the
/// working tree and has no such spelling, so it is screened without asking
/// here. `diff-tree` compares two trees and reaches neither the index nor the
/// working tree.
///
/// An option such as `-S` or `--output` takes the next word as its value, so
/// in `git diff -S --cached` the `--cached` is the search text and the diff
/// still reads the working tree. The spelling counts only where the word
/// before it cannot be such an option: nothing, a word that is not an option,
/// or one of the options below that never take a separate value.
pub(super) fn reads_working_tree(operation: &str, rest: &[String]) -> bool {
    let options: Vec<&str> = rest
        .iter()
        .map(String::as_str)
        .take_while(|argument| *argument != "--")
        .collect();
    let index_only = options.iter().enumerate().any(|(position, argument)| {
        matches!(*argument, "--cached" | "--staged")
            && position
                .checked_sub(1)
                .is_none_or(|previous| takes_no_separate_value(options[previous]))
    });
    (operation == "diff" && options.contains(&"--no-index")) || !index_only
}

/// Whether a `diff` word leaves the following word alone. Long options with
/// an optional value only ever take it after `=`.
fn takes_no_separate_value(word: &str) -> bool {
    if let Some(long) = word.strip_prefix("--") {
        return long.contains('=')
            || matches!(
                long,
                "cached"
                    | "staged"
                    | "merge-base"
                    | "stat"
                    | "numstat"
                    | "shortstat"
                    | "name-only"
                    | "name-status"
                    | "summary"
                    | "compact-summary"
                    | "raw"
                    | "patch"
                    | "no-patch"
                    | "minimal"
                    | "patience"
                    | "histogram"
                    | "check"
                    | "exit-code"
                    | "quiet"
                    | "color"
                    | "no-color"
                    | "word-diff"
                    | "no-renames"
                    | "find-renames"
                    | "find-copies"
                    | "text"
                    | "binary"
                    | "full-index"
                    | "no-prefix"
                    | "relative"
                    | "no-relative"
                    | "ignore-all-space"
                    | "ignore-space-change"
                    | "ignore-space-at-eol"
                    | "ignore-blank-lines"
                    | "ignore-cr-at-eol"
                    | "no-ext-diff"
                    | "no-textconv"
                    | "irreversible-delete"
                    | "function-context"
            );
    }
    let Some(short) = word.strip_prefix('-') else {
        return true;
    };
    // `-M`, `-C` and `-B` read a value only when it is attached (`-M50%`).
    !short.is_empty()
        && (short.starts_with(['M', 'C', 'B'])
            || short.bytes().all(|flag| b"puszRabwWD".contains(&flag)))
}

#[cfg(test)]
#[path = "git_config_filters_tests.rs"]
mod tests;
