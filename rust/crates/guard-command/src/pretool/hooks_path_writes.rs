//! Writes into a repository's configured hooks directory. Git runs a file
//! named after a hook in `core.hooksPath` on the next commit, checkout,
//! merge or push, so planting one there is code execution, the same as a
//! write under `.git/hooks`. Hidden hook directories such as `.husky` and
//! `.githooks` are guarded by name; this screen covers a visible one, such as
//! `hooks` or `scripts/githooks`, that only the configuration names. A write
//! to a configuration file that Git includes is screened too, because it can
//! set the hooks directory or a helper program.
//!
//! The configuration is read as plain files and never through Git, so
//! nothing a repository configures runs: each enclosing repository's `config`
//! and `config.worktree`, the user's global files and every file they
//! include. Every `core.hooksPath` found counts, whatever its precedence.
//! Configuration this reader cannot decode keeps the write at review, and
//! so does a path in it that is not UTF-8: Git reads those bytes as they are,
//! so a path rebuilt from a replacement character would name another file.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILES: usize = 16;
const MAX_INCLUDE_DEPTH: usize = 4;

/// Hook names Git runs from the hooks directory.
const GIT_HOOK_NAMES: &[&str] = &[
    "applypatch-msg",
    "commit-msg",
    "fsmonitor-watchman",
    "p4-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "p4-prepare-changelist",
    "post-applypatch",
    "post-checkout",
    "post-commit",
    "post-index-change",
    "post-merge",
    "post-receive",
    "post-rewrite",
    "post-update",
    "pre-applypatch",
    "pre-auto-gc",
    "pre-commit",
    "pre-merge-commit",
    "pre-push",
    "pre-rebase",
    "pre-receive",
    "prepare-commit-msg",
    "proc-receive",
    "push-to-checkout",
    "reference-transaction",
    "sendemail-validate",
    "update",
];

/// True when writing `target`, an absolute path with its links resolved,
/// creates or changes a file in a configured hooks directory, or a
/// configuration file Git includes. The user's global files apply to every
/// target. A repository's own files apply to targets in its work tree, and
/// also to the hooks directory named by the repository the command runs in
/// (`workspace`), even when that directory sits outside the work tree.
pub(super) fn configured_hooks_write(
    target: &Path,
    home: Option<&str>,
    workspace: Option<&str>,
) -> bool {
    let home = home.and_then(|home| fs::canonicalize(home).ok());
    let home = home.as_deref();
    let mut global = Scan::new(home);
    if let Some(home) = home {
        for file in [
            home.join(".gitconfig"),
            home.join(".config").join("git").join("config"),
        ] {
            if global.read(&file, 0).is_none() {
                return true;
            }
        }
    }
    if global.hit(target, None).unwrap_or(true) {
        return true;
    }
    if repository_ancestor_hit(target.ancestors().skip(1), target, &global) {
        return true;
    }
    let Some(workspace) = command_repository(workspace, home) else {
        return false;
    };
    repository_ancestor_hit(workspace.ancestors(), target, &global)
}

/// True when any directory in `roots` is a repository whose hooks
/// configuration covers `target`. A repository whose configuration cannot
/// be decoded is a hit, so the write stays reviewed.
fn repository_ancestor_hit<'a>(
    mut roots: impl Iterator<Item = &'a Path>,
    target: &Path,
    global: &Scan<'_>,
) -> bool {
    roots.any(|root| {
        fs::metadata(root.join(".git")).is_ok_and(|marker| {
            repository_hooks_write(root, &marker, target, global).unwrap_or(true)
        })
    })
}

/// The command's work tree, with `~/` resolved against `home`.
fn command_repository(workspace: Option<&str>, home: Option<&Path>) -> Option<PathBuf> {
    let workspace = workspace?;
    let path = if workspace == "~" {
        home?.to_path_buf()
    } else if let Some(rest) = workspace
        .strip_prefix("~/")
        .or(workspace.strip_prefix("~\\"))
    {
        home?.join(rest)
    } else {
        PathBuf::from(workspace)
    };
    fs::canonicalize(&path).ok()
}

/// `None` when the configuration of the repository at `root` cannot be
/// read or decoded, which the caller treats as a hit.
fn repository_hooks_write(
    root: &Path,
    marker: &fs::Metadata,
    target: &Path,
    global: &Scan<'_>,
) -> Option<bool> {
    let mut scan = Scan::new(global.home);
    for file in repository_files(root, marker)? {
        scan.read(&file, 0)?;
    }
    Some(scan.hit(target, Some(root))? || global.hit(target, Some(root))?)
}

/// The hooks directories and included files a set of configuration files
/// names. Hooks directories stay as written until a work tree resolves them.
struct Scan<'a> {
    home: Option<&'a Path>,
    hooks: Vec<String>,
    includes: Vec<PathBuf>,
    visited: usize,
}

impl<'a> Scan<'a> {
    fn new(home: Option<&'a Path>) -> Self {
        Self {
            home,
            hooks: Vec::new(),
            includes: Vec::new(),
            visited: 0,
        }
    }

    /// Records the hooks directories `path` and its includes name. `None`
    /// for a file it cannot read or decode, or beyond its bounds.
    fn read(&mut self, path: &Path, depth: usize) -> Option<()> {
        self.visited += 1;
        if self.visited > MAX_FILES || depth > MAX_INCLUDE_DEPTH {
            return None;
        }
        let Some(text) = read_config(path)? else {
            return Some(());
        };
        let directory = path.parent()?.to_path_buf();
        for (section, key, raw) in assignments(&text)? {
            if section == "core" && key == "hookspath" {
                self.hooks.push(decode(&raw).and_then(exact)?);
            } else if matches!(section.as_str(), "include" | "includeif") && key == "path" {
                // Every conditional include counts, whether or not it applies.
                let value = decode(&raw).and_then(exact)?;
                if let Some(file) = self.expand(&value, Some(directory.as_path()))? {
                    self.includes.push(file.clone());
                    self.read(&file, depth + 1)?;
                }
            }
        }
        Some(())
    }

    /// Whether `target` is an included file or lies in a hooks directory.
    /// A relative hooks directory resolves against the work tree `root`
    /// and names nothing without one.
    fn hit(&self, target: &Path, root: Option<&Path>) -> Option<bool> {
        let folded = fold(target);
        let same = |path: &Path| fold(path) == folded;
        if self.includes.iter().any(|file| {
            same(file.as_path()) || resolve(file).is_some_and(|real| same(real.as_path()))
        }) {
            return Some(true);
        }
        for value in &self.hooks {
            let Some(hooks) = self.expand(value, root)? else {
                continue;
            };
            if inside_hooks(target, &hooks, root)
                || resolve(&hooks).is_some_and(|real| inside_hooks(target, &real, root))
            {
                return Some(true);
            }
        }
        Some(false)
    }

    /// A path value resolved the way Git does: `~/` against the home and a
    /// relative value against `base`. `Some(None)` for an empty value or a
    /// relative one without a base, and `None` for a form this reader does
    /// not resolve (`~user`, `%(prefix)`).
    fn expand(&self, value: &str, base: Option<&Path>) -> Option<Option<PathBuf>> {
        if value.is_empty() {
            return Some(None);
        }
        let value = &native(value);
        let path = if value == "~" {
            self.home?.to_path_buf()
        } else if let Some(rest) = value.strip_prefix("~/").or(value.strip_prefix("~\\")) {
            self.home?.join(rest)
        } else if value.starts_with('~') || value.starts_with("%(") {
            return None;
        } else if Path::new(value).is_absolute() {
            PathBuf::from(value)
        } else {
            let Some(base) = base else {
                return Some(None);
            };
            base.join(value)
        };
        Some(Some(normalize(&path)))
    }
}

/// The configuration files of the repository whose work tree is `root`: a
/// `.git` directory's own, or a linked worktree's or submodule's admin
/// entry and the shared directory it names.
fn repository_files(root: &Path, marker: &fs::Metadata) -> Option<Vec<PathBuf>> {
    let git = root.join(".git");
    if marker.is_dir() {
        return Some(vec![git.join("config"), git.join("config.worktree")]);
    }
    if !marker.is_file() {
        return None;
    }
    let pointer = exact(read_config(&git)??)?;
    let admin = normalize(&root.join(native(pointer.trim().strip_prefix("gitdir:")?.trim())));
    let common = match read_config(&admin.join("commondir"))? {
        Some(text) => normalize(&admin.join(native(exact(text)?.trim()))),
        None => admin.clone(),
    };
    Some(vec![common.join("config"), admin.join("config.worktree")])
}

/// `Some(None)` for a missing file, `Some(Some(text))` for a plain, bounded
/// one, and `None` for anything else. Bytes that are not UTF-8 become
/// U+FFFD here, so a path read from the text must pass [`exact`].
fn read_config(path: &Path) -> Option<Option<String>> {
    let metadata = match fs::metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(None),
        // A parent that is a file, not a directory, also means no file.
        Err(_) if !path.parent().is_some_and(Path::is_dir) => return Some(None),
        Err(_) => return None,
        Ok(metadata) => metadata,
    };
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES || bytes.contains(&0) {
        return None;
    }
    Some(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// `value` unless it holds U+FFFD, which stands in for bytes that are not
/// UTF-8 and so cannot name the path Git would use.
fn exact(value: String) -> Option<String> {
    (!value.contains(char::REPLACEMENT_CHARACTER)).then_some(value)
}

/// Section, key and undecoded value of each `key = value` line, including
/// one that follows a header on its line, as in `[core] hooksPath = x`. A
/// line that continues a value ending in a backslash is part of that value,
/// which [`decode`] refuses. `None` for an unterminated header.
fn assignments(text: &str) -> Option<Vec<(String, String, String)>> {
    let mut result = Vec::new();
    let mut section = String::new();
    // Whether the previous line continues a value, and inside quotes.
    let mut pending: Option<bool> = None;
    for line in text.lines() {
        if let Some(quoted) = pending {
            pending = continues(line, quoted);
            continue;
        }
        let mut line = line.trim();
        if let Some(header) = line.strip_prefix('[') {
            let end = header_end(header)?;
            section = header[..end]
                .trim()
                .split(|c: char| c.is_whitespace() || c == '"')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            line = header[end + 1..].trim();
        }
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            pending = continues(value, false);
            let key = key.trim().to_ascii_lowercase();
            result.push((section.clone(), key, value.to_owned()));
        }
    }
    Some(result)
}

/// Whether a value's text, starting inside quotes or not, ends in a
/// backslash that continues it onto the next line, and if so whether that
/// line starts inside quotes. A comment ends the value.
fn continues(raw: &str, mut quoted: bool) -> Option<bool> {
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '#' | ';' if !quoted => return None,
            '\\' if chars.next().is_none() => return Some(quoted),
            _ => {}
        }
    }
    None
}

/// The byte offset of the `]` closing a section header, past any quoted
/// subsection name.
fn header_end(header: &str) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, c) in header.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ']' if !quoted => return Some(index),
            _ => {}
        }
    }
    None
}

/// A value the way Git reads it: quotes removed, an unquoted `#` or `;`
/// starting a comment, unquoted trailing whitespace dropped, and `\"`,
/// `\\`, `\n`, `\t` and `\b` decoded. `None` for another escape, a trailing
/// backslash (line continuation) or an unterminated quote.
fn decode(raw: &str) -> Option<String> {
    let mut decoded = String::new();
    let mut kept = 0;
    let mut quoted = false;
    let mut chars = raw.trim_start().chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                kept = decoded.len();
            }
            '#' | ';' if !quoted => break,
            '\\' => {
                decoded.push(match chars.next()? {
                    '"' => '"',
                    '\\' => '\\',
                    'n' => '\n',
                    't' => '\t',
                    'b' => '\u{8}',
                    _ => return None,
                });
                kept = decoded.len();
            }
            other => {
                decoded.push(other);
                if quoted || !other.is_whitespace() {
                    kept = decoded.len();
                }
            }
        }
    }
    if quoted {
        return None;
    }
    decoded.truncate(kept);
    Some(decoded)
}

/// Whether writing `target` places a file in the hooks directory `hooks`:
/// the target lies in it, or is a new directory, copied tree or link that
/// would hold it. Case is ignored, as it is on the default macOS volume. A
/// hooks directory at or above the work tree `root` would otherwise cover
/// every file in it, so there only a hook name directly inside counts.
fn inside_hooks(target: &Path, hooks: &Path, root: Option<&Path>) -> bool {
    let (target, hooks) = (fold(target), fold(hooks));
    if !root.is_some_and(|root| fold(root).starts_with(&hooks)) {
        return target.starts_with(&hooks) || hooks.starts_with(&target);
    }
    target.parent() == Some(hooks.as_path())
        && target
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.split('.').next())
            .is_some_and(|name| GIT_HOOK_NAMES.contains(&name))
}

/// `value` with `/` as the platform separator, so a value joined onto a
/// verbatim Windows path still splits into components.
fn native(value: &str) -> String {
    if cfg!(windows) {
        value.replace('/', "\\")
    } else {
        value.to_owned()
    }
}

fn fold(path: &Path) -> PathBuf {
    PathBuf::from(path.to_string_lossy().to_ascii_lowercase())
}

/// `path` with its longest existing ancestor resolved through links, or
/// `None` for a dangling link or an ancestor that cannot be resolved.
fn resolve(path: &Path) -> Option<PathBuf> {
    let mut existing = path;
    let mut rest = Vec::new();
    loop {
        if let Ok(real) = fs::canonicalize(existing) {
            return Some(
                rest.iter()
                    .rev()
                    .fold(real, |acc: PathBuf, part| acc.join(part)),
            );
        }
        if fs::symlink_metadata(existing).is_ok() {
            return None;
        }
        rest.push(existing.file_name()?.to_owned());
        existing = existing.parent()?;
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    result
}

#[cfg(test)]
#[path = "hooks_path_writes_tests.rs"]
mod tests;
