//! What a local CLI grant lets the workspace sandbox reach to run its program.
//!
//! The program and its script interpreter are opened as files, never as the
//! directories they sit in: each symbolic link the shell follows to a program
//! and the file it ends at get read and execute, and nothing beside them, so a
//! tool kept in `~/bin` or `~/Downloads` does not open its neighbours. The
//! `PATH` entry the session found a bare name through is kept, so the shell
//! finds the program by the same name.
use super::launch_roots::{executable_roots, locate, Lookup};
use super::launch_shebang::{shebang, Shebang};
use super::*;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::Component;

/// The file the agent's shell would run for `program` from `cwd`.
pub(super) fn found(program: &str, search_path: &str, cwd: &Path) -> Option<PathBuf> {
    match locate(program, search_path, Some(cwd)) {
        Lookup::Found(path) => Some(path),
        Lookup::Missing | Lookup::Unresolved => None,
    }
}

/// Most symbolic links followed to one file.
const MOST_LINKS: usize = 40;

/// The execute roots and `PATH` entries of a workspace plan, as a grant
/// widens them.
pub(super) struct Reach<'a> {
    exec_roots: Vec<PathBuf>,
    entries: Vec<String>,
    search_path: &'a str,
    home: Option<&'a Path>,
    workspace: &'a Path,
}

impl<'a> Reach<'a> {
    /// The reach `plan` already has, for the session `search_path`.
    pub(super) fn of(
        plan: &Value,
        search_path: &'a str,
        home: Option<&'a Path>,
        workspace: &'a Path,
    ) -> Option<Self> {
        Some(Self {
            exec_roots: serde_json::from_value(plan["exec_roots"].clone()).ok()?,
            entries: plan["sandbox_path"]
                .as_str()?
                .split(':')
                .map(str::to_owned)
                .collect(),
            search_path,
            home,
            workspace,
        })
    }

    /// Write the widened reach back into `plan`.
    pub(super) fn write(self, plan: &mut Value) {
        plan["exec_roots"] = json!(self.exec_roots);
        plan["sandbox_path"] = json!(self.entries.join(":"));
    }

    /// Let the sandbox run `program` as the session resolves it, and the
    /// interpreter its `#!` line names. `None` when either cannot be reached
    /// without opening more than those files.
    pub(super) fn admit_launch(&mut self, program: &str) -> Option<()> {
        let canonical = self.admit(program)?;
        let interpreters = match shebang(&canonical) {
            Shebang::Absent => Vec::new(),
            Shebang::Runs(programs) => programs,
            // A `#!` line that cannot be read for certain is not admitted.
            Shebang::Unclear => return None,
        };
        for interpreter in interpreters {
            self.admit(&interpreter)?;
        }
        Some(())
    }

    /// Open the links to `program` and the file it is, and keep its `PATH`
    /// entry. The file it is, canonicalized.
    fn admit(&mut self, program: &str) -> Option<PathBuf> {
        let found = found(program, self.search_path, self.workspace)?;
        let canonical = found.canonicalize().ok()?;
        for (link, directory) in links(&found)? {
            self.open(&link, directory)?;
        }
        self.open(&canonical, false)?;
        self.keep_entry(program, &found, &canonical)?;
        Some(canonical)
    }

    /// Execute and read `path`, unless the sandbox reaches it already. A link
    /// to a directory is never opened, which would open the directory it
    /// leads to; the system's own links at the filesystem root, such as
    /// `/bin`, are passed over, and any other directory link refuses.
    fn open(&mut self, path: &Path, directory: bool) -> Option<()> {
        // Roots the grant opened are matched by name: resolving one would let
        // an opened link stand for the file it leads to.
        let reachable = executable_roots(self.workspace, Vec::new());
        if path_is_within_any_lexically(path, &reachable)
            || self.exec_roots.iter().any(|root| path.starts_with(root))
        {
            return Some(());
        }
        if directory {
            return (path.parent() == Some(Path::new("/"))).then_some(());
        }
        if !admissible(path, self.home) {
            return None;
        }
        self.exec_roots.push(path.to_path_buf());
        Some(())
    }

    /// Keep the `PATH` entry the session found the bare name `program`
    /// through, ahead of the accepted entries it came before, and fail unless
    /// the sandbox then finds the same file by that name.
    fn keep_entry(&mut self, program: &str, found: &Path, canonical: &Path) -> Option<()> {
        if program.contains('/') || self.finds(program, canonical) {
            return Some(());
        }
        let entry = found.parent()?;
        let text = entry.to_str()?;
        if text.contains(':')
            || !entry
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            || !admissible(entry, self.home)
        {
            return None;
        }
        if !self.entries.iter().any(|item| item == text) {
            let place = self
                .search_path
                .split(':')
                .position(|item| Path::new(item) == entry)
                .unwrap_or(usize::MAX);
            let before = self
                .entries
                .iter()
                .filter(|accepted| self.session_index(accepted).is_some_and(|at| at < place))
                .count();
            self.entries.insert(before, text.to_owned());
        }
        self.finds(program, canonical).then_some(())
    }

    /// Where the session `PATH` lists the directory `accepted` names.
    fn session_index(&self, accepted: &str) -> Option<usize> {
        self.search_path.split(':').position(|item| {
            Path::new(item) == Path::new(accepted)
                || Path::new(item).canonicalize().ok().as_deref() == Some(Path::new(accepted))
        })
    }

    /// Whether the sandbox `PATH` finds `canonical` by the bare name `program`.
    fn finds(&self, program: &str, canonical: &Path) -> bool {
        found(program, &self.entries.join(":"), self.workspace)
            .and_then(|path| path.canonicalize().ok())
            .as_deref()
            == Some(canonical)
    }
}

/// A path the grant may open: never the filesystem root, the home itself, or
/// a credential path.
fn admissible(path: &Path, home: Option<&Path>) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && home.is_none_or(|home| home.canonicalize().ok().as_deref() != Some(path))
        && path
            .to_str()
            .is_some_and(|text| !crate::secret_path_probe::is_request_secret_path(text, None, home))
}

/// Every symbolic link met resolving the absolute `path`, in the order they
/// are followed, each with whether it leads to a directory.
fn links(path: &Path) -> Option<Vec<(PathBuf, bool)>> {
    if !path.is_absolute() {
        return None;
    }
    let mut pending: VecDeque<OsString> = VecDeque::new();
    push_components(path, &mut pending);
    let mut resolved = PathBuf::from("/");
    let mut found = Vec::new();
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(&part);
        if !std::fs::symlink_metadata(&next)
            .ok()?
            .file_type()
            .is_symlink()
        {
            resolved = next;
            continue;
        }
        if found.len() >= MOST_LINKS {
            return None;
        }
        let target = std::fs::read_link(&next).ok()?;
        let directory = std::fs::metadata(&next).ok()?.is_dir();
        found.push((next, directory));
        if target.is_absolute() {
            resolved = PathBuf::from("/");
        }
        let mut leading = VecDeque::new();
        push_components(&target, &mut leading);
        for part in leading.into_iter().rev() {
            pending.push_front(part);
        }
    }
    Some(found)
}

/// The named parts of `path`, with each `..` kept.
fn push_components(path: &Path, parts: &mut VecDeque<OsString>) {
    for component in path.components() {
        match component {
            Component::Normal(name) => parts.push_back(name.to_owned()),
            Component::ParentDir => parts.push_back(OsString::from("..")),
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "workspace_grant_launch_tests.rs"]
mod tests;
