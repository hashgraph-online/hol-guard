//! The Git excludes plain `rg` honors that the content walk's own ignore
//! tiers leave out.
//!
//! `rg -g GLOB` searches hidden and ignored entries too, and the content walk
//! lets a committed file through only when plain `rg` over the same root
//! already searches it. The walk's tiers model the rules that hide a file
//! from a proof, so they leave out the global Git excludes file, a linked
//! worktree's excludes and a nested repository's own excludes. A committed
//! file that only one of those hides is one plain `rg` skips, so the glob is
//! what reaches it and its content still needs the check.
//!
//! Every rule here can only mark more entries as skipped, which keeps more
//! of them under the content check. Re-include rules are dropped for the same
//! reason. A source Guard cannot read or model turns the exemption off.

use super::search_scope_ignore::{
    is_ignored, load_ignore_file, slash_path, IgnoreRule, IgnoreTiers,
};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Git config and `.git` files are small; a larger one is not modeled.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Positive Git exclude rules plain `rg` may skip a committed file by.
pub(super) struct PlainSkips {
    tiers: IgnoreTiers,
    /// Global rules with a slash. `rg` places them below a directory Guard
    /// cannot pin down, so they are matched below every one.
    anywhere: Vec<IgnoreRule>,
    /// A source exists that Guard could not read or model.
    unknown: bool,
}

impl PlainSkips {
    /// The global excludes `rg` reads, matched below `root`, and the
    /// excludes of the repository holding it.
    pub(super) fn load(root: &Path, repository: Option<&Path>, home: Option<&str>) -> Self {
        let mut skips = Self {
            tiers: IgnoreTiers::default(),
            anywhere: Vec::new(),
            unknown: false,
        };
        match slash_path(root) {
            Some(base) => {
                for file in global_excludes_files(home, &mut skips.unknown) {
                    skips.load_file(&file, &base, true);
                }
            }
            None => skips.unknown = true,
        }
        if let Some(repository) = repository {
            skips.add_repository(repository);
        }
        skips
    }

    /// The `info/exclude` files of the repository rooted at `repository`,
    /// through a linked worktree's `.git` file as well.
    pub(super) fn add_repository(&mut self, repository: &Path) {
        let Some(base) = slash_path(repository) else {
            self.unknown = true;
            return;
        };
        match git_directories(&repository.join(".git")) {
            Some(directories) => {
                for directory in directories {
                    self.load_file(&directory.join("info").join("exclude"), &base, false);
                }
            }
            None => self.unknown = true,
        }
    }

    /// Whether plain `rg` may skip the entry at `rendered`.
    pub(super) fn skips(&self, rendered: &str, is_directory: bool) -> bool {
        self.unknown
            || is_ignored(&self.tiers, rendered, is_directory).unwrap_or(true)
            || self
                .anywhere
                .iter()
                .any(|rule| rule.matches_below_any_base(rendered, is_directory))
    }

    /// Adds a nested repository's excludes when the walk models them.
    pub(super) fn enter(skips: &mut Option<Self>, repository: &Path) {
        if let Some(skips) = skips {
            skips.add_repository(repository);
        }
    }

    /// Whether the walk models these rules and plain `rg` may skip the entry.
    pub(super) fn hit(skips: &Option<Self>, rendered: &str, is_directory: bool) -> bool {
        skips
            .as_ref()
            .is_some_and(|skips| skips.skips(rendered, is_directory))
    }

    /// Loads one exclude file. A global file's name rules are matched below
    /// the search root and its slash rules below every directory.
    fn load_file(&mut self, file: &Path, base: &str, global: bool) {
        let file = match std::fs::symlink_metadata(file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                self.unknown = true;
                return;
            }
            // Git and `rg` follow a linked excludes file, as dotfile setups use.
            Ok(metadata) if metadata.is_symlink() => match std::fs::canonicalize(file) {
                Ok(target) => target,
                Err(_) => return,
            },
            Ok(_) => file.to_path_buf(),
        };
        let mut rules = Vec::new();
        if load_ignore_file(&file, base, &mut rules).is_err() {
            self.unknown = true;
            return;
        }
        for rule in rules {
            if rule.negated() {
                continue;
            }
            if global && rule.anchored() {
                self.anywhere.push(rule);
            } else {
                self.tiers.git.push(rule);
            }
        }
    }
}

/// The global excludes files `rg` may read: each `core.excludesFile` in the
/// user's Git config and the default `git/ignore` files. Reading all of them
/// can only skip more.
fn global_excludes_files(home: Option<&str>, unknown: &mut bool) -> Vec<PathBuf> {
    let home = home.map(Path::new);
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let mut configs = Vec::new();
    let mut files = Vec::new();
    if let Some(home) = home {
        configs.push(home.join(".gitconfig"));
        configs.push(home.join(".config/git/config"));
        files.push(home.join(".config/git/ignore"));
    }
    if let Some(xdg) = &xdg {
        configs.push(xdg.join("git/config"));
        files.push(xdg.join("git/ignore"));
    }
    for config in configs {
        let text = match read_small(&config) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(()) => {
                *unknown = true;
                continue;
            }
        };
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if !key.trim().eq_ignore_ascii_case("excludesfile") {
                continue;
            }
            let value = value.trim().trim_matches('"').trim();
            match (value.strip_prefix("~/"), home) {
                (Some(rest), Some(home)) => files.push(home.join(rest)),
                (None, _) if Path::new(value).is_absolute() => files.push(PathBuf::from(value)),
                // A relative or `~user` path depends on where `rg` runs.
                _ => *unknown = true,
            }
        }
    }
    files
}

/// The Git directory a `.git` entry names, and its common directory when
/// that is a linked worktree's.
fn git_directories(git: &Path) -> Option<Vec<PathBuf>> {
    let metadata = std::fs::symlink_metadata(git).ok()?;
    if metadata.is_dir() {
        return Some(vec![git.to_path_buf()]);
    }
    let text = read_small(git).ok()??;
    let named = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let directory = git.parent()?.join(named);
    let mut directories = vec![directory.clone()];
    match read_small(&directory.join("commondir")) {
        Ok(Some(common)) => directories.push(directory.join(common.trim())),
        Ok(None) => {}
        Err(()) => return None,
    }
    Some(directories)
}

/// A small file's text; `None` when it does not exist.
fn read_small(path: &Path) -> Result<Option<String>, ()> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(());
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}
