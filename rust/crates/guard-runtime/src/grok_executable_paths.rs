//! Path rules for the trusted Grok launcher: which locations are refused,
//! which installation roots an automatic PATH match may come from, and the
//! ownership and permission checks a launcher and its directories must pass.
//!
//! Paths are compared the way `pathlib` compares them: lexically, component by
//! component, and without case on Windows. `Path.resolve(strict=False)` is
//! emulated by canonicalising the longest existing prefix and appending the
//! rest.

use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

const FIXED_ROOTS: [&str; 4] = [
    "/usr/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/opt/local/bin",
];
const HOME_ROOTS: [&[&str]; 9] = [
    &[".local", "bin"],
    &[".grok", "bin"],
    &["bin"],
    &[".npm-global", "bin"],
    &[".bun", "bin"],
    &[".volta", "bin"],
    &[".asdf", "shims"],
    &[".local", "share", "pnpm"],
    &["Library", "pnpm"],
];
// Version managers keep one `bin` directory per installed Node release.
const DYNAMIC_PREFIXES: [&[&str]; 4] = [
    &[".nvm", "versions", "node"],
    &[".fnm", "node-versions"],
    &[".local", "share", "mise", "installs", "node"],
    &[".proto", "tools", "node"],
];
const DEFPATH: &str = if cfg!(windows) {
    ".;C:\\bin"
} else {
    "/bin:/usr/bin"
};
const PATH_SEPARATOR: &str = if cfg!(windows) { ";" } else { ":" };

/// The locations one request is judged against.
pub(crate) struct Context {
    pub(crate) home: PathBuf,
    pub(crate) guard_home: PathBuf,
    pub(crate) cwd: PathBuf,
    pub(crate) windows_roots: Vec<PathBuf>,
    /// The workspace, Guard home and (unless it is the anchor or holds the
    /// home directory) the cwd, each with its resolved form.
    blocked: Vec<(PathBuf, Option<PathBuf>)>,
}

impl Context {
    pub(crate) fn new(
        home: PathBuf,
        guard_home: PathBuf,
        workspace: Option<PathBuf>,
        cwd: PathBuf,
        windows_roots: Vec<PathBuf>,
    ) -> Self {
        let mut roots: Vec<PathBuf> = workspace.into_iter().collect();
        roots.push(guard_home.clone());
        let (resolved_cwd, resolved_home) = match (lenient(&cwd, &cwd), lenient(&home, &cwd)) {
            (Some(resolved_cwd), Some(resolved_home)) => (resolved_cwd, resolved_home),
            _ => (cwd.clone(), home.clone()),
        };
        if resolved_cwd.parent().is_some() && !relative_to(&resolved_home, &resolved_cwd) {
            roots.push(resolved_cwd);
        }
        let blocked = roots
            .into_iter()
            .map(|root| {
                let resolved = lenient(&root, &cwd);
                (root, resolved)
            })
            .collect();
        Self {
            home,
            guard_home,
            cwd,
            windows_roots,
            blocked,
        }
    }

    /// `_path_is_blocked`: whether `path` lies in the workspace, the Guard
    /// home or the cwd once both sides are resolved.
    pub(crate) fn blocked(&self, path: &Path) -> bool {
        let target = lenient(path, &self.cwd);
        self.blocked
            .iter()
            .any(|(root, resolved)| match (&target, resolved) {
                (Some(target), Some(resolved)) => relative_to(target, resolved),
                _ => same(path, root),
            })
    }

    /// `_automatic_install_root`: whether an automatic PATH match sits in a
    /// known installation root, judged on the unresolved path.
    pub(crate) fn automatic_root(&self, candidate: &Path) -> bool {
        let fixed = FIXED_ROOTS.iter().map(|root| PathBuf::from(*root));
        let home = HOME_ROOTS.iter().map(|parts| join(&self.home, parts));
        if fixed.chain(home).any(|root| relative_to(candidate, &root)) {
            return true;
        }
        if let Some(parts) = relative_parts(candidate, &self.home) {
            let in_bin = candidate
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == "bin");
            let managed = DYNAMIC_PREFIXES.iter().any(|prefix| {
                parts.len() >= prefix.len()
                    && parts
                        .iter()
                        .zip(prefix.iter())
                        .all(|(part, want)| part.as_str() == *want)
            });
            if in_bin && managed {
                return true;
            }
        }
        self.windows_roots
            .iter()
            .any(|root| relative_to(candidate, root))
    }

    /// `_sanitized_path`: the PATH entries that are absolute, outside the
    /// refused locations, existing directories and (off Windows) owned and
    /// writable only by root or the current user, each kept once.
    pub(crate) fn sanitized_path(&self, value: Option<&str>) -> String {
        let raw = value.filter(|value| !value.is_empty()).unwrap_or(DEFPATH);
        let mut kept: Vec<String> = Vec::new();
        for entry in raw.split(PATH_SEPARATOR) {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let candidate = expand(entry, &self.home);
            if !candidate.is_absolute() || self.blocked(&candidate) {
                continue;
            }
            let Some(resolved) = strict(&candidate) else {
                continue;
            };
            if !resolved.is_dir() || self.blocked(&resolved) || !chain_secure(&resolved) {
                continue;
            }
            let Some(text) = resolved.to_str() else {
                continue;
            };
            if !kept.iter().any(|known| known == text) {
                kept.push(text.to_owned());
            }
        }
        if kept.is_empty() {
            DEFPATH.to_owned()
        } else {
            kept.join(PATH_SEPARATOR)
        }
    }
}

fn join(base: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

/// `_expand_path`: a leading `~` names the home directory.
pub(crate) fn expand(value: &str, home: &Path) -> PathBuf {
    if value == "~" {
        return home.to_path_buf();
    }
    let native = format!("~{}", std::path::MAIN_SEPARATOR);
    match value
        .strip_prefix(native.as_str())
        .or_else(|| value.strip_prefix("~/"))
    {
        Some("") => home.to_path_buf(),
        Some(rest) => home.join(rest),
        None => PathBuf::from(value),
    }
}

/// `PurePath.is_relative_to`, without case on Windows.
pub(crate) fn relative_to(path: &Path, root: &Path) -> bool {
    if cfg!(windows) {
        let lower = |path: &Path| PathBuf::from(path.to_string_lossy().to_lowercase());
        lower(path).starts_with(lower(root))
    } else {
        path.starts_with(root)
    }
}

fn same(path: &Path, other: &Path) -> bool {
    relative_to(path, other) && relative_to(other, path)
}

/// The components of `path` below `root`, as `PurePath.relative_to(...).parts`.
fn relative_parts(path: &Path, root: &Path) -> Option<Vec<String>> {
    if !relative_to(path, root) {
        return None;
    }
    let skip = root.components().count();
    Some(
        path.components()
            .skip(skip)
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect(),
    )
}

/// `Path.resolve(strict=True)`.
pub(crate) fn strict(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok().map(strip_verbatim)
}

/// `Path.resolve(strict=False)` with a relative path taken from `cwd`; `None`
/// when a component cannot be inspected for a reason other than absence.
pub(crate) fn lenient(path: &Path, cwd: &Path) -> Option<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let parts: Vec<Component> = joined.components().collect();
    for end in (1..=parts.len()).rev() {
        let prefix: PathBuf = parts[..end].iter().collect();
        match fs::canonicalize(&prefix) {
            Ok(base) => {
                let mut resolved = strip_verbatim(base);
                for part in &parts[end..] {
                    match part {
                        Component::ParentDir => {
                            resolved.pop();
                        }
                        Component::Normal(name) => resolved.push(name),
                        _ => {}
                    }
                }
                return Some(resolved);
            }
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {}
            Err(_) => return None,
        }
    }
    Some(joined)
}

#[cfg(windows)]
fn strip_verbatim(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{unc}"))
    } else if let Some(local) = text.strip_prefix(r"\\?\") {
        PathBuf::from(local)
    } else {
        path
    }
}

#[cfg(not(windows))]
fn strip_verbatim(path: PathBuf) -> PathBuf {
    path
}

/// `_executable_security_error`: the launcher must be a regular, executable
/// file; off Windows it and every directory above both spellings must also be
/// owned by root or the current user and writable by no one else.
pub(crate) fn security_error(candidate: &Path, resolved: &Path) -> Result<(), &'static str> {
    let metadata =
        fs::metadata(resolved).map_err(|_| "The selected Grok executable cannot be inspected.")?;
    if !metadata.is_file() {
        return Err("The selected Grok executable is not a regular file.");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let executable = nix::unistd::access(resolved, nix::unistd::AccessFlags::X_OK).is_ok();
        if metadata.mode() & 0o111 == 0 || !executable {
            return Err("The selected Grok executable is not executable.");
        }
        if !owner_trusted(metadata.uid()) {
            return Err("The selected Grok executable has an unexpected owner.");
        }
        if metadata.mode() & 0o022 != 0 {
            return Err("The selected Grok executable is writable by another local account.");
        }
        if !chain_secure(candidate.parent().unwrap_or(candidate)) {
            return Err("The Grok installation path has unsafe ownership or permissions.");
        }
        if !chain_secure(resolved.parent().unwrap_or(resolved)) {
            return Err("The Grok executable target path has unsafe ownership or permissions.");
        }
    }
    #[cfg(not(unix))]
    let _ = candidate;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn owner_trusted(uid: u32) -> bool {
    uid == 0 || uid == nix::unistd::getuid().as_raw()
}

/// `_directory_chain_is_secure`: `directory` and each ancestor is owned by
/// root or the current user and writable by neither group nor others.
#[cfg(unix)]
pub(crate) fn chain_secure(directory: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    directory.ancestors().all(|ancestor| {
        fs::metadata(ancestor)
            .is_ok_and(|metadata| owner_trusted(metadata.uid()) && metadata.mode() & 0o022 == 0)
    })
}

/// Windows has no mode bits to check.
#[cfg(not(unix))]
pub(crate) fn chain_secure(_directory: &Path) -> bool {
    true
}
