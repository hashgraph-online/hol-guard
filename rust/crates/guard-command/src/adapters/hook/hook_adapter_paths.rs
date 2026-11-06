//! `pathlib` path semantics used by the hook action envelope: pure path
//! parsing for both flavors, `expanduser`, `Path.resolve(strict=False)` and
//! the workspace/target-path redaction built on them.

use crate::home_path_text::split_root_nt;
use crate::hook_adapter_prepare::AdapterError;
use crate::hook_adapter_pytext::py_strip;
use crate::hook_adapter_secret_path::redacted_secret_path_context;

/// Caller-supplied environment; Rust never reads the process environment.
#[derive(Debug, Clone, Default)]
pub struct PathEnv {
    /// `os.path.expanduser("~")` on the host, when resolvable.
    pub tilde_home: Option<String>,
    /// `str(Path.home())` on the host, when resolvable.
    pub default_home: Option<String>,
    /// `os.getcwd()` on the host, when resolvable.
    pub cwd: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    Posix,
    Windows,
}

impl Flavor {
    pub fn host() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Posix
        }
    }

    fn sep(self) -> &'static str {
        match self {
            Self::Posix => "/",
            Self::Windows => "\\",
        }
    }
}

/// A parsed `PurePath` (`drive`, `root`, `tail`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurePath {
    flavor: Flavor,
    drive: String,
    root: String,
    tail: Vec<String>,
}

impl PurePath {
    pub fn parse(flavor: Flavor, text: &str) -> Self {
        if text.is_empty() {
            return Self {
                flavor,
                drive: String::new(),
                root: String::new(),
                tail: Vec::new(),
            };
        }
        let (drive, root, rel) = match flavor {
            Flavor::Posix => posix_split_root(text),
            Flavor::Windows => windows_split_root(text),
        };
        let tail = rel
            .split(flavor.sep())
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_owned)
            .collect();
        Self {
            flavor,
            drive,
            root,
            tail,
        }
    }

    pub fn host(text: &str) -> Self {
        Self::parse(Flavor::host(), text)
    }

    pub fn name(&self) -> &str {
        self.tail.last().map_or("", String::as_str)
    }

    pub fn is_absolute(&self) -> bool {
        match self.flavor {
            Flavor::Windows => !self.drive.is_empty() && !self.root.is_empty(),
            Flavor::Posix => self.root.starts_with('/'),
        }
    }

    /// `str(path)`.
    pub fn text(&self) -> String {
        let joined = self.tail.join(self.flavor.sep());
        if !self.drive.is_empty() || !self.root.is_empty() {
            return format!("{}{}{joined}", self.drive, self.root);
        }
        let mut tail = self.tail.clone();
        if self.flavor == Flavor::Windows
            && tail.first().is_some_and(|first| has_windows_drive(first))
        {
            tail.insert(0, ".".to_owned());
        }
        let text = tail.join(self.flavor.sep());
        if text.is_empty() {
            ".".to_owned()
        } else {
            text
        }
    }

    fn fold(&self, text: &str) -> String {
        match self.flavor {
            Flavor::Windows => text.to_lowercase(),
            Flavor::Posix => text.to_owned(),
        }
    }

    /// `self.is_relative_to(other)`.
    pub fn is_relative_to(&self, other: &Self) -> bool {
        self.fold(&self.drive) == self.fold(&other.drive)
            && self.fold(&self.root) == self.fold(&other.root)
            && self.tail.len() >= other.tail.len()
            && self
                .tail
                .iter()
                .zip(&other.tail)
                .all(|(left, right)| self.fold(left) == self.fold(right))
    }

    /// `relative_to(other)` rendered with `as_posix()` or `"."` when empty.
    pub fn relative_posix(&self, other: &Self) -> String {
        let rest = &self.tail[other.tail.len()..];
        if rest.is_empty() {
            ".".to_owned()
        } else {
            rest.join("/")
        }
    }
}

fn has_windows_drive(part: &str) -> bool {
    part.chars().nth(1) == Some(':')
}

fn posix_split_root(text: &str) -> (String, String, String) {
    if !text.starts_with('/') {
        (String::new(), String::new(), text.to_owned())
    } else if !text[1..].starts_with('/') || text[2..].starts_with('/') {
        (String::new(), "/".to_owned(), text[1..].to_owned())
    } else {
        (String::new(), "//".to_owned(), text[2..].to_owned())
    }
}

fn windows_split_root(text: &str) -> (String, String, String) {
    let replaced = text.replace('/', "\\");
    let (drive, root, rel) = split_root_nt(&replaced);
    let mut root = root.to_owned();
    if root.is_empty() && drive.starts_with('\\') && !drive.ends_with('\\') {
        let parts: Vec<&str> = drive.split('\\').collect();
        if (parts.len() == 4 && parts[2] != "?" && parts[2] != ".") || parts.len() == 6 {
            root = "\\".to_owned();
        }
    }
    (drive.to_owned(), root, rel.to_owned())
}

/// `Path.expanduser()`.
pub fn expanduser(path: PurePath, env: &PathEnv) -> Result<PurePath, AdapterError> {
    let Some(first) = path.tail.first() else {
        return Ok(path);
    };
    if !path.drive.is_empty() || !path.root.is_empty() || !first.starts_with('~') {
        return Ok(path);
    }
    if first != "~" {
        return Err(AdapterError::Unsupported(
            "native_hook_adapter_tilde_user_unsupported",
        ));
    }
    let Some(home) = env.tilde_home.as_deref() else {
        return Err(AdapterError::Unsupported(
            "native_hook_adapter_home_unavailable",
        ));
    };
    let home = if path.flavor == Flavor::Posix {
        let trimmed = home.trim_end_matches('/');
        if trimmed.is_empty() {
            "/"
        } else {
            trimmed
        }
    } else {
        home
    };
    let parsed = PurePath::parse(path.flavor, home);
    let mut tail = parsed.tail;
    tail.extend(path.tail[1..].iter().cloned());
    Ok(PurePath {
        flavor: path.flavor,
        drive: parsed.drive,
        root: parsed.root,
        tail,
    })
}

/// `Path(text).expanduser()` rendered as `str(...)`.
pub fn expanded_text(text: &str, env: &PathEnv) -> Result<String, AdapterError> {
    Ok(expanduser(PurePath::host(text), env)?.text())
}

fn nul_guard(text: &str) -> Result<(), AdapterError> {
    if text.contains('\0') {
        Err(AdapterError::Unsupported("native_hook_adapter_nul_path"))
    } else {
        Ok(())
    }
}

/// `_safe_resolve(path)` over `str(path)`; returns `str` of the result.
pub fn safe_resolve(text: &str, env: &PathEnv) -> Result<String, AdapterError> {
    nul_guard(text)?;
    Ok(resolve_host(text, env).unwrap_or_else(|| text.to_owned()))
}

#[cfg(unix)]
fn resolve_host(text: &str, env: &PathEnv) -> Option<String> {
    let resolved = posix_realpath(text, env)?;
    match std::fs::metadata(&resolved) {
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => None,
        _ => Some(PurePath::parse(Flavor::Posix, &resolved).text()),
    }
}

#[cfg(not(unix))]
fn resolve_host(text: &str, env: &PathEnv) -> Option<String> {
    // Windows: lexical normalization only. Final-path resolution is not ported.
    let _ = env;
    Some(PurePath::parse(Flavor::Windows, text).text())
}

#[cfg(unix)]
fn posix_join(base: &str, name: &str) -> String {
    if name.starts_with('/') {
        name.to_owned()
    } else if base.is_empty() || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

#[cfg(unix)]
fn posix_split(path: &str) -> (String, String) {
    let index = path.rfind('/').map_or(0, |index| index + 1);
    let (head, tail) = path.split_at(index);
    let head = if !head.is_empty() && head.chars().any(|ch| ch != '/') {
        head.trim_end_matches('/')
    } else {
        head
    };
    (head.to_owned(), tail.to_owned())
}

#[cfg(unix)]
fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let initial = if !path.starts_with('/') {
        0
    } else if path.starts_with("//") && !path.starts_with("///") {
        2
    } else {
        1
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".." || (initial == 0 && comps.is_empty()) || comps.last() == Some(&"..") {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let joined = comps.join("/");
    let result = format!("{}{joined}", "/".repeat(initial));
    if result.is_empty() {
        ".".to_owned()
    } else {
        result
    }
}

#[cfg(unix)]
fn posix_realpath(text: &str, env: &PathEnv) -> Option<String> {
    let mut seen = std::collections::HashMap::new();
    let (path, _ok) = joinrealpath(String::new(), text, &mut seen)?;
    let absolute = if path.starts_with('/') {
        path
    } else {
        posix_join(env.cwd.as_deref()?, &path)
    };
    Some(posix_normpath(&absolute))
}

#[cfg(unix)]
type Seen = std::collections::HashMap<String, Option<String>>;

/// `posixpath._joinrealpath`; `None` is an `OSError` raised by `readlink`.
#[cfg(unix)]
fn joinrealpath(mut path: String, rest: &str, seen: &mut Seen) -> Option<(String, bool)> {
    let mut rest = rest;
    if rest.starts_with('/') {
        rest = &rest[1..];
        path = "/".to_owned();
    }
    while !rest.is_empty() {
        let (name, remainder) = match rest.split_once('/') {
            Some((name, remainder)) => (name, remainder),
            None => (rest, ""),
        };
        rest = remainder;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            if path.is_empty() {
                path = "..".to_owned();
            } else {
                let (head, tail) = posix_split(&path);
                path = head;
                if tail == ".." {
                    path = posix_join(&posix_join(&path, ".."), "..");
                }
            }
            continue;
        }
        let newpath = posix_join(&path, name);
        let is_link = std::fs::symlink_metadata(&newpath)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false);
        if !is_link {
            path = newpath;
            continue;
        }
        match seen.get(&newpath) {
            Some(Some(resolved)) => {
                path = resolved.clone();
                continue;
            }
            Some(None) => return Some((posix_join(&newpath, rest), false)),
            None => {}
        }
        seen.insert(newpath.clone(), None);
        let target = std::fs::read_link(&newpath).ok()?;
        let target = target.to_str()?.to_owned();
        let (resolved, ok) = joinrealpath(path.clone(), &target, seen)?;
        if !ok {
            return Some((posix_join(&resolved, rest), false));
        }
        seen.insert(newpath, Some(resolved.clone()));
        path = resolved;
    }
    Some((path, true))
}

/// `redacted_workspace_label(workspace, home_dir=...)`.
pub fn workspace_label(
    workspace: &str,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<String, AdapterError> {
    let workspace_path = expanduser(PurePath::host(workspace), env)?;
    let home_path =
        match home_dir {
            Some(home) => expanduser(PurePath::host(home), env)?,
            None => PurePath::host(env.default_home.as_deref().ok_or(
                AdapterError::Unsupported("native_hook_adapter_home_unavailable"),
            )?),
        };
    let resolved_workspace = PurePath::host(&safe_resolve(&workspace_path.text(), env)?);
    let resolved_home = PurePath::host(&safe_resolve(&home_path.text(), env)?);
    if resolved_workspace.is_relative_to(&resolved_home) {
        let relative = resolved_workspace.relative_posix(&resolved_home);
        return Ok(if relative == "." {
            "~".to_owned()
        } else {
            format!("~/{relative}")
        });
    }
    let name = [resolved_workspace.name(), workspace_path.name()]
        .into_iter()
        .find(|name| !name.is_empty())
        .unwrap_or("workspace");
    Ok(format!(".../{name}"))
}

/// `_workspace_hash` preimage: `str(Path(workspace).expanduser())`.
pub fn workspace_hash_text(workspace: &str, env: &PathEnv) -> Result<String, AdapterError> {
    expanded_text(workspace, env)
}

/// `_redacted_target_path(path, home_dir=...)`.
pub fn redacted_target_path(
    path: &str,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<Option<String>, AdapterError> {
    let stripped = py_strip(path);
    if stripped.is_empty() {
        return Ok(None);
    }
    if stripped == "~" || stripped.starts_with("~/") {
        return Ok(Some(
            crate::redacted_command_tokens::redact_text(stripped).text,
        ));
    }
    if stripped.starts_with('~') {
        if let Some(context) = redacted_secret_path_context(stripped) {
            return Ok(Some(context));
        }
        let name = PurePath::host(stripped);
        let name = if name.name().is_empty() {
            "path"
        } else {
            name.name()
        };
        return Ok(Some(format!(".../{name}")));
    }
    let windows = PurePath::parse(Flavor::Windows, stripped);
    if windows.is_absolute() {
        if let Some(context) = redacted_secret_path_context(stripped) {
            return Ok(Some(context));
        }
        let name = if windows.name().is_empty() {
            "path"
        } else {
            windows.name()
        };
        return Ok(Some(format!(".../{name}")));
    }
    if PurePath::host(stripped).is_absolute() {
        let label = workspace_label(stripped, home_dir, env)?;
        if label.starts_with(".../") {
            if let Some(context) = redacted_secret_path_context(stripped) {
                return Ok(Some(context));
            }
        }
        return Ok(Some(label));
    }
    Ok(Some(
        crate::redacted_command_tokens::redact_text(stripped).text,
    ))
}
