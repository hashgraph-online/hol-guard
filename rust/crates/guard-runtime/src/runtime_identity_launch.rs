//! Resolve the executable a configured MCP server launch would run, for
//! `runtime-identity-probe`.
//!
//! A launch spec carries the configured command, the server's own `PATH` when
//! it sets one, and the directory the launch runs in; the request carries the
//! process environment values the caller chose to share. A bare command is
//! looked up through the search path the server would use, so the answer is
//! the file a launch would find rather than whatever a login shell prints.
//! Relative commands and relative search path entries resolve against the
//! launch directory. A launcher script's `#!` interpreter is added as a second
//! candidate, one level deep.
//!
//! Nothing here starts a process, opens anything that is not a regular file,
//! or reads more than a script's first line. Environment values are used to
//! expand search paths and are never copied into a reply.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Metadata};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::runtime_identity_launch_shebang::shebang_interpreter;

pub(crate) const FEATURE: &str = "runtime-identity-launch-v1";
pub(crate) const MAX_LAUNCHES: usize = 2_048;
pub(crate) const DEFAULT_CANDIDATE_LIMIT: usize = 64;
pub(crate) const MAX_TEXT_BYTES: usize = 4_096;

const LOOKUP_SEARCH_PATH: &str = "search_path";
const LOOKUP_CONFIGURED_PATH: &str = "configured_path";
const ROLE_LAUNCH: &str = "launch";
const ROLE_INTERPRETER: &str = "interpreter";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LaunchSpec {
    pub command: String,
    #[serde(default)]
    pub configured_path: Option<String>,
    pub launch_dir: String,
}

impl LaunchSpec {
    pub(crate) fn is_valid(&self) -> bool {
        let text_ok = |text: &str| text.len() <= MAX_TEXT_BYTES && !text.contains('\0');
        text_ok(&self.command)
            && self.configured_path.as_deref().is_none_or(text_ok)
            && text_ok(&self.launch_dir)
            && Path::new(&self.launch_dir).is_absolute()
    }
}

/// The process environment values a request shares. A name matches exactly
/// first, then case-insensitively, the way a harness reads its own variables.
pub(crate) struct Environment<'a>(pub &'a BTreeMap<String, String>);

impl Environment<'_> {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .or_else(|| {
                self.0
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value)
            })
            .map(String::as_str)
    }
}

/// What the probe takes from the launches: replies per spec and the sorted
/// candidate paths to describe.
pub(crate) struct Collected {
    pub launches: Vec<Value>,
    pub paths: Vec<String>,
    pub truncated: bool,
}

pub(crate) fn collect(specs: &[LaunchSpec], env: &Environment, limit: usize) -> Collected {
    let mut admitted: BTreeSet<String> = BTreeSet::new();
    let mut truncated = false;
    let mut launches = Vec::with_capacity(specs.len());
    for (index, spec) in specs.iter().enumerate() {
        let resolved = resolve(spec, env);
        let state = if resolved.targets.is_empty() {
            "unresolved"
        } else {
            "resolved"
        };
        let mut targets = Vec::new();
        for (path, role) in &resolved.targets {
            if !admitted.contains(path) && admitted.len() >= limit {
                truncated = true;
                continue;
            }
            admitted.insert(path.clone());
            targets.push(json!({"path": path, "role": role}));
        }
        launches.push(json!({
            "index": index,
            "state": state,
            "lookup": resolved.lookup,
            "targets": targets,
        }));
    }
    Collected {
        launches,
        paths: admitted.into_iter().collect(),
        truncated,
    }
}

struct Resolution {
    lookup: &'static str,
    /// Empty when nothing was found; a launch and, for a script, its interpreter.
    targets: Vec<(String, &'static str)>,
}

fn resolve(spec: &LaunchSpec, env: &Environment) -> Resolution {
    let text = spec.command.trim();
    let launch_dir = Path::new(&spec.launch_dir);
    let search_path = anchored_search_path(spec, env, launch_dir);
    let explicit = is_explicit_path(text);
    let lookup = if explicit {
        LOOKUP_CONFIGURED_PATH
    } else {
        LOOKUP_SEARCH_PATH
    };
    let launch = if text.is_empty() {
        None
    } else if explicit {
        explicit_file(text, launch_dir, env)
    } else {
        which(text, search_path.as_deref(), env)
    };
    let Some(launch) = launch else {
        return Resolution {
            lookup,
            targets: Vec::new(),
        };
    };
    let mut targets = vec![(launch.clone(), ROLE_LAUNCH)];
    if let Some(interpreter) =
        shebang_interpreter(&launch, |name| which(name, search_path.as_deref(), env))
    {
        if interpreter != launch {
            targets.push((interpreter, ROLE_INTERPRETER));
        }
    }
    Resolution { lookup, targets }
}

fn is_explicit_path(command: &str) -> bool {
    command.contains('/') || (cfg!(windows) && command.contains('\\'))
}

fn explicit_file(text: &str, launch_dir: &Path, env: &Environment) -> Option<String> {
    let expanded = expand_home(text, env);
    let candidate = Path::new(&expanded);
    let anchored = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        launch_dir.join(candidate)
    };
    let normalized = normalize(&anchored);
    is_regular_file(&normalized).then(|| normalized.to_string_lossy().into_owned())
}

/// `~` and `~/..` follow the home variable the caller shared; `~name` is left alone.
fn expand_home(text: &str, env: &Environment) -> String {
    let rest = if text == "~" {
        Some("")
    } else {
        text.strip_prefix("~/")
            .or_else(|| text.strip_prefix("~\\").filter(|_| cfg!(windows)))
    };
    let home = if cfg!(windows) {
        env.get("USERPROFILE").or_else(|| env.get("HOME"))
    } else {
        env.get("HOME")
    };
    match (rest, home) {
        (Some(rest), Some(home)) if !home.is_empty() => normalize(&Path::new(home).join(rest))
            .to_string_lossy()
            .into_owned(),
        _ => text.to_owned(),
    }
}

/// Drop `.` components and doubled separators; `..` is kept, as the file system sees it.
fn normalize(path: &Path) -> PathBuf {
    path.components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect()
}

pub(crate) fn path_separator() -> char {
    if cfg!(windows) {
        ';'
    } else {
        ':'
    }
}

/// The search path a launch uses, with relative and empty entries made
/// absolute against the launch directory. `None` means no path is known.
fn anchored_search_path(spec: &LaunchSpec, env: &Environment, launch_dir: &Path) -> Option<String> {
    let configured = spec
        .configured_path
        .as_deref()
        .filter(|path| !path.is_empty());
    let raw = match configured {
        // A variable this request lacks cannot be interpreted faithfully, so
        // the path is empty and the launch is reported unresolved.
        Some(path) => Some(expand_placeholders(path, env).unwrap_or_default()),
        None => env.get("PATH").map(str::to_owned),
    }?;
    if raw.is_empty() {
        return Some(raw);
    }
    let separator = path_separator();
    let entries: Vec<String> = raw
        .split(separator)
        .map(|entry| {
            if Path::new(entry).is_absolute() {
                entry.to_owned()
            } else {
                launch_dir.join(entry).to_string_lossy().into_owned()
            }
        })
        .collect();
    Some(entries.join(&separator.to_string()))
}

/// Expand `$NAME`, `${NAME}` and `%NAME%`. `None` when any variable is unknown.
fn expand_placeholders(value: &str, env: &Environment) -> Option<String> {
    static PLACEHOLDER: OnceLock<Regex> = OnceLock::new();
    let pattern = PLACEHOLDER
        .get_or_init(|| Regex::new(r"\$\{(\w+)\}|\$(\w+)|%(\w+)%").expect("static pattern"));
    let mut unknown = false;
    let expanded = pattern.replace_all(value, |captures: &Captures| {
        let name = (1..=3)
            .find_map(|group| captures.get(group))
            .map_or("", |found| found.as_str());
        match env.get(name) {
            Some(found) => found.to_owned(),
            None => {
                unknown = true;
                captures[0].to_owned()
            }
        }
    });
    (!unknown).then(|| expanded.into_owned())
}

/// The absolute regular file `name` resolves to through `search_path`. The
/// first match wins, and a FIFO or device there is never a runtime.
pub(crate) fn which(name: &str, search_path: Option<&str>, env: &Environment) -> Option<String> {
    let search_path = search_path.filter(|path| !path.is_empty())?;
    let names = candidate_names(name, env);
    for directory in search_path.split(path_separator()) {
        for file in &names {
            let path = Path::new(directory).join(file);
            if is_launchable(&path) {
                return (path.is_absolute() && is_regular_file(&path))
                    .then(|| normalize(&path).to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// File names a lookup tries in one directory: `PATHEXT` extensions on Windows.
fn candidate_names(name: &str, env: &Environment) -> Vec<String> {
    if !cfg!(windows) {
        return vec![name.to_owned()];
    }
    let pathext = env
        .get("PATHEXT")
        .filter(|value| !value.is_empty())
        .unwrap_or(".COM;.EXE;.BAT;.CMD");
    let extensions: Vec<&str> = pathext.split(';').filter(|ext| !ext.is_empty()).collect();
    let lowered = name.to_ascii_lowercase();
    if extensions
        .iter()
        .any(|ext| lowered.ends_with(&ext.to_ascii_lowercase()))
    {
        return vec![name.to_owned()];
    }
    extensions
        .iter()
        .map(|ext| format!("{name}{ext}"))
        .collect()
}

/// Exists, is not a directory, and could be executed.
fn is_launchable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| !meta.is_dir() && is_executable(&meta))
}

#[cfg(unix)]
fn is_executable(meta: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &Metadata) -> bool {
    // Windows has no execute bit; `candidate_names` applies `PATHEXT` instead.
    true
}

/// Follows symlinks: the file a launch would reach, not the link.
pub(crate) fn is_regular_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

#[cfg(test)]
#[path = "runtime_identity_launch_tests.rs"]
pub(crate) mod tests;
