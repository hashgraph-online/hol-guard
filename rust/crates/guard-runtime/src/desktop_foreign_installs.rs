//! `desktop-foreign-inventory --stdin`: the HOL Guard installs a
//! Desktop-managed Core supersedes (`guard/desktop_foreign_installs.py`
//! before the inventory moved here).
//!
//! A pipx or uv tool venv, a `pip --user` install, or a stale link left in a
//! bin directory keeps an older `hol-guard` on PATH. This command only finds
//! them; `desktop-foreign-remove` removes them once the caller has stopped
//! their residents, so a resident that will not stop keeps its install.
//!
//! The runtime runs with an isolated environment and its own working
//! directory, so the caller sends the variables and the directory the lookup
//! reads. A relative configured path is anchored to that directory, since
//! the runtime's own working directory is elsewhere. Paths follow `pathlib`:
//! a lexical spelling for what is reported, a non-strict `resolve` for what is
//! compared, and `normpath` for a link target that may no longer exist.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf, MAIN_SEPARATOR};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cloud_request_text::py_strip;

#[path = "desktop_foreign_paths.rs"]
mod paths;

use paths::{
    contains, exists, glob_prefix_matches, head, is_dir, is_file, is_python_name, is_symlink,
    link_target, path_key, pure, text, texts, within,
};

const COMMAND: &str = "desktop-foreign-inventory";
const SCHEMA: &str = "desktop-foreign-inventory.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
/// Sorted, as `sorted(PACKAGE_DIR_NAMES)` visits them.
const PACKAGE_DIR_NAMES: [&str; 2] = ["hol-guard", "hol_guard"];
const ENTRY_POINT_NAMES: [&str; 6] = [
    "hol-guard",
    "hol-guard-eval",
    "hol-guard-secrets",
    "plugin-scanner",
    "plugin-guard",
    "plugin-ecosystem-scanner",
];
const DESKTOP_PATH_SHIM_MARKER: &[u8] = b"HOL_GUARD_DESKTOP_USER_PATH_SHIM";
const DESKTOP_DATA_DIR_NAME: &str = "org.hol.guard.desktop";
const SCRIPT_PACKAGE_MARKER: &[u8] = b"codex_plugin_scanner";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    home: String,
    cwd: String,
    path: String,
    environment: BTreeMap<String, String>,
    protected: Vec<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "desktop_foreign_inventory_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("desktop_foreign_inventory_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let cwd = pure(&request.cwd);
    if !cwd.is_absolute() {
        return Err(invalid());
    }
    let host = Host {
        home: cwd.join(pure(&request.home)),
        cwd,
        environment: request.environment,
    };
    let protected: Vec<PathBuf> = request
        .protected
        .iter()
        .map(String::as_str)
        .map(pure)
        .collect();
    serde_json::to_vec(&host.inventory(&request.path, &protected))
        .map_err(|_| "desktop_foreign_inventory_response_unencodable".to_owned())
}

fn invalid() -> String {
    "desktop_foreign_inventory_request_invalid".to_owned()
}

/// One tool venv that installed the hol-guard package.
struct Candidate {
    kind: &'static str,
    root: PathBuf,
    runtimes: Vec<PathBuf>,
    entries: Vec<PathBuf>,
}

struct Host {
    home: PathBuf,
    cwd: PathBuf,
    environment: BTreeMap<String, String>,
}

impl Host {
    fn inventory(&self, path_env: &str, protected: &[PathBuf]) -> Value {
        let collections: Vec<(&'static str, PathBuf)> = self
            .pipx_venv_dirs()
            .into_iter()
            .map(|root| ("pipx", root))
            .chain(self.uv_tool_dirs().into_iter().map(|root| ("uv", root)))
            .collect();
        let mut candidates = Vec::new();
        for &(kind, ref collection) in &collections {
            for name in PACKAGE_DIR_NAMES {
                let venv = collection.join(name);
                if !is_dir(&venv) || is_symlink(&venv) || self.contains_any(&venv, protected) {
                    continue;
                }
                // A runtime that cannot be named cannot be stopped first.
                if let Some(runtimes) = self.venv_runtimes(&venv) {
                    candidates.push(Candidate {
                        kind,
                        root: venv,
                        runtimes,
                        entries: Vec::new(),
                    });
                }
            }
        }
        let mut stale = Vec::new();
        let mut user_site: Vec<(PathBuf, Vec<PathBuf>)> = Vec::new();
        for entry in self.bin_entries(path_env) {
            if self.desktop_owned_entry(&entry) {
                continue;
            }
            let owner = candidates
                .iter()
                .position(|candidate| self.entry_belongs_to(&entry, &candidate.root));
            if let Some(owner) = owner {
                candidates[owner].entries.push(entry);
            } else if dangling_tool_link(&entry, &collections) {
                stale.push(entry);
            } else if let Some(interpreter) = user_site_interpreter(&entry) {
                match user_site
                    .iter()
                    .position(|(known, _)| *known == interpreter)
                {
                    Some(index) => user_site[index].1.push(entry),
                    None => user_site.push((interpreter, vec![entry])),
                }
            }
        }
        let venvs: Vec<Value> = candidates
            .iter()
            .map(|candidate| {
                json!({
                    "kind": candidate.kind,
                    "root": text(&candidate.root),
                    "entries": texts(&candidate.entries),
                    "runtimes": texts(&candidate.runtimes),
                })
            })
            .collect();
        let user_site: Vec<Value> = user_site
            .iter()
            .map(|(interpreter, entries)| {
                json!({"interpreter": text(interpreter), "entries": texts(entries)})
            })
            .collect();
        json!({"venvs": venvs, "stale_entries": texts(&stale), "user_site": user_site})
    }

    fn pipx_venv_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self
            .env_path("PIPX_HOME")
            .map(|pipx_home| pipx_home.join("venvs"))
            .into_iter()
            .collect();
        dirs.push(self.home.join(".local").join("pipx").join("venvs"));
        dirs.push(self.data_home().join("pipx").join("venvs"));
        if cfg!(target_os = "macos") {
            dirs.push(
                self.home
                    .join("Library")
                    .join("Application Support")
                    .join("pipx")
                    .join("venvs"),
            );
        }
        if cfg!(windows) {
            dirs.push(self.home.join("pipx").join("venvs"));
            let local_appdata = self
                .env_path("LOCALAPPDATA")
                .unwrap_or_else(|| self.home.join("AppData").join("Local"));
            dirs.push(local_appdata.join("pipx").join("pipx").join("venvs"));
        }
        self.unique(dirs)
    }

    fn uv_tool_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self.env_path("UV_TOOL_DIR").into_iter().collect();
        dirs.push(self.data_home().join("uv").join("tools"));
        if cfg!(windows) {
            let appdata = self
                .env_path("APPDATA")
                .unwrap_or_else(|| self.home.join("AppData").join("Roaming"));
            dirs.push(appdata.join("uv").join("tools"));
        }
        self.unique(dirs)
    }

    fn bin_dirs(&self, path_env: &str) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = ["PIPX_BIN_DIR", "UV_TOOL_BIN_DIR", "XDG_BIN_HOME"]
            .into_iter()
            .filter_map(|name| self.env_path(name))
            .collect();
        dirs.push(self.home.join(".local").join("bin"));
        let resolved_home = self.resolve(&self.home);
        let separator = if cfg!(windows) { ';' } else { ':' };
        for entry in path_env.split(separator) {
            if py_strip(entry).is_empty() {
                continue;
            }
            let directory = self.anchored(pure(&self.expanduser(entry)));
            if within(&self.resolve(&directory), &resolved_home) {
                dirs.push(directory);
            }
        }
        self.unique(dirs)
    }

    fn bin_entries(&self, path_env: &str) -> Vec<PathBuf> {
        let names = entry_file_names();
        let mut entries = Vec::new();
        for directory in self.bin_dirs(path_env) {
            for name in &names {
                let entry = directory.join(name);
                if is_symlink(&entry) || is_file(&entry) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    fn data_home(&self) -> PathBuf {
        self.env_path("XDG_DATA_HOME")
            .unwrap_or_else(|| self.home.join(".local").join("share"))
    }

    /// `_env_path`: a set, non-blank variable as a user-expanded path.
    fn env_path(&self, name: &str) -> Option<PathBuf> {
        let value = py_strip(self.environment.get(name)?);
        (!value.is_empty()).then(|| self.anchored(pure(&self.expanduser(value))))
    }

    /// A configured path as the caller reads it from its own directory.
    fn anchored(&self, path: PathBuf) -> PathBuf {
        if path == Path::new(".") {
            self.cwd.clone()
        } else {
            self.cwd.join(path)
        }
    }

    /// `os.path.expanduser` for `~`, `~/...` and this user's own `~name`.
    /// Another account's `~name` is left as written: its tool installs are
    /// not this user's to retire.
    fn expanduser(&self, value: &str) -> String {
        let Some(rest) = value.strip_prefix('~') else {
            return value.to_owned();
        };
        let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
        let (name, tail) = rest.split_at(rest.find(separators).unwrap_or(rest.len()));
        let Some(home) = self.user_home() else {
            return value.to_owned();
        };
        if !name.is_empty() && !self.names_this_user(name) {
            return value.to_owned();
        }
        let expanded = format!("{}{tail}", home.trim_end_matches(separators));
        if expanded.is_empty() {
            MAIN_SEPARATOR.to_string()
        } else {
            expanded
        }
    }

    /// Whether `~name` names the login the environment carries.
    fn names_this_user(&self, name: &str) -> bool {
        let logins: &[&str] = if cfg!(windows) {
            &["USERNAME"]
        } else {
            &["USER", "LOGNAME"]
        };
        logins
            .iter()
            .any(|login| self.environment.get(*login).map(String::as_str) == Some(name))
    }

    fn user_home(&self) -> Option<String> {
        let variable = |name: &str| self.environment.get(name).cloned();
        if !cfg!(windows) {
            return variable("HOME");
        }
        variable("USERPROFILE").or_else(|| Some(variable("HOMEDRIVE")? + &variable("HOMEPATH")?))
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        paths::resolve(&self.cwd, path)
    }

    /// `_unique`: first spelling of each resolved path.
    fn unique(&self, paths: Vec<PathBuf>) -> Vec<PathBuf> {
        let mut seen = Vec::new();
        let mut result = Vec::new();
        for path in paths {
            let key = path_key(&self.resolve(&path));
            if !seen.contains(&key) {
                seen.push(key);
                result.push(path);
            }
        }
        result
    }

    fn contains_any(&self, root: &Path, paths: &[PathBuf]) -> bool {
        let resolved = self.resolve(root);
        paths.iter().any(|path| within(path, &resolved))
    }

    fn desktop_owned_entry(&self, entry: &Path) -> bool {
        self.resolve(entry)
            .components()
            .any(|part| part.as_os_str() == OsStr::new(DESKTOP_DATA_DIR_NAME))
            || contains(&head(entry), DESKTOP_PATH_SHIM_MARKER)
    }

    fn entry_belongs_to(&self, entry: &Path, venv: &Path) -> bool {
        if is_symlink(entry) && within(&link_target(entry), venv) {
            return true;
        }
        let resolved_venv = self.resolve(venv);
        if within(&self.resolve(entry), &resolved_venv) {
            return true;
        }
        let content = head(entry);
        // The trailing separator keeps a sibling venv such as `hol-guard-dev` out.
        let needles = [venv, resolved_venv.as_path()].map(|root| {
            let mut needle = root.as_os_str().to_owned();
            needle.push(MAIN_SEPARATOR.to_string());
            needle
        });
        if cfg!(windows) {
            let lowered = content.to_ascii_lowercase();
            return needles.iter().any(|needle| {
                contains(&lowered, needle.to_string_lossy().to_lowercase().as_bytes())
            });
        }
        needles
            .iter()
            .any(|needle| contains(&content, needle.as_encoded_bytes()))
    }

    /// `_venv_runtimes`, or `None` when one cannot be reported by name.
    fn venv_runtimes(&self, venv: &Path) -> Option<Vec<PathBuf>> {
        let name = if cfg!(windows) {
            "hol-guard-runtime.exe"
        } else {
            "hol-guard-runtime"
        };
        let tail = |site_packages: PathBuf| {
            site_packages
                .join("codex_plugin_scanner")
                .join("guard")
                .join("_native")
                .join(name)
        };
        let mut found = Vec::new();
        if let Ok(listing) = fs::read_dir(venv.join("lib")) {
            let mut names = Vec::new();
            for item in listing.flatten() {
                let file_name = item.file_name();
                let Some(spelled) = file_name.to_str() else {
                    if file_name.as_encoded_bytes().starts_with(b"python") {
                        return None;
                    }
                    continue;
                };
                if glob_prefix_matches(spelled, "python") {
                    names.push(spelled.to_owned());
                }
            }
            names.sort();
            for directory in names {
                let path = tail(venv.join("lib").join(directory).join("site-packages"));
                if is_file(&path) {
                    found.push(path);
                }
            }
        }
        let windows_layout = tail(venv.join("Lib").join("site-packages"));
        if is_file(&windows_layout) {
            found.push(windows_layout);
        }
        Some(self.unique(found))
    }
}

fn dangling_tool_link(entry: &Path, collections: &[(&'static str, PathBuf)]) -> bool {
    if !is_symlink(entry) || exists(entry) {
        return false;
    }
    let target = link_target(entry);
    collections.iter().any(|(_, collection)| {
        PACKAGE_DIR_NAMES
            .iter()
            .any(|name| within(&target, &collection.join(name)))
    })
}

/// `_user_site_interpreter`: the system interpreter behind a `pip --user`
/// console script. Whether hol-guard really sits in its user site is checked
/// just before removal, so a script for a system install is left alone.
fn user_site_interpreter(entry: &Path) -> Option<PathBuf> {
    if cfg!(windows) || is_symlink(entry) {
        return None;
    }
    let content = head(entry);
    let script = content.strip_prefix(b"#!")?;
    if !contains(&content, SCRIPT_PACKAGE_MARKER) {
        return None;
    }
    let line = script
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut words = py_strip(&line).split_whitespace();
    let (Some(word), None) = (words.next(), words.next()) else {
        return None;
    };
    let interpreter = pure(word);
    if !interpreter.is_absolute() || !is_file(&interpreter) {
        return None;
    }
    // A user's own shell wrapper that calls Guard is not a pip console script.
    if !interpreter
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(is_python_name)
    {
        return None;
    }
    let parent = |path: &Path| path.parent().unwrap_or(path).to_path_buf();
    if is_file(&parent(&parent(&interpreter)).join("pyvenv.cfg")) {
        return None;
    }
    Some(interpreter)
}

fn entry_file_names() -> Vec<String> {
    if !cfg!(windows) {
        return ENTRY_POINT_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
    }
    ENTRY_POINT_NAMES
        .iter()
        .flat_map(|name| ["", ".exe", ".cmd"].map(|suffix| format!("{name}{suffix}")))
        .collect()
}

#[cfg(test)]
#[path = "desktop_foreign_installs_tests.rs"]
mod tests;
