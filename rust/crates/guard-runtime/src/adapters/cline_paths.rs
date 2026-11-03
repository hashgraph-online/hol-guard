//! `runner_authority` kind `cline_paths`: where Guard may write Cline's hooks
//! and plugin, and which managed hooks it may remove (`cline_paths.py` and
//! `cline_state_paths.py` before they moved here).
//!
//! Python reads `CLINE_DATA_DIR` and `CLINE_DIR`, expands `~` and joins a
//! relative value to its own working directory, then sends the home, the
//! Guard home and that working directory with every request:
//!
//! - `check` validates one destination from a trusted root down: a `..`
//!   segment, a symlink at any level, or a parent that resolves outside the
//!   home and the Guard home is refused before the path is used.
//! - `roots` names the Cline data directory and the hook roots Cline reads.
//! - `plugin_root` is the checked Guard plugin root under that directory.
//! - `state_paths` binds each path recorded at install to the slot it must be.
//! - `uninstall` removes the managed hooks still bound to their slots.

use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use crate::guard_paths::{python_realpath, python_realpath_lax};

const MARKER: &str = "HOL_GUARD_MANAGED_CLINE_HOOK_V1";
const EVENTS: [&str; 6] = [
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "TaskStart",
    "TaskError",
    "SessionShutdown",
];
const BASE_KEYS: [&str; 5] = ["op", "home", "guard_home", "cwd", "data_dirs"];
const ESCAPES: &str = "Cline destination escapes Guard-managed or configured Cline roots";
/// Cline runs a `.ps1` hook through PowerShell on Windows.
const HOOK_SUFFIX: &str = if cfg!(windows) { ".ps1" } else { "" };

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let extra: &[&str] = match op {
        "check" => &["path"],
        "state_paths" => &["paths", "workers", "root"],
        "roots" | "plugin_root" | "uninstall" => &[],
        _ => return Err(ERR_INVALID),
    };
    if fields.len() != BASE_KEYS.len() + extra.len()
        || !BASE_KEYS
            .iter()
            .chain(extra)
            .all(|key| fields.contains_key(*key))
    {
        return Err(ERR_INVALID);
    }
    let cline = Cline::new(fields)?;
    Ok(match op {
        "check" => {
            let path = fields
                .get("path")
                .and_then(Value::as_str)
                .ok_or(ERR_INVALID)?;
            answer(cline.check(&cline.cwd.join(path)))
        }
        "roots" => json!({
            "data_dir": text(&cline.data_dir()),
            "hook_roots": cline.hook_roots().iter().map(|root| text(root.as_path())).collect::<Vec<_>>(),
        }),
        "plugin_root" => {
            let root = cline.data_dir().join("plugins").join("hol-guard");
            answer(cline.check(&root.join("index.js")).map(|_| root))
        }
        "state_paths" => {
            let root = &fields["root"];
            json!({
                "paths": bound(&cline.bind(&fields["paths"], false, root)),
                "workers": bound(&cline.bind(&fields["workers"], true, root)),
            })
        }
        _ => cline.uninstall(),
    })
}

/// The checked path, or the refusal Python raises as `RuntimeError`.
fn answer(checked: Result<PathBuf, String>) -> Value {
    match checked {
        Ok(path) => json!({ "path": text(&path) }),
        Err(refusal) => json!({ "refusal": refusal }),
    }
}

fn bound(paths: &[Option<PathBuf>; 6]) -> Value {
    let mut map = Map::new();
    for (event, path) in EVENTS.iter().zip(paths) {
        let spelled = path.as_deref().and_then(Path::to_str);
        map.insert(
            (*event).to_owned(),
            spelled.map_or(Value::Null, Value::from),
        );
    }
    Value::Object(map)
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

/// A JSON string that Python's `isinstance(value, str) and value and "\x00"
/// not in value` accepts.
fn spelling(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|value| !value.is_empty() && !value.contains('\0'))
}

struct Cline {
    home: PathBuf,
    guard_home: PathBuf,
    home_resolved: PathBuf,
    guard_resolved: PathBuf,
    cwd: PathBuf,
    data_dirs: Vec<String>,
}

impl Cline {
    fn new(fields: &Map<String, Value>) -> Result<Self, &'static str> {
        let absolute = |key: &str| {
            let path = PathBuf::from(fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)?);
            if path.is_absolute() {
                Ok(path)
            } else {
                Err(ERR_INVALID)
            }
        };
        let home = absolute("home")?;
        let guard_home = absolute("guard_home")?;
        let resolve = |path: &Path| python_realpath_lax(path).map_err(|_| ERR_INVALID);
        let data_dirs: Vec<String> = fields
            .get("data_dirs")
            .and_then(Value::as_array)
            .filter(|values| values.len() == 2)
            .ok_or(ERR_INVALID)?
            .iter()
            .map(|value| value.as_str().map(str::to_owned).ok_or(ERR_INVALID))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            home_resolved: resolve(&home)?,
            guard_resolved: resolve(&guard_home)?,
            cwd: absolute("cwd")?,
            home,
            guard_home,
            data_dirs,
        })
    }

    /// `_safe_configured_data_dir`: a configured directory counts only while
    /// it resolves inside the home, so an inherited variable cannot send
    /// Guard's writes anywhere else.
    fn configured(&self, value: &str) -> Option<PathBuf> {
        if value.is_empty() {
            return None;
        }
        let candidate = python_realpath_lax(Path::new(value)).ok()?;
        candidate
            .starts_with(&self.home_resolved)
            .then_some(candidate)
    }

    /// `cline_data_dir`: `CLINE_DATA_DIR`, then the legacy `CLINE_DIR`, then
    /// `~/.cline`.
    fn data_dir(&self) -> PathBuf {
        self.data_dirs
            .iter()
            .find_map(|value| self.configured(value))
            .unwrap_or_else(|| self.home.join(".cline"))
    }

    /// `cline_hook_roots`: the UI's hooks folder and the data directory's,
    /// with a configured data directory read first.
    fn hook_roots(&self) -> Vec<PathBuf> {
        let data_dir = self.data_dir();
        let data_hooks = data_dir.join("hooks");
        let mut candidates = vec![
            self.home.join("Documents").join("Cline").join("Hooks"),
            data_hooks.clone(),
            self.home.join(".cline").join("hooks"),
        ];
        if self
            .data_dirs
            .iter()
            .any(|value| self.configured(value).as_ref() == Some(&data_dir))
        {
            candidates.insert(0, data_hooks);
        }
        let mut unique: Vec<PathBuf> = Vec::new();
        for candidate in candidates {
            if !unique.contains(&candidate) {
                unique.push(candidate);
            }
        }
        unique
    }

    /// `ensure_safe_cline_destination`: the destination rebuilt beneath the
    /// first trusted root that holds it. `..` and NUL are refused before any
    /// filesystem probe, and a root that is itself the destination is no
    /// destination at all.
    fn check(&self, path: &Path) -> Result<PathBuf, String> {
        if path.as_os_str().as_encoded_bytes().contains(&0)
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(ESCAPES.to_owned());
        }
        let destination: PathBuf = self.cwd.join(path).components().collect();
        for root in [
            &self.home_resolved,
            &self.guard_resolved,
            &self.home,
            &self.guard_home,
        ] {
            let Ok(relative) = destination.strip_prefix(root) else {
                continue;
            };
            if relative.as_os_str().is_empty() {
                continue;
            }
            return self.walk(root, relative);
        }
        Err(ESCAPES.to_owned())
    }

    /// `_checked_cline_destination`: every level from the root down must not
    /// be a symlink, checked outermost first, and the parent must still
    /// resolve inside the home or the Guard home.
    fn walk(&self, root: &Path, relative: &Path) -> Result<PathBuf, String> {
        let mut current = root.to_path_buf();
        if is_symlink(&current) {
            return Err(format!(
                "Cline destination parent is a symlink: {}",
                current.display()
            ));
        }
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err("Cline destination contains an unsafe path component".to_owned());
            };
            current.push(name);
            if is_symlink(&current) {
                return Err(format!(
                    "Cline destination is a symlink: {}",
                    current.display()
                ));
            }
        }
        let parent = current.parent().unwrap_or(&current);
        let resolved = python_realpath_lax(parent).map_err(|_| ESCAPES.to_owned())?;
        if resolved.starts_with(&self.home_resolved) || resolved.starts_with(&self.guard_resolved) {
            Ok(current)
        } else {
            Err(ESCAPES.to_owned())
        }
    }

    /// `_canonical_saved_hook_root`: a custom hooks folder recorded at
    /// install, kept after its environment override changes while it still
    /// resolves inside the home.
    fn saved_hook_root(&self, value: &Value) -> Option<PathBuf> {
        let recorded = Path::new(spelling(value)?);
        let name = recorded.file_name()?.to_str()?;
        if !recorded.is_absolute() || name.to_lowercase() != "hooks" {
            return None;
        }
        let checked = self
            .check(&recorded.join(format!("PreToolUse{HOOK_SUFFIX}")))
            .ok()?;
        let resolved = python_realpath(checked.parent()?).ok().flatten()?;
        resolved
            .starts_with(&self.home_resolved)
            .then_some(resolved)
    }

    /// `canonical_cline_state_path` for each event of one recorded group.
    fn bind(&self, group: &Value, worker: bool, saved_root: &Value) -> [Option<PathBuf>; 6] {
        let group = group.as_object();
        let saved = (!worker)
            .then(|| self.saved_hook_root(saved_root))
            .flatten();
        EVENTS.map(|event| {
            let value = group.and_then(|group| group.get(event))?;
            self.state_path(event, value, worker, saved.as_ref())
        })
    }

    /// One recorded path bound to the slot derived from trusted context: the
    /// resolved slot when the recording resolves to it, otherwise `None`.
    fn state_path(
        &self,
        event: &str,
        value: &Value,
        worker: bool,
        saved_root: Option<&PathBuf>,
    ) -> Option<PathBuf> {
        let recorded = Path::new(spelling(value)?);
        if !recorded.is_absolute() {
            return None;
        }
        let candidates: Vec<PathBuf> = if worker {
            // Native worker configs are `.json`; earlier installs wrote Python workers.
            let workers = self
                .guard_home
                .join("managed")
                .join("cline")
                .join("hook-workers");
            vec![
                workers.join(format!("{event}.json")),
                workers.join(format!("{event}.py")),
            ]
        } else {
            let mut roots = self.hook_roots();
            if let Some(saved) = saved_root {
                if !roots.contains(saved) {
                    roots.push(saved.clone());
                }
            }
            roots
                .iter()
                .map(|root| root.join(format!("{event}{HOOK_SUFFIX}")))
                .collect()
        };
        let recorded = python_realpath(recorded).ok().flatten()?;
        candidates.iter().find_map(|candidate| {
            self.check(candidate).ok()?;
            let resolved = python_realpath(candidate).ok().flatten()?;
            (resolved == recorded).then_some(resolved)
        })
    }

    /// `uninstall_persisted_cline_hooks`: remove only the managed hooks still
    /// bound to their slots, and the install record once nothing is left.
    fn uninstall(&self) -> Value {
        let state_path = self
            .guard_home
            .join("managed")
            .join("cline")
            .join("native-hooks-state.json");
        let state = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .unwrap_or(Value::Null);
        let field = |key: &str| state.get(key).unwrap_or(&Value::Null);
        let mut removed = Vec::new();
        let mut retained = Vec::new();
        for (group, worker) in [("paths", false), ("workers", true)] {
            let paths = self.bind(field(group), worker, field("root"));
            let recorded = field(group);
            for (event, path) in EVENTS.iter().zip(paths) {
                let Some(value) = recorded.get(*event).and_then(Value::as_str) else {
                    continue;
                };
                let Some(path) = path else {
                    // An unbound recording is never removed; one that still
                    // exists is reported so the caller knows it remains.
                    if self.cwd.join(value).exists() {
                        retained.push(value.to_owned());
                    }
                    continue;
                };
                if is_managed(&path) && std::fs::remove_file(&path).is_ok() {
                    removed.push(text(&path));
                } else {
                    retained.push(text(&path));
                }
            }
        }
        if retained.is_empty() && state_path.is_file() && std::fs::remove_file(&state_path).is_err()
        {
            retained.push(text(&state_path));
        }
        json!({
            "transport": "hooks",
            "complete": retained.is_empty(),
            "removed": removed,
            "retained_modified_or_unowned": retained,
        })
    }
}

/// A regular file, not a symlink, that carries Guard's managed marker.
fn is_managed(path: &Path) -> bool {
    path.is_file()
        && !is_symlink(path)
        && std::fs::read_to_string(path).is_ok_and(|text| text.contains(MARKER))
}

#[cfg(all(test, unix))]
#[path = "cline_paths_tests.rs"]
mod tests;
