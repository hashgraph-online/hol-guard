//! Shared pieces of the Gemini, Antigravity, Devin, Grok and Kimi detection kinds: the request
//! (home and workspace as Python holds them, plus its working directory when
//! either is relative), the `_json_payload` reader, and an inventory that
//! keeps found paths unique and walks skill roots with the same native
//! discovery and directory identity the Python adapters called. Every string
//! the inventory carries must be encodable: a lone surrogate CPython would
//! keep is refused, never dropped.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::aibom_paths::{py_join, py_path};
use super::aibom_skills::{identity_metadata, LIMITS};
use super::pyjson::LONE_SURROGATE_MARK;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::skill_identity_discovery::discover_skill_documents;
use super::skill_identity_inspect::inspect_skill_directory;
use super::zcode_artifacts::{Fields, Scope};

pub(crate) const ERR_STAT: &str = "native_runner_authority_adapter_path_unexaminable";

pub(crate) use guard_adapter_detection::{
    carried, json_document, json_payload, mcp_fields, SkillNaming, ERR_NAME, ERR_VALUE,
};

/// The directories one detection request names.
pub(crate) struct Request {
    pub(crate) home: PathBuf,
    pub(crate) workspace: Option<PathBuf>,
    cwd: Option<PathBuf>,
}

fn path_arg(args: &Map<String, Value>, key: &str) -> Result<Option<PathBuf>, &'static str> {
    match args.get(key) {
        Some(Value::String(path)) if !path.contains('\0') => Ok(Some(py_path(path))),
        None | Some(Value::Null) if key == "workspace" => Ok(None),
        _ => Err(ERR_INVALID),
    }
}

/// A path field every request of one kind names (a string without NUL).
pub(crate) fn required_path(args: &Value, key: &str) -> Result<PathBuf, &'static str> {
    path_arg(args_object(args)?, key)?.ok_or(ERR_INVALID)
}

/// The OS error codes Python 3.12's `Path.is_file`, `is_dir` and `exists`
/// treat as "absent" beyond not-found and not-a-directory.
#[cfg(unix)]
fn ignorable_code(code: i32) -> bool {
    const EBADF: i32 = 9;
    const ELOOP: i32 = if cfg!(target_os = "macos") { 62 } else { 40 };
    code == EBADF || code == ELOOP
}

#[cfg(windows)]
fn ignorable_code(code: i32) -> bool {
    matches!(code, 21 | 123 | 1921)
}

#[cfg(not(any(unix, windows)))]
fn ignorable_code(_code: i32) -> bool {
    false
}

/// `path.stat()` as Python 3.12's `Path.is_file`/`is_dir`/`exists` see it:
/// `None` when absent, a refusal for any error Python would raise (a parent
/// it may not search, an over-long name).
pub(crate) fn py_stat(path: &Path) -> Result<Option<fs::Metadata>, &'static str> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) || error.raw_os_error().is_some_and(ignorable_code) =>
        {
            Ok(None)
        }
        Err(_) => Err(ERR_STAT),
    }
}

impl Request {
    pub(crate) fn parse(args: &Value, harness: &str) -> Result<Self, &'static str> {
        let args = args_object(args)?;
        if args.get("harness").and_then(Value::as_str) != Some(harness) {
            return Err(ERR_INVALID);
        }
        let home = path_arg(args, "home")?.ok_or(ERR_INVALID)?;
        let workspace = path_arg(args, "workspace")?;
        let cwd = match args.get("cwd") {
            None | Some(Value::Null) => None,
            Some(Value::String(cwd)) if !cwd.contains('\0') && Path::new(cwd).is_absolute() => {
                Some(PathBuf::from(cwd))
            }
            Some(_) => return Err(ERR_INVALID),
        };
        let relative =
            !home.is_absolute() || workspace.as_ref().is_some_and(|path| !path.is_absolute());
        if relative && cwd.is_none() {
            return Err(ERR_INVALID);
        }
        Ok(Self {
            home,
            workspace,
            cwd,
        })
    }

    /// A further directory the request names, read from Python's `cwd` when
    /// it is relative.
    pub(crate) fn path(&self, args: &Value, key: &str) -> Result<PathBuf, &'static str> {
        let path = path_arg(args_object(args)?, key)?.ok_or(ERR_INVALID)?;
        if !path.is_absolute() && self.cwd.is_none() {
            return Err(ERR_INVALID);
        }
        Ok(path)
    }
}

fn carries_lone_surrogate(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains(LONE_SURROGATE_MARK),
        Value::Array(items) => items.iter().any(carries_lone_surrogate),
        Value::Object(map) => map
            .iter()
            .any(|(key, item)| key.contains(LONE_SURROGATE_MARK) || carries_lone_surrogate(item)),
        _ => false,
    }
}

pub(crate) struct Inventory {
    cwd: Option<PathBuf>,
    workspace: Option<PathBuf>,
    pub(crate) artifacts: Vec<Value>,
    found_paths: Vec<String>,
    warnings: Vec<String>,
}

impl Inventory {
    pub(crate) fn new(request: &Request) -> Self {
        Self {
            cwd: request.cwd.clone(),
            workspace: request.workspace.clone(),
            artifacts: Vec::new(),
            found_paths: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Where `path` is on disk: a relative path is read from Python's `cwd`.
    pub(crate) fn fs(&self, path: &Path) -> PathBuf {
        match &self.cwd {
            Some(cwd) if !path.is_absolute() => cwd.join(path),
            _ => path.to_path_buf(),
        }
    }

    /// Whether Python's working directory came with the request.
    pub(crate) fn has_cwd(&self) -> bool {
        self.cwd.is_some()
    }

    /// `_append_found_path`.
    pub(crate) fn found(&mut self, path: &Path) {
        let path = path.to_string_lossy();
        if !self.found_paths.iter().any(|found| *found == path) {
            self.found_paths.push(path.into_owned());
        }
    }

    /// `found_paths.append`: kept even when already listed.
    pub(crate) fn push_found(&mut self, path: &Path) {
        self.found_paths.push(path.to_string_lossy().into_owned());
    }

    /// Python 3.12's `Path.is_file`, read from Python's `cwd`.
    pub(crate) fn is_file(&self, path: &Path) -> Result<bool, &'static str> {
        Ok(py_stat(&self.fs(path))?.is_some_and(|metadata| metadata.is_file()))
    }

    /// Python 3.12's `Path.is_dir`, read from Python's `cwd`.
    pub(crate) fn is_dir(&self, path: &Path) -> Result<bool, &'static str> {
        Ok(py_stat(&self.fs(path))?.is_some_and(|metadata| metadata.is_dir()))
    }

    /// Python 3.12's `Path.exists`, read from Python's `cwd`.
    pub(crate) fn exists(&self, path: &Path) -> Result<bool, &'static str> {
        Ok(py_stat(&self.fs(path))?.is_some())
    }

    /// Adds a warning; `finish` keeps only the first of equal ones.
    pub(crate) fn warn(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub(crate) fn has_found(&self) -> bool {
        !self.found_paths.is_empty()
    }

    /// `_scope_for`: `project` below the workspace, else `global`.
    pub(crate) fn scope_for(&self, path: &Path) -> &'static str {
        match &self.workspace {
            Some(workspace) if path.starts_with(workspace) => "project",
            _ => "global",
        }
    }

    /// The skill documents and discovery issues below `skill_root`; `label`
    /// names the harness in warnings and issue names.
    pub(crate) fn skills(
        &mut self,
        scope: &Scope<'_>,
        label: &str,
        naming: &SkillNaming<'_>,
        skill_root: &Path,
        identity_root: &Path,
    ) -> Result<(), &'static str> {
        let root = self.fs(skill_root);
        let identity_root = self.fs(identity_root);
        let discovery = discover_skill_documents(&root, &LIMITS);
        let incomplete = format!(
            "{label} {} skill directory identity is incomplete; approval reuse is disabled.",
            scope.scope
        );
        for encoded in &discovery.documents_hex {
            let relative = hex::decode(encoded).map_err(|_| ERR_NAME)?;
            let relative = String::from_utf8(relative).map_err(|_| ERR_NAME)?;
            // `skill_path.parent.relative_to(skill_root)` raises when the
            // anchored document is compared with a relative root.
            if !skill_root.is_absolute() {
                return Err(ERR_INVALID);
            }
            let skill_md = py_join(skill_root, &relative);
            self.found(&skill_md);
            let parent = relative.rsplit_once('/').map_or(".", |(parent, _)| parent);
            let relative_id = format!("skills/{parent}");
            let name = match naming {
                SkillNaming::Prefixed => relative_id.as_str(),
                SkillNaming::Bare { .. } => parent,
            };
            let identity = inspect_skill_directory(&skill_md, &identity_root, &LIMITS);
            if identity.status != "complete" {
                self.warnings.push(incomplete.clone());
            }
            let metadata = identity_metadata(&identity, &relative_id)?;
            self.artifacts.push(scope.wire(
                format!("{}:{}:skill:{name}", scope.harness, scope.scope),
                name,
                "skill",
                &skill_md,
                Fields::default(),
                metadata,
            ));
        }
        for issue in &discovery.issues {
            let relative = hex::decode(&issue.relative_path_hex).map_err(|_| ERR_NAME)?;
            let relative = String::from_utf8(relative).map_err(|_| ERR_NAME)?;
            let path = if relative == "." {
                skill_root.to_path_buf()
            } else {
                py_join(skill_root, &relative)
            };
            self.found(&path);
            let relative_id = format!("skills/.guard-discovery/{}", issue.issue_id);
            self.warnings.push(format!(
                "{label} {} skill discovery is incomplete; approval reuse is disabled.",
                scope.scope
            ));
            let key = match naming {
                SkillNaming::Prefixed => issue.issue_id.clone(),
                SkillNaming::Bare { root_label } => format!("{root_label}:{}", issue.issue_id),
            };
            self.artifacts.push(scope.wire(
                format!("{}:{}:skill-discovery:{key}", scope.harness, scope.scope),
                &format!("Incomplete {label} skill discovery"),
                "skill",
                &path,
                Fields::default(),
                identity_metadata(&issue.identity, &relative_id)?,
            ));
        }
        Ok(())
    }

    /// The kind result: warnings keep their first position, and an inventory
    /// that would carry a lone surrogate is refused.
    pub(crate) fn finish(self) -> KindResult {
        let mut warnings: Vec<String> = Vec::new();
        for warning in self.warnings {
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
        let result = json!({
            "artifacts": self.artifacts,
            "found_paths": self.found_paths,
            "warnings": warnings,
        });
        if carries_lone_surrogate(&result) {
            return Err(ERR_VALUE);
        }
        Ok(result)
    }
}

/// The runtime bridge: the inventory carries a detection leaf's host needs.
impl guard_adapter_detection::DetectionHost for Inventory {
    fn resolve(&self, path: &Path) -> PathBuf {
        self.fs(path)
    }

    fn mark_found(&mut self, path: &Path) {
        self.found(path);
    }

    fn record(&mut self, artifact: Value) {
        self.artifacts.push(artifact);
    }

    fn scope_of(&self, path: &Path) -> &'static str {
        self.scope_for(path)
    }

    fn discover_skills(
        &mut self,
        scope: &Scope<'_>,
        label: &str,
        naming: &SkillNaming<'_>,
        skill_root: &Path,
        identity_root: &Path,
    ) -> Result<(), &'static str> {
        self.skills(scope, label, naming, skill_root, identity_root)
    }
}
