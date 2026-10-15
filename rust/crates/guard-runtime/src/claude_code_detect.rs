//! `runner_authority` kind `claude_code_detect`: the config parsing and
//! artifact discovery of `ClaudeCodeHarnessAdapter.detect`. Python sends the
//! home and workspace directories as it holds them (plus its working
//! directory when either is relative); this reads the user and project
//! settings, `.mcp.json` and the project agent, skill, command and rule
//! directories, and returns the artifacts and the config paths that were
//! found. Paths are reported as Python spells them and read through `cwd`.
//! Every refusal is a stable code and never a partial inventory.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::aibom_paths::{
    file_content_hash, is_dir, is_file, py_path, resolves_within_root, safe_matching_files, stem,
};
use super::claude_code_config::{hook_artifacts, kept, mcp_artifacts, ERR_VALUE};
use super::pyjson::{parse_marking_lone_surrogates, JsonFailure, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{Fields, Scope};

const ERR_TEXT: &str = "native_runner_authority_claude_code_text_undecodable";
const ERR_NAME: &str = "native_runner_authority_claude_code_name_undecodable";

const HARNESS: &str = "claude-code";
const SETTINGS_FILES: [&str; 2] = ["settings.json", "settings.local.json"];

/// How a project directory names the artifacts it holds.
#[derive(Clone, Copy)]
enum Naming {
    Stem,
    Skill,
    Rule,
}

/// Directory, artifact type, id prefix and naming, in discovery order.
const PROJECT_DIRECTORIES: [(&str, &str, &str, Naming); 4] = [
    ("agents", "agent", "agent", Naming::Stem),
    ("skills", "skill", "skill", Naming::Skill),
    ("commands", "command", "command", Naming::Stem),
    ("rules", "instruction", "instruction", Naming::Rule),
];

/// `_json_payload`: the object a settings file holds, or an empty one when it
/// is missing, unreadable, not JSON or not an object. Bytes that are not UTF-8
/// and input `json.loads` raises a non-`JSONDecodeError` on are refused.
fn settings_payload(path: &Path) -> Result<PyVal, &'static str> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(PyVal::Dict(Vec::new()));
    };
    let text = String::from_utf8(bytes).map_err(|_| ERR_TEXT)?;
    match parse_marking_lone_surrogates(&text) {
        Ok(value @ PyVal::Dict(_)) => Ok(value),
        Ok(_) | Err(JsonFailure::Syntax) => Ok(PyVal::Dict(Vec::new())),
        Err(_) => Err(ERR_VALUE),
    }
}

/// `sorted(base_dir.glob("**/SKILL.md"))` as relative parts: every entry
/// named `SKILL.md` at any depth, directory links listed but never descended,
/// unreadable directories skipped. A directory whose name cannot be carried
/// is refused, as the walk would have to report what lies beneath it.
fn skill_entries(base: &Path) -> Result<Vec<Vec<String>>, &'static str> {
    let mut found: Vec<Vec<String>> = Vec::new();
    let mut pending = vec![(base.to_path_buf(), Vec::<String>::new())];
    while let Some((directory, relative)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let real_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) if real_dir => return Err(ERR_NAME),
                Err(_) => continue,
            };
            let mut parts = relative.clone();
            parts.push(name);
            if real_dir {
                pending.push((entry.path(), parts.clone()));
            }
            if parts.last().is_some_and(|name| name == "SKILL.md") {
                found.push(parts);
            }
        }
    }
    found.sort();
    Ok(found)
}

struct Detection {
    cwd: Option<PathBuf>,
    workspace: Option<PathBuf>,
    artifacts: Vec<Value>,
    found_paths: Vec<String>,
}

impl Detection {
    /// Where `path` is on disk: a relative path is read from Python's `cwd`.
    fn fs(&self, path: &Path) -> PathBuf {
        match &self.cwd {
            Some(cwd) if !path.is_absolute() => cwd.join(path),
            _ => path.to_path_buf(),
        }
    }

    fn settings(&mut self, path: &Path) -> Result<(), &'static str> {
        let payload = settings_payload(&self.fs(path))?;
        if !payload.truthy() {
            return Ok(());
        }
        self.found_paths
            .push(kept(&path.to_string_lossy())?.to_owned());
        let in_workspace = self
            .workspace
            .as_ref()
            .is_some_and(|workspace| path.starts_with(workspace));
        let scope = Scope {
            harness: HARNESS,
            scope: if in_workspace { "project" } else { "global" },
        };
        self.artifacts
            .extend(mcp_artifacts(&scope, path, &payload)?);
        self.artifacts
            .extend(hook_artifacts(&scope, path, &payload)?);
        Ok(())
    }

    /// `_discover_project_markdown_artifacts` for one project directory.
    fn project_directory(
        &mut self,
        workspace: &Path,
        (directory, artifact_type, prefix, naming): (&str, &str, &str, Naming),
    ) -> Result<(), &'static str> {
        let base = workspace.join(".claude").join(directory);
        let (root_fs, base_fs) = (self.fs(workspace), self.fs(&base));
        if !is_dir(&base_fs) || !resolves_within_root(&root_fs, &base_fs, true) {
            return Ok(());
        }
        if directory == "agents" {
            self.found_paths.push(base.to_string_lossy().into_owned());
        }
        let entries: Vec<Vec<String>> = match naming {
            Naming::Skill => skill_entries(&base_fs)?,
            Naming::Stem | Naming::Rule => safe_matching_files(&root_fs, &base_fs, ".md")?
                .iter()
                .filter_map(|path| path.file_name())
                .map(|name| vec![name.to_string_lossy().into_owned()])
                .collect(),
        };
        let scope = Scope {
            harness: HARNESS,
            scope: "project",
        };
        for parts in entries {
            let relative: PathBuf = parts.iter().collect();
            let candidate_fs = base_fs.join(&relative);
            if matches!(naming, Naming::Skill)
                && !(is_file(&candidate_fs) && resolves_within_root(&root_fs, &candidate_fs, true))
            {
                continue;
            }
            let file_name = parts.last().map(String::as_str).unwrap_or_default();
            let name = match naming {
                Naming::Stem => stem(file_name).to_owned(),
                Naming::Rule => format!("rules-{}", stem(file_name)),
                Naming::Skill if parts.len() == 1 => ".".to_owned(),
                Naming::Skill => parts[..parts.len() - 1].join("/"),
            };
            let name = kept(&name)?;
            let mut metadata = Map::new();
            if let Some(digest) = file_content_hash(&candidate_fs) {
                metadata.insert("content_digest".to_owned(), json!(digest));
            }
            self.artifacts.push(scope.wire(
                format!("claude-code:project:{prefix}:{name}"),
                name,
                artifact_type,
                &base.join(&relative),
                Fields::default(),
                metadata,
            ));
        }
        Ok(())
    }
}

fn directory_arg(args: &Map<String, Value>, key: &str) -> Result<Option<PathBuf>, &'static str> {
    match args.get(key) {
        Some(Value::String(path)) => Ok(Some(py_path(path))),
        None | Some(Value::Null) if key == "workspace" => Ok(None),
        _ => Err(ERR_INVALID),
    }
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args.get("harness").and_then(Value::as_str) != Some(HARNESS) {
        return Err(ERR_INVALID);
    }
    let home = directory_arg(args, "home")?.ok_or(ERR_INVALID)?;
    let workspace = directory_arg(args, "workspace")?;
    let cwd = match args.get("cwd") {
        None | Some(Value::Null) => None,
        Some(Value::String(cwd)) if Path::new(cwd).is_absolute() => Some(PathBuf::from(cwd)),
        Some(_) => return Err(ERR_INVALID),
    };
    let relative =
        !home.is_absolute() || workspace.as_ref().is_some_and(|path| !path.is_absolute());
    if relative && cwd.is_none() {
        return Err(ERR_INVALID);
    }

    let mut candidates: Vec<PathBuf> = SETTINGS_FILES
        .iter()
        .map(|name| home.join(".claude").join(name))
        .collect();
    if let Some(workspace) = &workspace {
        candidates.extend(
            SETTINGS_FILES
                .iter()
                .map(|name| workspace.join(".claude").join(name)),
        );
        candidates.push(workspace.join(".mcp.json"));
    }
    let mut detection = Detection {
        cwd,
        workspace: workspace.clone(),
        artifacts: Vec::new(),
        found_paths: Vec::new(),
    };
    for candidate in &candidates {
        detection.settings(candidate)?;
    }
    if let Some(workspace) = &workspace {
        for directory in PROJECT_DIRECTORIES {
            detection.project_directory(workspace, directory)?;
        }
    }
    Ok(json!({
        "artifacts": detection.artifacts,
        "found_paths": detection.found_paths,
        "warnings": [],
    }))
}
