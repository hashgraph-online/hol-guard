//! `runner_authority` kind `pi_detect`: the resource discovery behind
//! `_PiFamilyHarnessAdapter.detect` for Pi and Oh My Pi. Python names the
//! global and project roots; this reads each root's `settings.json`, resolves
//! the packages, extensions, skills, prompts and themes it configures, walks
//! the default resource directories, and returns the artifacts and the paths
//! that were found. Paths are spelled as Python spells them: relative roots
//! stay relative and resolved settings matches are absolute. Every refusal is
//! a stable code and never a partial inventory.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::aibom_paths::{exists, is_dir, is_file, resolve};
use super::context_digest::python_strip;
use super::pi_glob::{expand_user, glob, has_magic, rglob, ERR_NAME};
use super::pyjson::{parse_marking_lone_surrogates, JsonFailure, PyVal, LONE_SURROGATE_MARK};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use super::zcode_artifacts::{Fields, Scope};
use super::zcode_detect::sort_key;

const ERR_TEXT: &str = "native_runner_authority_pi_text_undecodable";
const ERR_VALUE: &str = "native_runner_authority_pi_value_unrepresentable";
const ERR_PATH: &str = "native_runner_authority_pi_path_unresolvable";

const EXTENSION_SUFFIXES: [&str; 6] = [".ts", ".js", ".mts", ".cts", ".mjs", ".cjs"];
const THEME_SUFFIXES: [&str; 5] = [".json", ".js", ".ts", ".yaml", ".yml"];
const REMOTE_PREFIXES: [&str; 5] = ["npm:", "git:", "http://", "https://", "ssh://"];

/// The four resource kinds, with their default directory and the file test
/// for a configured file or a walked entry.
#[derive(Clone, Copy, PartialEq)]
enum Resource {
    Extension,
    Skill,
    Prompt,
    Theme,
}

impl Resource {
    const ALL: [Resource; 4] = [Self::Extension, Self::Skill, Self::Prompt, Self::Theme];

    fn key(self) -> &'static str {
        match self {
            Self::Extension => "extensions",
            Self::Skill => "skills",
            Self::Prompt => "prompts",
            Self::Theme => "themes",
        }
    }

    fn artifact_type(self) -> &'static str {
        match self {
            Self::Extension => "extension",
            Self::Skill => "skill",
            Self::Prompt => "prompt",
            Self::Theme => "theme",
        }
    }

    /// Whether a configured path that is not a directory is this resource.
    fn configured_file(self, path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        match self {
            Self::Extension => EXTENSION_SUFFIXES.contains(&suffix(name)),
            Self::Skill => name == "SKILL.md",
            Self::Prompt => suffix(name) == ".md",
            Self::Theme => THEME_SUFFIXES.contains(&suffix(name)),
        }
    }

    /// The `rglob` filter: `*` then a regular-file suffix test, or the
    /// `SKILL.md` and `*.md` patterns, which keep entries of any kind.
    fn walked(self, name: &str, path: &Path) -> bool {
        match self {
            Self::Extension => is_file(path) && EXTENSION_SUFFIXES.contains(&suffix(name)),
            Self::Skill => same_name(name, "SKILL.md"),
            Self::Prompt => {
                if cfg!(windows) {
                    name.to_lowercase().ends_with(".md")
                } else {
                    name.ends_with(".md")
                }
            }
            Self::Theme => is_file(path) && THEME_SUFFIXES.contains(&suffix(name)),
        }
    }
}

fn same_name(name: &str, expected: &str) -> bool {
    if cfg!(windows) {
        name.eq_ignore_ascii_case(expected)
    } else {
        name == expected
    }
}

/// `PurePath.suffix`.
fn suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => &name[index..],
        _ => "",
    }
}

fn stable_suffix(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..16].to_owned()
}

fn text(path: &Path) -> Result<&str, &'static str> {
    path.to_str().ok_or(ERR_NAME)
}

/// A string the inventory carries; a lone surrogate CPython cannot encode is
/// refused.
fn kept(value: &str) -> Result<&str, &'static str> {
    if value.contains(LONE_SURROGATE_MARK) {
        Err(ERR_VALUE)
    } else {
        Ok(value)
    }
}

/// `json_payload`: an unreadable file or text that is not a JSON object reads
/// as empty; bytes that are not UTF-8 and text `json.loads` raises a
/// non-`JSONDecodeError` on are refused, as the original raised on them.
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

/// The non-blank strings of a settings list.
fn settings_values<'a>(payload: &'a PyVal, key: &str) -> Vec<&'a str> {
    payload
        .get(key)
        .and_then(PyVal::as_list)
        .unwrap_or_default()
        .iter()
        .filter_map(PyVal::as_str)
        .filter(|value| !python_strip(value).is_empty())
        .collect()
}

struct Detection<'a> {
    harness: &'a str,
    home: &'a str,
    cwd: Option<PathBuf>,
    artifacts: Vec<Value>,
    found_paths: Vec<String>,
    seen: HashSet<String>,
}

impl Detection<'_> {
    /// The filesystem path for a Python spelling: relative paths are read
    /// from the caller's directory.
    fn fs(&self, path: &Path) -> Result<PathBuf, &'static str> {
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        self.cwd
            .as_ref()
            .map(|cwd| cwd.join(path))
            .ok_or(ERR_INVALID)
    }

    fn resolved(&self, path: &Path) -> Result<PathBuf, &'static str> {
        resolve(&self.fs(path)?).map_err(|()| ERR_PATH)
    }

    fn found(&mut self, path: &Path) -> Result<(), &'static str> {
        let text = text(path)?.to_owned();
        if !self.found_paths.contains(&text) {
            self.found_paths.push(text);
        }
        Ok(())
    }

    fn push(&mut self, dedupe_key: String, scope: &str, wire: impl FnOnce(&Scope<'_>) -> Value) {
        if self.seen.insert(dedupe_key) {
            let scope = Scope {
                harness: self.harness,
                scope,
            };
            self.artifacts.push(wire(&scope));
        }
    }

    /// A settings entry with no local match: a package, or a configured
    /// resource that is remote or missing.
    fn configured(
        &mut self,
        settings: &Path,
        scope: &str,
        id_scope: &str,
        artifact_type: &str,
        key: &str,
        value: &str,
    ) -> Result<(), &'static str> {
        let value = kept(value)?;
        let artifact_id = if key == "packages" {
            format!(
                "{}:{id_scope}:package:{}",
                self.harness,
                stable_suffix(value)
            )
        } else {
            format!(
                "{}:{id_scope}:{artifact_type}:configured:{}",
                self.harness,
                stable_suffix(value)
            )
        };
        let mut metadata = Map::new();
        metadata.insert("source".to_owned(), json!("settings.json"));
        metadata.insert("key".to_owned(), json!(key));
        metadata.insert("value".to_owned(), json!(value));
        self.push(artifact_id.clone(), scope, |wire| {
            wire.wire(
                artifact_id,
                value,
                artifact_type,
                settings,
                Fields::default(),
                metadata,
            )
        });
        Ok(())
    }

    /// One discovered resource file, labelled relative to `id_root`.
    fn resource_file(
        &mut self,
        resource: Resource,
        path: &Path,
        scope: &str,
        id_scope: &str,
        id_root: &Path,
    ) -> Result<(), &'static str> {
        self.found(path)?;
        let label = |path: &Path| -> Result<String, &'static str> {
            let relative = path.strip_prefix(id_root).map_err(|_| ERR_PATH)?;
            let parts: Vec<&str> = relative
                .iter()
                .map(|part| part.to_str().ok_or(ERR_NAME))
                .collect::<Result<_, _>>()?;
            Ok(if parts.is_empty() {
                ".".to_owned()
            } else {
                parts.join("/")
            })
        };
        let name = if resource == Resource::Skill {
            let parent = label(path.parent().unwrap_or(path))?;
            if parent == "." {
                "skills".to_owned()
            } else {
                format!("skills/{parent}")
            }
        } else {
            label(path)?
        };
        let artifact_type = resource.artifact_type();
        let resolved = self.resolved(path)?;
        let dedupe_key = format!("{artifact_type}:{id_scope}:{}", text(&resolved)?);
        let artifact_id = format!("{}:{id_scope}:{artifact_type}:{name}", self.harness);
        self.push(dedupe_key, scope, |wire| {
            wire.wire(
                artifact_id,
                &name,
                artifact_type,
                path,
                Fields::default(),
                Map::new(),
            )
        });
        Ok(())
    }

    /// `_append_*_artifacts`: every matching entry under a resource directory.
    fn resource_tree(
        &mut self,
        resource: Resource,
        root: &Path,
        scope: &str,
        id_scope: &str,
        id_root: &Path,
    ) -> Result<(), &'static str> {
        let fs_root = self.fs(root)?;
        if !is_dir(&fs_root) {
            return Ok(());
        }
        for parts in rglob(&fs_root, |name, path| resource.walked(name, path))? {
            let path = parts
                .iter()
                .fold(root.to_path_buf(), |path, part| path.join(part));
            self.resource_file(resource, &path, scope, id_scope, id_root)?;
        }
        Ok(())
    }

    /// `resolve_configured_paths`: the resolved local paths a settings entry
    /// names, through `glob` when the joined path holds a wildcard.
    fn configured_paths(&self, settings: &Path, value: &str) -> Result<Vec<PathBuf>, &'static str> {
        if REMOTE_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
        {
            return Ok(Vec::new());
        }
        let candidate = expand_user(value, self.home)?;
        let candidate = if candidate.is_absolute() {
            candidate
        } else {
            settings.parent().unwrap_or(Path::new("")).join(candidate)
        };
        let pattern = text(&candidate)?;
        if !has_magic(pattern) {
            let resolved = self.resolved(&candidate)?;
            return Ok(if exists(&resolved) {
                vec![resolved]
            } else {
                Vec::new()
            });
        }
        let cwd = match &self.cwd {
            Some(cwd) => cwd.clone(),
            None if candidate.is_absolute() => PathBuf::new(),
            None => return Err(ERR_INVALID),
        };
        let mut matches = Vec::new();
        for item in glob(pattern, &cwd)? {
            let resolved = resolve(&item).map_err(|()| ERR_PATH)?;
            if exists(&resolved) {
                matches.push(resolved);
            }
        }
        matches.sort_by_cached_key(|path| {
            path.iter()
                .map(|part| sort_key(&part.to_string_lossy()))
                .collect::<Vec<_>>()
        });
        matches.dedup();
        Ok(matches)
    }

    fn settings(&mut self, root: &Path, scope: &str, id_scope: &str) -> Result<(), &'static str> {
        let settings = root.join("settings.json");
        let fs_settings = self.fs(&settings)?;
        if !is_file(&fs_settings) {
            return Ok(());
        }
        self.found(&settings)?;
        let payload = settings_payload(&fs_settings)?;
        for value in settings_values(&payload, "packages") {
            self.configured(&settings, scope, id_scope, "package", "packages", value)?;
        }
        for resource in Resource::ALL {
            let default_root = root.join(resource.key());
            for value in settings_values(&payload, resource.key()) {
                let value = kept(value)?;
                let matches = self.configured_paths(&settings, value)?;
                if matches.is_empty() {
                    self.configured(
                        &settings,
                        scope,
                        id_scope,
                        resource.artifact_type(),
                        resource.key(),
                        value,
                    )?;
                    continue;
                }
                for found in matches {
                    let directory = is_dir(&found);
                    let id_root = if found.starts_with(&default_root) {
                        default_root.clone()
                    } else if directory {
                        found.clone()
                    } else {
                        found.parent().unwrap_or(&found).to_path_buf()
                    };
                    if directory {
                        self.resource_tree(resource, &found, scope, id_scope, &id_root)?;
                    } else if resource.configured_file(&found) {
                        self.resource_file(resource, &found, scope, id_scope, &id_root)?;
                    }
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn detect(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let text_arg = |key: &str| args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let harness = text_arg("harness")?;
    if !matches!(harness, "pi" | "omp") {
        return Err(ERR_INVALID);
    }
    let cwd = match args.get("cwd") {
        None => None,
        Some(Value::String(cwd)) if Path::new(cwd).is_absolute() => Some(PathBuf::from(cwd)),
        Some(_) => return Err(ERR_INVALID),
    };
    let mut detection = Detection {
        harness,
        home: text_arg("home")?,
        cwd,
        artifacts: Vec::new(),
        found_paths: Vec::new(),
        seen: HashSet::new(),
    };
    for root in args
        .get("roots")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
    {
        let field = |key: &str| root.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
        let (path, scope, id_scope) = (
            PathBuf::from(field("path")?),
            field("scope")?,
            field("id_scope")?,
        );
        detection.settings(&path, scope, id_scope)?;
        for resource in Resource::ALL {
            let directory = path.join(resource.key());
            detection.resource_tree(resource, &directory, scope, id_scope, &directory)?;
        }
    }
    Ok(json!({
        "artifacts": detection.artifacts,
        "found_paths": detection.found_paths,
        "warnings": [],
    }))
}
