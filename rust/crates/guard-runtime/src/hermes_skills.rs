//! Hermes skill discovery: `<home>/skills/<category>/<skill>/SKILL.md` and the
//! scannable files below each skill's `references`, `templates`, `scripts` and
//! `assets` directories.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::aibom_paths::{is_dir, is_file};
use super::aibom_skills::{directory_identity, DirectoryIdentity};
use super::hermes_detect::Found;
use super::hermes_inspect::{inspect_text_file, FileInspection};
use super::hermes_text::{code_blocks, env_mentions, frontmatter, is_scannable, plain_markdown};
use super::zcode_artifacts::{Fields, Scope};
use super::zcode_detect::sort_key;

const SKILL_SUBDIRS: [&str; 4] = ["references", "templates", "scripts", "assets"];
const ERR_NAME: &str = "native_runner_authority_hermes_non_utf8_path";
const ERR_IDENTITY: &str = "native_runner_authority_hermes_skill_identity_invalid";
const PLAIN_TEXT_LIMIT: usize = 2048;
const DESCRIPTION_LIMIT: usize = 200;

const SCOPE: Scope<'static> = Scope {
    harness: "hermes",
    scope: "global",
};

/// Finished identities a caller supplies where no native walk exists, keyed by
/// the `SKILL.md` path.
pub(crate) type Identities<'a> = Option<&'a Map<String, Value>>;

/// Directory children sorted by name, or nothing when the directory cannot be
/// read. A name that is not UTF-8 refuses when it is a directory (it would be
/// walked and reported) and is skipped otherwise.
fn children(dir: &Path) -> Result<Vec<(String, PathBuf)>, &'static str> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut named: Vec<(String, String, PathBuf)> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return Ok(Vec::new());
        };
        let path = entry.path();
        match entry.file_name().into_string() {
            Ok(name) => named.push((sort_key(&name), name, path)),
            Err(_) if is_dir(&path) => return Err(ERR_NAME),
            Err(_) => {}
        }
    }
    named.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(named
        .into_iter()
        .map(|(_, name, path)| (name, path))
        .collect())
}

fn inspection_entries(inspection: &FileInspection) -> Result<Vec<(String, Value)>, &'static str> {
    inspection
        .metadata()
        .into_iter()
        .map(|(key, value)| Ok((key, value.to_json().ok_or(ERR_IDENTITY)?)))
        .collect()
}

/// `_inspection_signals`.
fn inspection_signals(inspection: &FileInspection, label: &str) -> Vec<String> {
    if !inspection.complete {
        let reason = inspection.reason.unwrap_or("unknown");
        return vec![format!(
            "{label} inspection is incomplete ({reason}); unseen content cannot be treated as safe."
        )];
    }
    if inspection.analysis_truncated {
        return vec![format!(
            "{label} risk preview is truncated; review the complete content before approval."
        )];
    }
    Vec::new()
}

fn risk_args(content: &str) -> (Vec<String>, bool) {
    let blocks = code_blocks(content);
    let has_blocks = !blocks.is_empty();
    let mut args = blocks;
    let plain = plain_markdown(content, PLAIN_TEXT_LIMIT);
    if !plain.is_empty() {
        args.push(plain);
    }
    (args, has_blocks)
}

fn identity(
    skill_md: &Path,
    scope_root: &Path,
    label: &str,
    supplied: Identities<'_>,
) -> Result<DirectoryIdentity, &'static str> {
    let key = skill_md.to_string_lossy();
    if let Some(entry) = supplied.and_then(|map| map.get(key.as_ref())) {
        let entry = entry.as_object().ok_or(ERR_IDENTITY)?;
        return Ok(DirectoryIdentity {
            metadata: entry
                .get("metadata")
                .and_then(Value::as_object)
                .ok_or(ERR_IDENTITY)?
                .clone(),
            complete: entry
                .get("complete")
                .and_then(Value::as_bool)
                .ok_or(ERR_IDENTITY)?,
            failure_reason: match entry.get("failure_reason") {
                None | Some(Value::Null) => None,
                Some(Value::String(reason)) => Some(reason.clone()),
                Some(_) => return Err(ERR_IDENTITY),
            },
        });
    }
    directory_identity(skill_md, scope_root, label)
}

/// `_scan_skills_dir`.
pub(crate) fn scan_skills(
    skills_dir: &Path,
    found: &mut Found,
    supplied: Identities<'_>,
) -> Result<(), &'static str> {
    if !is_dir(skills_dir) {
        return Ok(());
    }
    for (category, category_dir) in children(skills_dir)? {
        if !is_dir(&category_dir) {
            continue;
        }
        for (skill, skill_dir) in children(&category_dir)? {
            if !is_dir(&skill_dir) {
                continue;
            }
            let skill_md = skill_dir.join("SKILL.md");
            if !is_file(&skill_md) {
                continue;
            }
            found.paths.push(skill_md.to_string_lossy().into_owned());
            scan_skill(
                &category, &skill, &skill_dir, &skill_md, skills_dir, found, supplied,
            )?;
        }
    }
    Ok(())
}

fn scan_skill(
    category: &str,
    skill: &str,
    skill_dir: &Path,
    skill_md: &Path,
    scope_root: &Path,
    found: &mut Found,
    supplied: Identities<'_>,
) -> Result<(), &'static str> {
    let inspection = inspect_text_file(skill_md, Some(skill_dir), None);
    let content = inspection.preview.as_str();
    let front = frontmatter(content)?;
    let (args, has_blocks) = risk_args(content);

    let name = front
        .flat("name")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| skill.to_owned());
    let description = front.flat("description").unwrap_or_default();
    let related = front.flat("related_skills").unwrap_or_default();

    let identity = identity(
        skill_md,
        scope_root,
        &format!("{category}/{skill}"),
        supplied,
    )?;
    let mut metadata = identity.metadata.clone();
    metadata.insert("category".to_owned(), json!(category));
    metadata.insert(
        "description".to_owned(),
        json!(description
            .chars()
            .take(DESCRIPTION_LIMIT)
            .collect::<String>()),
    );
    metadata.insert("has_code_blocks".to_owned(), json!(has_blocks));
    metadata.insert("related_skills".to_owned(), json!(related));
    metadata.insert(
        "env_mentions".to_owned(),
        json!(env_mentions(content).into_iter().collect::<Vec<_>>()),
    );
    for (key, value) in inspection_entries(&inspection)? {
        metadata.insert(key, value);
    }
    let mut signals = inspection_signals(&inspection, "Hermes skill");
    if !identity.complete {
        signals
            .push("Hermes skill directory identity is incomplete; review is required.".to_owned());
        let reason = identity.failure_reason.as_deref().unwrap_or("unknown");
        found.warnings.push(format!(
            "Hermes skill directory identity is incomplete ({reason}); approval reuse is disabled."
        ));
    }
    if !signals.is_empty() {
        metadata.insert("runtime_request_signals".to_owned(), json!(signals));
    }
    let skill_path = skill_md.to_string_lossy();
    found.artifacts.push(SCOPE.wire(
        format!("hermes:skill:{category}:{skill}"),
        &name,
        "skill",
        skill_md,
        Fields {
            command: Some(&skill_path),
            args,
            ..Fields::default()
        },
        metadata,
    ));

    for subdir_name in SKILL_SUBDIRS {
        let subdir = skill_dir.join(subdir_name);
        if !is_dir(&subdir) {
            continue;
        }
        for (relative, file_path) in subdirectory_files(&subdir)? {
            let rel = relative.join(std::path::MAIN_SEPARATOR_STR);
            let file_inspection = inspect_text_file(&file_path, Some(skill_dir), None);
            let file_content = file_inspection.preview.as_str();
            let (file_args, file_blocks) = risk_args(file_content);
            let mut file_metadata = Map::new();
            file_metadata.insert("parent_skill".to_owned(), json!(name));
            file_metadata.insert("subdir".to_owned(), json!(subdir_name));
            file_metadata.insert("has_code_blocks".to_owned(), json!(file_blocks));
            file_metadata.insert(
                "env_mentions".to_owned(),
                json!(env_mentions(file_content).into_iter().collect::<Vec<_>>()),
            );
            for (key, value) in inspection_entries(&file_inspection)? {
                file_metadata.insert(key, value);
            }
            let file_signals = inspection_signals(&file_inspection, "Hermes skill file");
            if !file_signals.is_empty() {
                file_metadata.insert("runtime_request_signals".to_owned(), json!(file_signals));
            }
            let command = file_path.to_string_lossy();
            found.artifacts.push(SCOPE.wire(
                format!("hermes:skill:{category}:{skill}:{rel}"),
                &format!("{name}/{rel}"),
                "skill_file",
                &file_path,
                Fields {
                    command: Some(&command),
                    args: file_args,
                    ..Fields::default()
                },
                file_metadata,
            ));
        }
    }
    Ok(())
}

/// `sorted(subdir.rglob("*"))` filtered to scannable regular files: every
/// entry at any depth, never descending a directory link, unreadable
/// directories skipped, ordered by path parts relative to the subdirectory.
fn subdirectory_files(subdir: &Path) -> Result<Vec<(Vec<String>, PathBuf)>, &'static str> {
    let mut entries: Vec<(Vec<String>, PathBuf)> = Vec::new();
    let mut pending: Vec<(PathBuf, Vec<String>)> = vec![(
        subdir.to_path_buf(),
        vec![subdir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()],
    )];
    while let Some((directory, relative)) = pending.pop() {
        let Ok(listing) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in listing.filter_map(Result::ok) {
            let path = entry.path();
            let real_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(raw) => {
                    let _ = raw;
                    if real_dir || (is_file(&path) && is_scannable(&path)) {
                        return Err(ERR_NAME);
                    }
                    continue;
                }
            };
            let mut parts = relative.clone();
            parts.push(name);
            if real_dir {
                pending.push((path.clone(), parts.clone()));
            }
            entries.push((parts, path));
        }
    }
    entries.sort_by(|left, right| {
        let key = |item: &(Vec<String>, PathBuf)| -> Vec<String> {
            item.0.iter().map(|part| sort_key(part)).collect()
        };
        key(left).cmp(&key(right))
    });
    Ok(entries
        .into_iter()
        .filter(|(_, path)| is_file(path) && is_scannable(path))
        .collect())
}
