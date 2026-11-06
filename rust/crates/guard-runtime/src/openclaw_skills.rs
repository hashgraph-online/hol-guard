//! OpenClaw skills: every `SKILL.md` below each distinct skill root and the
//! scannable files of its `references`, `templates`, `scripts` and `assets`
//! directories, walked the way Python 3.12's `rglob` walks them.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map};
use sha2::{Digest, Sha256};

use super::adapter_inventory::{Inventory, ERR_NAME, ERR_STAT};
use super::aibom_paths::resolve;
use super::context_digest::python_strip;
use super::daemon_lifecycle_text::py_splitlines;
use super::hermes_text::{code_blocks, plain_markdown};
use super::zcode_artifacts::{Fields, Scope};
use super::zcode_detect::sort_key;

const MAX_FILE_READ: usize = 64 * 1024;
const SKILL_SUBDIRS: [&str; 4] = ["references", "templates", "scripts", "assets"];
const SCANNABLE_EXTENSIONS: [&str; 11] = [
    ".md", ".txt", ".py", ".sh", ".bash", ".js", ".ts", ".yaml", ".yml", ".json", ".toml",
];
const SCANNABLE_NAMES: [&str; 4] = [".env", "Dockerfile", "Makefile", "Procfile"];

/// One entry below a walked directory, as `rglob` reports it.
struct Entry {
    path: PathBuf,
    parts: Vec<String>,
    undecodable: bool,
}

/// Every entry of `root` and of each directory below it, the way Python
/// 3.12's `rglob` lists them: directory links are reported but never
/// entered, unreadable directories are skipped, and the result is sorted as
/// `sorted()` orders paths.
fn walk(inventory: &Inventory, root: &Path) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut pending = vec![(root.to_path_buf(), Vec::<String>::new(), false)];
    while let Some((dir, parts, undecodable)) = pending.pop() {
        let Ok(listing) = fs::read_dir(inventory.fs(&dir)) else {
            continue;
        };
        for entry in listing.flatten() {
            let name = entry.file_name();
            let mut child = parts.clone();
            child.push(name.to_string_lossy().into_owned());
            let child_undecodable = undecodable || name.to_str().is_none();
            let path = dir.join(&name);
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push((path.clone(), child.clone(), child_undecodable));
            }
            entries.push(Entry {
                path,
                parts: child,
                undecodable: child_undecodable,
            });
        }
    }
    entries.sort_by_cached_key(|entry| {
        entry
            .parts
            .iter()
            .map(|part| sort_key(part))
            .collect::<Vec<_>>()
    });
    entries
}

/// Python 3.12's `Path.is_symlink`, read from Python's `cwd`.
fn is_symlink(inventory: &Inventory, path: &Path) -> Result<bool, &'static str> {
    match fs::symlink_metadata(inventory.fs(path)) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ERR_STAT),
    }
}

fn is_skill_document(name: &str) -> bool {
    if cfg!(windows) {
        name.to_lowercase() == "skill.md"
    } else {
        name == "SKILL.md"
    }
}

/// `_path_digest`: the resolved path, else the path as given.
fn path_digest(inventory: &Inventory, path: &Path) -> Result<String, &'static str> {
    let resolved = resolve(&inventory.fs(path)).unwrap_or_else(|()| path.to_path_buf());
    let text = resolved.to_str().ok_or(ERR_NAME)?;
    Ok(hex::encode(Sha256::digest(text.as_bytes()))[..12].to_owned())
}

/// `_safe_read`: up to 64 KiB of characters with universal newlines, or
/// nothing when the file cannot be opened or decoded as far as Python reads.
fn safe_read(path: &Path) -> String {
    let Ok(file) = fs::File::open(path) else {
        return String::new();
    };
    let mut bytes = Vec::new();
    let limit = (4 * MAX_FILE_READ + 4) as u64;
    if file.take(limit).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    let translate = |text: &str| text.replace("\r\n", "\n").replace('\r', "\n");
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => translate(text),
        Err(error) => {
            let valid = std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap_or_default();
            let prefix = translate(valid);
            if prefix.chars().count() < MAX_FILE_READ {
                return String::new();
            }
            prefix
        }
    };
    text.chars().take(MAX_FILE_READ).collect()
}

fn content_hash(content: &str) -> String {
    hex::encode(Sha256::digest(content.as_bytes()))[..16].to_owned()
}

/// `_frontmatter_name`.
fn frontmatter_name(content: &str) -> Option<String> {
    let (head, _) = content.strip_prefix("---")?.split_once("---")?;
    for line in py_splitlines(head) {
        let (key, value) = line.split_once(':').unwrap_or((line, ""));
        let value = python_strip(value);
        if python_strip(key) == "name" && !value.is_empty() {
            return Some(value.trim_matches(&['"', '\''][..]).to_owned());
        }
    }
    None
}

/// `_extract_env_mentions`, sorted.
fn env_mentions(content: &str) -> Vec<String> {
    static BRACED: OnceLock<Regex> = OnceLock::new();
    static PROCESS: OnceLock<Regex> = OnceLock::new();
    let braced = BRACED.get_or_init(|| {
        Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("static pattern compiles")
    });
    let process = PROCESS.get_or_init(|| {
        Regex::new(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)").expect("static pattern compiles")
    });
    let mut mentions: Vec<String> = braced
        .captures_iter(content)
        .chain(process.captures_iter(content))
        .map(|captures| captures[1].to_owned())
        .collect();
    mentions.sort();
    mentions.dedup();
    mentions
}

/// `_risk_args`.
fn risk_args(content: &str) -> Vec<String> {
    let mut args = code_blocks(content);
    let plain = plain_markdown(content, 2048);
    if !plain.is_empty() {
        args.push(plain);
    }
    args
}

/// `_is_scannable`, with Python's `Path.suffix` rule.
fn is_scannable(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let suffix = match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => &name[index..],
        _ => "",
    };
    if SCANNABLE_EXTENSIONS.contains(&suffix.to_lowercase().as_str()) {
        return true;
    }
    suffix.is_empty()
        && (SCANNABLE_NAMES.contains(&&*name)
            || path.components().any(|part| part.as_os_str() == "scripts"))
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `_artifacts_for_skill`.
fn skill_artifacts(
    inventory: &mut Inventory,
    root: &Path,
    skill_md: &Path,
) -> Result<(), &'static str> {
    let content = safe_read(&inventory.fs(skill_md));
    let skill_dir = skill_md.parent().unwrap_or(skill_md);
    let dir_name = skill_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = frontmatter_name(&content)
        .filter(|name| !name.is_empty())
        .unwrap_or(dir_name);
    let root_id = path_digest(inventory, root)?;
    let dir_id = path_digest(inventory, skill_dir)?;
    let scope = format!("skill-root:{root_id}");
    let skill_scope = Scope {
        harness: "openclaw",
        scope: &scope,
    };
    let prefix = format!("openclaw:skill:{root_id}:{dir_id}:{name}");
    let mut metadata = Map::new();
    metadata.insert("content_hash".to_owned(), json!(content_hash(&content)));
    metadata.insert("skill_root".to_owned(), json!(text(root)));
    metadata.insert("skill_root_id".to_owned(), json!(root_id));
    metadata.insert("skill_dir".to_owned(), json!(text(skill_dir)));
    metadata.insert("skill_dir_id".to_owned(), json!(dir_id));
    metadata.insert("env_mentions".to_owned(), json!(env_mentions(&content)));
    let command = text(skill_md);
    let artifact = skill_scope.wire(
        prefix.clone(),
        &name,
        "skill",
        skill_md,
        Fields {
            command: Some(command.as_str()),
            args: risk_args(&content),
            ..Fields::default()
        },
        metadata,
    );
    inventory.artifacts.push(artifact);
    for subdir_name in SKILL_SUBDIRS {
        let subdir = skill_dir.join(subdir_name);
        if !inventory.is_dir(&subdir)? {
            continue;
        }
        for entry in walk(inventory, &subdir) {
            let path = &entry.path;
            if is_symlink(inventory, path)? || !inventory.is_file(path)? || !is_scannable(path) {
                continue;
            }
            let file_content = safe_read(&inventory.fs(path));
            if file_content.is_empty() {
                continue;
            }
            if entry.undecodable {
                return Err(ERR_NAME);
            }
            let relative = text(
                &entry
                    .parts
                    .iter()
                    .fold(PathBuf::from(subdir_name), |relative, part| {
                        relative.join(part)
                    }),
            );
            let mut metadata = Map::new();
            metadata.insert("parent_skill".to_owned(), json!(name));
            metadata.insert(
                "content_hash".to_owned(),
                json!(content_hash(&file_content)),
            );
            metadata.insert("skill_root_id".to_owned(), json!(root_id));
            metadata.insert("skill_dir_id".to_owned(), json!(dir_id));
            metadata.insert(
                "env_mentions".to_owned(),
                json!(env_mentions(&file_content)),
            );
            let command = text(path);
            let artifact = skill_scope.wire(
                format!("{prefix}:{relative}"),
                &format!("{name}/{relative}"),
                "skill_file",
                path,
                Fields {
                    command: Some(command.as_str()),
                    args: risk_args(&file_content),
                    ..Fields::default()
                },
                metadata,
            );
            inventory.artifacts.push(artifact);
        }
    }
    Ok(())
}

/// `skill_artifacts`: every `SKILL.md` below each distinct skill root.
pub(crate) fn skills(inventory: &mut Inventory, roots: Vec<PathBuf>) -> Result<(), &'static str> {
    let mut seen: Vec<PathBuf> = Vec::new();
    for root in roots {
        if seen.contains(&root) || !inventory.is_dir(&root)? {
            continue;
        }
        seen.push(root.clone());
        for entry in walk(inventory, &root) {
            let name = entry.parts.last().map(String::as_str).unwrap_or_default();
            if !is_skill_document(name) {
                continue;
            }
            let skill_md = &entry.path;
            if is_symlink(inventory, skill_md)? || !inventory.is_file(skill_md)? {
                continue;
            }
            if entry.undecodable {
                return Err(ERR_NAME);
            }
            inventory.push_found(skill_md);
            skill_artifacts(inventory, &root, skill_md)?;
        }
    }
    Ok(())
}
