//! Package-manager configuration collection (`configuration_material`).

use std::collections::{BTreeMap, BTreeSet};

use crate::launch_identity_common::sha256_hex;

use crate::codex_output_py::{py_splitlines, py_strip, PyPath};
use crate::hook_adapter_value::{parse_python_json, OMap, OValue};

use super::configuration_names::{
    dynamic_code_regex, env_reference_regex, manager_names, npm_dynamic_regex,
    user_configuration_paths, JS_MANAGERS,
};
use super::fs::{ContextFiles, Fs, MAX_CONFIG_FILE_BYTES, MAX_TREE_FILES};
use super::ports::Ports;
use super::{object, text, BuildError, Built};

const LIFECYCLE_NAMES: &[&str] = &[
    "install",
    "postinstall",
    "preinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
];

pub(super) struct ConfigurationInput<'a> {
    pub(super) workspace: &'a str,
    pub(super) repository_root: Option<&'a str>,
    pub(super) manager: &'a str,
    pub(super) environment: &'a BTreeMap<String, String>,
}

pub(super) struct Configuration {
    pub(super) registry: OValue,
    pub(super) workspace: OValue,
    pub(super) hooks: OValue,
    pub(super) referenced: Vec<String>,
}

impl Configuration {
    pub(super) fn unavailable(reason: &str) -> Self {
        let status = || object(vec![("status", text(reason))]);
        Self {
            registry: status(),
            workspace: status(),
            hooks: status(),
            referenced: Vec::new(),
        }
    }
}

struct Entry {
    path: String,
    digest: String,
}

#[derive(Default)]
struct Collected {
    registry: Vec<Entry>,
    workspace: Vec<Entry>,
    hooks: Vec<Entry>,
    referenced: BTreeSet<String>,
}

/// `_configuration_roots`: repository root first, workspace last.
fn configuration_roots(workspace: &str, repository_root: Option<&str>) -> Vec<String> {
    let Some(repository_root) = repository_root else {
        return vec![workspace.to_owned()];
    };
    let repository = PyPath::new(repository_root);
    let mut roots = Vec::new();
    let mut current = PyPath::new(workspace);
    loop {
        roots.push(current.to_string());
        if current == repository {
            break;
        }
        if current.relative_to(&repository).is_none() {
            return vec![workspace.to_owned()];
        }
        current = current.parent();
    }
    roots.reverse();
    roots
}

/// `_root_label`.
fn root_label(root: &str, workspace: &str, repository_root: Option<&str>) -> String {
    let path = PyPath::new(root);
    if let Some(repository_root) = repository_root {
        if let Some(parts) = path.relative_to(&PyPath::new(repository_root)) {
            let relative = if parts.is_empty() {
                ".".to_owned()
            } else {
                parts.join("/")
            };
            return format!("repository/{relative}");
        }
    }
    if path == PyPath::new(workspace) {
        return "workspace".to_owned();
    }
    "configuration".to_owned()
}

/// `_normalize_npmrc`.
fn normalize_npmrc(content: &str) -> String {
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for line in py_splitlines(content) {
        let stripped = py_strip(&line);
        if stripped.is_empty() || stripped.starts_with('#') || stripped.starts_with(';') {
            continue;
        }
        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        values.insert(py_strip(key).to_lowercase(), py_strip(value).to_owned());
    }
    let mut map = OMap::new();
    for (key, value) in values {
        map.insert(&key, OValue::Str(value));
    }
    OValue::Map(map).canonical_json()
}

#[derive(Clone, Copy, Default)]
struct Inspect {
    normalize_npmrc: bool,
    dynamic_code: bool,
}

#[derive(Clone, Copy)]
enum Bucket {
    Registry,
    Workspace,
    Hooks,
}

fn dynamic() -> BuildError {
    BuildError::Unavailable("dynamic_manager_configuration")
}

/// `_append_optional_config`.
fn append_optional_config(
    fs: &Fs,
    files: &mut ContextFiles,
    path: &str,
    label: &str,
    bucket: Bucket,
    inspect: Inspect,
    collected: &mut Collected,
) -> Built<()> {
    if !fs.exists(path)? {
        return Ok(());
    }
    let payload = files.read(fs, path, MAX_CONFIG_FILE_BYTES, false)?;
    let content = String::from_utf8(payload.clone()).unwrap_or_default();
    let normalized = if inspect.normalize_npmrc {
        if npm_dynamic_regex().is_match(&content) {
            return Err(dynamic());
        }
        normalize_npmrc(&content).into_bytes()
    } else {
        payload
    };
    if inspect.dynamic_code && dynamic_code_regex().is_match(&content) {
        return Err(dynamic());
    }
    for captures in env_reference_regex().captures_iter(&content) {
        collected.referenced.insert(captures[1].to_owned());
    }
    let entry = Entry {
        digest: sha256_hex(&normalized),
        path: format!("{label}/{}", PyPath::new(path).name()),
    };
    match bucket {
        Bucket::Registry => collected.registry.push(entry),
        Bucket::Workspace => collected.workspace.push(entry),
        Bucket::Hooks => collected.hooks.push(entry),
    }
    Ok(())
}

fn unsupported() -> BuildError {
    BuildError::Unavailable("unsupported_configuration")
}

/// `json.loads(bytes)` for the encodings the port can represent (UTF-8, with or
/// without a byte-order mark). Anything else is reported as unsupported, which
/// only ever makes the context non-portable.
fn parse_package_json(payload: &[u8]) -> Built<OValue> {
    let body = payload.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(payload);
    let content = std::str::from_utf8(body).map_err(|_| unsupported())?;
    parse_python_json(content).map_err(|_| unsupported())
}

/// `_append_package_json_security_sections`.
fn append_package_json_sections(
    fs: &Fs,
    files: &mut ContextFiles,
    ports: &mut dyn Ports,
    path: &str,
    label: &str,
    collected: &mut Collected,
) -> Built<()> {
    let payload = files.read(fs, path, MAX_CONFIG_FILE_BYTES, false)?;
    let parsed = parse_package_json(&payload)?;
    let OValue::Map(parsed) = parsed else {
        return Err(unsupported());
    };
    let mut workspace_sections = OMap::new();
    for key in ["packageManager", "workspaces"] {
        if let Some(value) = parsed.get(key) {
            workspace_sections.insert(key, value.clone());
        }
    }
    let mut lifecycle = OMap::new();
    if let Some(OValue::Map(scripts)) = parsed.get("scripts") {
        for (key, value) in scripts.iter() {
            if LIFECYCLE_NAMES.contains(&key) {
                lifecycle.insert(key, value.clone());
            }
        }
    }
    let has_lifecycle = !lifecycle.is_empty();
    let mut hook_sections = OMap::new();
    hook_sections.insert("lifecycle_scripts", OValue::Map(lifecycle));
    for key in ["overrides", "pnpm", "resolutions"] {
        if let Some(value) = parsed.get(key) {
            hook_sections.insert(key, value.clone());
        }
    }
    let entry_path = format!("{label}/package.json");
    let workspace_digest = ports.digest_material(&OValue::Map(workspace_sections).canonical_json());
    collected.workspace.push(Entry {
        digest: workspace_digest,
        path: entry_path.clone(),
    });
    let hook_digest = ports.digest_material(&OValue::Map(hook_sections).canonical_json());
    collected.hooks.push(Entry {
        digest: hook_digest,
        path: entry_path,
    });
    if has_lifecycle {
        return Err(BuildError::Unavailable("dynamic_lifecycle_hook"));
    }
    Ok(())
}

/// `_append_tree`.
fn append_tree(
    fs: &Fs,
    files: &mut ContextFiles,
    root: &str,
    label: &str,
    collected: &mut Collected,
) -> Built<()> {
    if !fs.exists(root)? {
        return Ok(());
    }
    if fs.is_symlink(root)? || !fs.is_dir(root)? {
        return Err(unsupported());
    }
    let listing = fs
        .rglob(root)
        .map_err(|()| BuildError::Unavailable("unreadable_configuration"))?;
    let mut file_paths = Vec::new();
    for path in listing {
        if fs.is_file(&path)? || fs.is_symlink(&path)? {
            file_paths.push(path);
        }
    }
    if file_paths.len() > MAX_TREE_FILES {
        return Err(BuildError::Unavailable("oversized_configuration"));
    }
    let base = PyPath::new(root);
    for path in file_paths {
        let payload = files.read(fs, &path, MAX_CONFIG_FILE_BYTES, false)?;
        let parsed = PyPath::new(&path);
        if matches!(parsed.suffix(), ".cjs" | ".js" | ".mjs") {
            let content = String::from_utf8(payload.clone()).unwrap_or_default();
            if dynamic_code_regex().is_match(&content) {
                return Err(dynamic());
            }
        }
        let relative = parsed
            .relative_to(&base)
            .map_or_else(String::new, |parts| parts.join("/"));
        collected.hooks.push(Entry {
            digest: sha256_hex(&payload),
            path: format!("{label}/{relative}"),
        });
    }
    Ok(())
}

fn files_material(mut entries: Vec<Entry>) -> OValue {
    entries.sort_by(|left, right| (&left.path, &left.digest).cmp(&(&right.path, &right.digest)));
    let listing = entries
        .iter()
        .map(|entry| {
            object(vec![
                ("digest", text(&entry.digest)),
                ("path", text(&entry.path)),
            ])
        })
        .collect();
    object(vec![("files", OValue::List(listing))])
}

pub(super) fn configuration_material(
    fs: &Fs,
    files: &mut ContextFiles,
    ports: &mut dyn Ports,
    input: &ConfigurationInput<'_>,
) -> Built<Configuration> {
    let manager = input.manager;
    let roots = configuration_roots(input.workspace, input.repository_root);
    let names = manager_names(manager);
    let mut collected = Collected::default();
    for root in &roots {
        let label = root_label(root, input.workspace, input.repository_root);
        let base = PyPath::new(root);
        for name in names.registry {
            let inspect = Inspect {
                normalize_npmrc: name.ends_with("npmrc"),
                dynamic_code: false,
            };
            let path = base.join(name).to_string();
            append_optional_config(
                fs,
                files,
                &path,
                &label,
                Bucket::Registry,
                inspect,
                &mut collected,
            )?;
        }
        for name in names.workspace {
            let path = base.join(name).to_string();
            append_optional_config(
                fs,
                files,
                &path,
                &label,
                Bucket::Workspace,
                Inspect::default(),
                &mut collected,
            )?;
        }
        for name in names.hooks {
            let inspect = Inspect {
                normalize_npmrc: false,
                dynamic_code: true,
            };
            let path = base.join(name).to_string();
            append_optional_config(
                fs,
                files,
                &path,
                &label,
                Bucket::Hooks,
                inspect,
                &mut collected,
            )?;
        }
        let package_json = base.join("package.json").to_string();
        if JS_MANAGERS.contains(&manager) && fs.exists(&package_json)? {
            append_package_json_sections(fs, files, ports, &package_json, &label, &mut collected)?;
        }
    }
    for (path, npmrc) in user_configuration_paths(fs, manager, input.environment)? {
        let inspect = Inspect {
            normalize_npmrc: npmrc,
            dynamic_code: false,
        };
        append_optional_config(
            fs,
            files,
            &path,
            "user",
            Bucket::Registry,
            inspect,
            &mut collected,
        )?;
    }
    if JS_MANAGERS.contains(&manager) {
        for root in &roots {
            let label = root_label(root, input.workspace, input.repository_root);
            for relative in [".yarn/plugins", ".yarn/patches", "patches"] {
                let tree = PyPath::new(root).join(relative).to_string();
                append_tree(
                    fs,
                    files,
                    &tree,
                    &format!("{label}/{relative}"),
                    &mut collected,
                )?;
            }
        }
    }
    Ok(Configuration {
        registry: files_material(collected.registry),
        workspace: files_material(collected.workspace),
        hooks: files_material(collected.hooks),
        referenced: collected.referenced.into_iter().collect(),
    })
}
