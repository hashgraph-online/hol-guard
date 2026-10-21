//! The static configuration closure that a routine runner loads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use serde_json::Value;

use super::{framed_digest, module_scan, probe, sha256_hex, Abort, Outcome};
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_interpreter_trust::resolve_strict;

const MAX_CONFIG_FILES: usize = 128;
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MODULE_SUFFIXES: [&str; 8] = ["", ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".json"];
const NODE_BUILTINS: [&str; 30] = [
    "assert",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "crypto",
    "dns",
    "events",
    "fs",
    "http",
    "https",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "querystring",
    "readline",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "worker_threads",
    "zlib",
];

/// Local module files to capture next and the bare packages they import.
type Modules = (Vec<PyPath>, BTreeSet<String>);

fn root_names(runner: &str) -> &'static [&'static str] {
    match runner {
        "next" => &[
            "next.config.js",
            "next.config.cjs",
            "next.config.mjs",
            "next.config.ts",
            "next.config.cts",
            "next.config.mts",
        ],
        "eslint" => &[
            "eslint.config.js",
            "eslint.config.cjs",
            "eslint.config.mjs",
            "eslint.config.ts",
            "eslint.config.cts",
            "eslint.config.mts",
            ".eslintrc",
            ".eslintrc.js",
            ".eslintrc.cjs",
            ".eslintrc.json",
            ".eslintrc.yaml",
            ".eslintrc.yml",
        ],
        _ => &["tsconfig.json"],
    }
}

/// `routine_configuration_identity`: the digest of the runner configuration
/// and its statically referenced local modules, plus their bare packages.
pub(super) fn configuration_identity(
    workspace: &PyPath,
    runner: &str,
) -> Outcome<(String, Vec<String>)> {
    let mut pending = Vec::new();
    for name in std::iter::once("package.json").chain(root_names(runner).iter().copied()) {
        let candidate = workspace.join(name);
        if probe(&candidate, pyfs::exists)? {
            pending.push(candidate);
        }
    }
    let canonical_workspace = resolve_strict(workspace).ok_or(Abort)?;
    let mut captured: BTreeMap<String, String> = BTreeMap::new();
    let mut packages: BTreeSet<String> = BTreeSet::new();
    let mut total_bytes = 0_usize;
    while let Some(path) = pending.pop() {
        let canonical = canonical_workspace_file(&canonical_workspace, &path)?;
        let relative = canonical
            .relative_to(&canonical_workspace)
            .ok_or(Abort)?
            .join("/");
        if captured.contains_key(&relative) {
            continue;
        }
        if captured.len() >= MAX_CONFIG_FILES {
            return Err(Abort);
        }
        let data = fs::read(canonical.to_string()).map_err(|_| Abort)?;
        total_bytes += data.len();
        if total_bytes > MAX_CONFIG_BYTES {
            return Err(Abort);
        }
        captured.insert(relative, sha256_hex(&data));
        let suffix = canonical.suffix().to_lowercase();
        if matches!(suffix.as_str(), ".yaml" | ".yml") || canonical.name() == ".eslintrc" {
            return Err(Abort);
        }
        let (local, external) = if suffix == ".json" {
            json_configuration_modules(&canonical_workspace, &canonical, &data)?
        } else {
            let text = std::str::from_utf8(&data).map_err(|_| Abort)?;
            script_configuration_modules(&canonical_workspace, &canonical, text)?
        };
        pending.extend(local);
        packages.extend(external);
    }
    let records: Vec<Value> = captured
        .into_iter()
        .map(|(relative, digest)| {
            Value::Array(vec![Value::String(relative), Value::String(digest)])
        })
        .collect();
    let digest = framed_digest(b"hol-guard:node-config:v1\0", &Value::Array(records))?;
    Ok((digest, packages.into_iter().collect()))
}

/// A regular, non-symlink file inside the workspace and outside `node_modules`.
fn canonical_workspace_file(workspace: &PyPath, path: &PyPath) -> Outcome<PyPath> {
    if probe(path, pyfs::is_symlink)? || !probe(path, pyfs::is_file)? {
        return Err(Abort);
    }
    let canonical = resolve_strict(path).ok_or(Abort)?;
    let relative = canonical.relative_to(workspace).ok_or(Abort)?;
    if relative.iter().any(|part| part == "node_modules") {
        return Err(Abort);
    }
    Ok(canonical)
}

fn script_configuration_modules(
    workspace: &PyPath,
    importer: &PyPath,
    text: &str,
) -> Outcome<Modules> {
    if module_scan::rejects(text) {
        return Err(Abort);
    }
    let mut resolved = Vec::new();
    let mut packages = BTreeSet::new();
    for raw in module_scan::static_paths(text) {
        if !raw.starts_with('.') {
            packages.extend(bare_package_name(&raw));
            continue;
        }
        resolved.push(resolve_local_module(workspace, importer, &raw)?);
    }
    Ok((resolved, packages))
}

fn json_configuration_modules(
    workspace: &PyPath,
    importer: &PyPath,
    data: &[u8],
) -> Outcome<Modules> {
    let payload: Value = serde_json::from_str(&decode_json_bytes(data)?).map_err(|_| Abort)?;
    let mut specifiers = Vec::new();
    let mut packages = BTreeSet::new();
    collect_json_config_inputs(&payload, &mut specifiers, &mut packages);
    let mut resolved = Vec::new();
    for raw in specifiers {
        if raw.starts_with('.') {
            resolved.push(resolve_local_module(workspace, importer, &raw)?);
        } else {
            packages.extend(bare_package_name(&raw));
        }
    }
    Ok((resolved, packages))
}

/// `json.loads(bytes)`: `json.detect_encoding` then a strict decode.
fn decode_json_bytes(data: &[u8]) -> Outcome<String> {
    if data.starts_with(&[0, 0, 0xFE, 0xFF]) {
        return utf32(&data[4..], true);
    }
    if data.starts_with(&[0xFF, 0xFE, 0, 0]) {
        return utf32(&data[4..], false);
    }
    if data.starts_with(&[0xFE, 0xFF]) {
        return utf16(&data[2..], true);
    }
    if data.starts_with(&[0xFF, 0xFE]) {
        return utf16(&data[2..], false);
    }
    if let Some(rest) = data.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return utf8(rest);
    }
    if data.len() >= 4 {
        if data[0] == 0 {
            return if data[1] != 0 {
                utf16(data, true)
            } else {
                utf32(data, true)
            };
        }
        if data[1] == 0 {
            return if data[2] != 0 || data[3] != 0 {
                utf16(data, false)
            } else {
                utf32(data, false)
            };
        }
    } else if data.len() == 2 {
        if data[0] == 0 {
            return utf16(data, true);
        }
        if data[1] == 0 {
            return utf16(data, false);
        }
    }
    utf8(data)
}

fn utf8(data: &[u8]) -> Outcome<String> {
    String::from_utf8(data.to_vec()).map_err(|_| Abort)
}

fn utf16(data: &[u8], big_endian: bool) -> Outcome<String> {
    if data.len() % 2 != 0 {
        return Err(Abort);
    }
    let units = data.chunks_exact(2).map(|pair| {
        let bytes = [pair[0], pair[1]];
        if big_endian {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        }
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|_| Abort)
}

fn utf32(data: &[u8], big_endian: bool) -> Outcome<String> {
    if data.len() % 4 != 0 {
        return Err(Abort);
    }
    data.chunks_exact(4)
        .map(|quad| {
            let bytes = [quad[0], quad[1], quad[2], quad[3]];
            let point = if big_endian {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            };
            char::from_u32(point).ok_or(Abort)
        })
        .collect()
}

fn collect_json_config_inputs(
    payload: &Value,
    specifiers: &mut Vec<String>,
    packages: &mut BTreeSet<String>,
) {
    match payload {
        Value::Object(entries) => {
            for (key, value) in entries {
                match key.as_str() {
                    "extends" | "path" => {
                        for item in string_values(value) {
                            match eslint_extended_package(item) {
                                Some(package) => {
                                    packages.insert(package);
                                }
                                None => specifiers.push(item.to_owned()),
                            }
                        }
                    }
                    "parser" if value.is_string() => {
                        packages.extend(value.as_str().and_then(bare_package_name));
                    }
                    "plugins" => collect_plugin_packages(value, packages),
                    _ => collect_json_config_inputs(value, specifiers, packages),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_json_config_inputs(item, specifiers, packages);
            }
        }
        _ => {}
    }
}

fn string_values(value: &Value) -> Vec<&str> {
    match value {
        Value::String(text) => vec![text.as_str()],
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn collect_plugin_packages(value: &Value, packages: &mut BTreeSet<String>) {
    let Value::Array(items) = value else {
        return;
    };
    for item in items {
        match item {
            Value::String(plugin) => {
                packages.insert(eslint_plugin_package(plugin));
            }
            Value::Object(entry) => {
                packages.extend(
                    entry
                        .get("name")
                        .and_then(Value::as_str)
                        .and_then(bare_package_name),
                );
            }
            _ => {}
        }
    }
}

fn eslint_extended_package(specifier: &str) -> Option<String> {
    let remainder = specifier.strip_prefix("plugin:")?;
    let parts: Vec<&str> = remainder.split('/').collect();
    if !remainder.starts_with('@') || parts.len() < 2 {
        return Some(eslint_plugin_package(parts[0]));
    }
    let plugin = if parts.len() >= 3 {
        parts[..2].join("/")
    } else {
        parts[0].to_owned()
    };
    Some(eslint_plugin_package(&plugin))
}

fn eslint_plugin_package(plugin: &str) -> String {
    if plugin.starts_with('@') {
        let (scope, name) = plugin.split_once('/').unwrap_or((plugin, ""));
        if name.is_empty() {
            return format!("{scope}/eslint-plugin");
        }
        return if name.starts_with("eslint-plugin") {
            format!("{scope}/{name}")
        } else {
            format!("{scope}/eslint-plugin-{name}")
        };
    }
    if plugin.starts_with("eslint-plugin-") {
        plugin.to_owned()
    } else {
        format!("eslint-plugin-{plugin}")
    }
}

fn bare_package_name(specifier: &str) -> Option<String> {
    if ["node:", "eslint:", "plugin:"]
        .iter()
        .any(|prefix| specifier.starts_with(prefix))
        || NODE_BUILTINS.contains(&specifier)
    {
        return None;
    }
    let parts: Vec<&str> = specifier.split('/').collect();
    if specifier.starts_with('@') && parts.len() >= 2 {
        return Some(parts[..2].join("/"));
    }
    Some(parts[0].to_owned())
}

/// The first existing module candidate for a relative specifier.
fn resolve_local_module(workspace: &PyPath, importer: &PyPath, raw: &str) -> Outcome<PyPath> {
    let base = importer.parent().join(raw);
    let mut candidates: Vec<PyPath> = MODULE_SUFFIXES
        .iter()
        .map(|suffix| PyPath::new(&format!("{base}{suffix}")))
        .collect();
    candidates.extend(
        MODULE_SUFFIXES[1..]
            .iter()
            .map(|suffix| base.join(&format!("index{suffix}"))),
    );
    for candidate in candidates {
        if probe(&candidate, pyfs::is_file)? {
            return canonical_workspace_file(workspace, &candidate);
        }
    }
    Err(Abort)
}
