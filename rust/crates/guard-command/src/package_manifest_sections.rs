//! The parts of a manifest that decide what a package manager installs.
//!
//! A saved package approval is meant to hold while the lockfile does. Binding
//! the whole `package.json` or `pyproject.toml` made it lapse on edits that
//! install nothing different: a release version bump, a new `dev` script, a
//! linter setting. Only the sections below reach the resolver, the build
//! backend or an install hook, so only they are digested. Where a section
//! might reach an install, it stays: every script once any install hook is
//! present, since a hook can run another script by name, and every `[tool]`
//! table except the linters and test runners listed below, since a build
//! backend reads its own. A manifest that cannot be parsed is digested whole,
//! as before. The execution context
//! (Unix only) and the approval hash (every platform) both read it from here.

use crate::codex_output_py::PyPath;
use crate::hook_adapter_value::{parse_python_json, OMap, OValue};
use crate::launch_identity_common::sha256_hex;

/// Lifecycle scripts a package manager runs on install. Other scripts only run
/// when someone asks for them by name.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const LIFECYCLE_NAMES: &[&str] = &[
    "dependencies",
    "install",
    "pnpm:devPreinstall",
    "postinstall",
    "postprepare",
    "preinstall",
    "prepare",
    "preprepare",
    "prepublish",
    "prepublishOnly",
];

const PACKAGE_JSON_SECTIONS: &[&str] = &[
    "bundleDependencies",
    "bundledDependencies",
    "cpu",
    "dependencies",
    "dependenciesMeta",
    "devDependencies",
    "engines",
    "optionalDependencies",
    "os",
    "overrides",
    "packageManager",
    "patchedDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "pnpm",
    "resolutions",
    "trustedDependencies",
    "workspaces",
];

const PYPROJECT_PROJECT_KEYS: &[&str] = &[
    "dependencies",
    "dynamic",
    "entry-points",
    "gui-scripts",
    "name",
    "optional-dependencies",
    "requires-python",
    "scripts",
];

/// `[tool]` tables read only by linters, formatters, type checkers and test
/// runners. No package manager or build backend reads them; every other
/// `[tool]` table is kept.
const INERT_TOOL_TABLES: &[&str] = &[
    "bandit",
    "basedpyright",
    "black",
    "codespell",
    "coverage",
    "docformatter",
    "interrogate",
    "isort",
    "mypy",
    "pydocstyle",
    "pylint",
    "pyright",
    "pytest",
    "ruff",
    "ty",
    "vulture",
];

/// `[tool.poetry]` keys that describe the published package, not what installs.
const POETRY_METADATA_KEYS: &[&str] = &[
    "authors",
    "classifiers",
    "description",
    "documentation",
    "homepage",
    "keywords",
    "license",
    "maintainers",
    "readme",
    "repository",
    "urls",
    "version",
];

/// The digest a manifest file contributes: its install-relevant sections when
/// it is a `package.json` or `pyproject.toml` that parses, else its bytes.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn manifest_digest(path: &str, payload: &[u8]) -> String {
    match install_section_bytes(path, payload) {
        Some(sections) => sha256_hex(sections.as_bytes()),
        None => sha256_hex(payload),
    }
}

/// The canonical JSON of a manifest's install-relevant sections, or `None`
/// when `path` is not a `package.json` or `pyproject.toml` that parses. The
/// approval hash binds this in place of the file bytes for the same reason
/// the execution context does.
pub fn install_section_bytes(path: &str, payload: &[u8]) -> Option<String> {
    let sections = match PyPath::new(path).name() {
        "package.json" => package_json_sections(payload),
        "pyproject.toml" => pyproject_sections(payload),
        _ => None,
    }?;
    Some(OValue::Map(sections).canonical_json())
}

fn package_json_sections(payload: &[u8]) -> Option<OMap> {
    let body = payload.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(payload);
    let OValue::Map(parsed) = parse_python_json(std::str::from_utf8(body).ok()?).ok()? else {
        return None;
    };
    let mut sections = OMap::new();
    for key in PACKAGE_JSON_SECTIONS {
        if let Some(value) = parsed.get(key) {
            sections.insert(key, value.clone());
        }
    }
    // An install hook can run any other script by name and reads `config`
    // through `npm_package_config_*`, so both stay bound while a hook exists.
    if let Some(OValue::Map(scripts)) = parsed.get("scripts") {
        if scripts
            .iter()
            .any(|(key, _)| LIFECYCLE_NAMES.contains(&key))
        {
            sections.insert("scripts", OValue::Map(scripts.clone()));
            if let Some(config) = parsed.get("config") {
                sections.insert("config", config.clone());
            }
        }
    }
    Some(sections)
}

fn pyproject_sections(payload: &[u8]) -> Option<OMap> {
    let parsed: toml::Table = toml::from_str(std::str::from_utf8(payload).ok()?).ok()?;
    let mut sections = OMap::new();
    if let Some(toml::Value::Table(project)) = parsed.get("project") {
        let kept = pick(project, |key| PYPROJECT_PROJECT_KEYS.contains(&key))?;
        sections.insert("project", OValue::Map(kept));
    }
    for key in ["build-system", "dependency-groups"] {
        if let Some(value) = parsed.get(key) {
            sections.insert(key, toml_value(value)?);
        }
    }
    if let Some(toml::Value::Table(tool)) = parsed.get("tool") {
        let mut tools = OMap::new();
        for (name, value) in tool {
            match (name.as_str(), value) {
                (name, _) if INERT_TOOL_TABLES.contains(&name) => {}
                ("poetry", toml::Value::Table(poetry)) => {
                    let kept = pick(poetry, |key| !POETRY_METADATA_KEYS.contains(&key))?;
                    tools.insert("poetry", OValue::Map(kept));
                }
                (name, value) => tools.insert(name, toml_value(value)?),
            }
        }
        if !tools.is_empty() {
            sections.insert("tool", OValue::Map(tools));
        }
    }
    Some(sections)
}

fn pick(table: &toml::Table, keep: impl Fn(&str) -> bool) -> Option<OMap> {
    let mut kept = OMap::new();
    for (key, value) in table {
        if keep(key) {
            kept.insert(key, toml_value(value)?);
        }
    }
    Some(kept)
}

/// A TOML value as JSON. Floats and datetimes never appear in the sections
/// above in practice; either one falls back to digesting the whole file
/// rather than guess at a spelling.
fn toml_value(value: &toml::Value) -> Option<OValue> {
    Some(match value {
        toml::Value::String(text) => OValue::Str(text.clone()),
        toml::Value::Integer(number) => OValue::Int(number.to_string()),
        toml::Value::Boolean(flag) => OValue::Bool(*flag),
        toml::Value::Array(items) => {
            OValue::List(items.iter().map(toml_value).collect::<Option<_>>()?)
        }
        toml::Value::Table(table) => OValue::Map(pick(table, |_| true)?),
        toml::Value::Float(_) | toml::Value::Datetime(_) => return None,
    })
}
