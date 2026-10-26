//! `hol-guard plugin check --spec agent-plugins-1.0`: whether a plugin root
//! conforms to the Agent Plugins Specification 1.0.0, and what a conforming
//! client would do with each part that does not.
//!
//! The rules follow the specification text and its two schemas
//! (`schemas/1.0.0/plugin.schema.json` and `mcp.schema.json` at tag `v1.0.0`
//! of github.com/agentplugins/agent-plugins-spec). They are written out here
//! because the specification forbids fetching a schema while loading a
//! plugin, and the Kit makes no network calls. Where the text and the schemas
//! differ, the text wins, as the specification says.
//!
//! Every finding names the section it comes from and its effect on a client:
//! reject the plugin, ignore a field, skip a skill or server, disable MCP, or
//! treat a component type as invalid. A package passes only when a client
//! would load all of it.

use std::path::Path;

use serde::Serialize;
use serde_json::{json, Map, Value};

mod mcp;
mod paths;
mod skills;
mod url;

use mcp::mcp_servers;
use paths::{read_inside, Read};
use skills::discover_skills;
pub(crate) use skills::portable_skill;
pub(crate) use url::url_problem;

pub const SPEC: &str = "agent-plugins-1.0";
pub const VERSION: &str = "1.0.0";
pub const PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
pub const MCP_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
const SCHEMA_PREFIX: &str = "https://agent-plugins.org/schemas/";

const MANIFEST_FIELDS: [&str; 10] = [
    "$schema",
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
    "extensions",
];
const MAX_NAME: usize = 64;
const MAX_SKILL_DESCRIPTION: usize = 1024;
const MAX_SKILLS: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// The client rejects the plugin and loads none of it.
    RejectPlugin,
    /// The client reports the field and ignores it.
    IgnoreField,
    /// The client treats the whole component type as invalid.
    InvalidComponent,
    /// The client disables MCP for the plugin.
    DisableMcp,
    SkipSkill,
    SkipServer,
    /// Advice only; the client loads the part.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub level: Level,
    pub code: &'static str,
    pub path: String,
    pub message: String,
    /// The section of the specification the finding comes from.
    pub section: &'static str,
    pub effect: Effect,
}

#[derive(Default)]
struct Report {
    findings: Vec<Finding>,
}

impl Report {
    fn error(
        &mut self,
        code: &'static str,
        path: &str,
        section: &'static str,
        effect: Effect,
        message: impl Into<String>,
    ) {
        self.findings.push(Finding {
            level: Level::Error,
            code,
            path: path.to_owned(),
            message: message.into(),
            section,
            effect,
        });
    }

    fn warning(
        &mut self,
        code: &'static str,
        path: &str,
        section: &'static str,
        message: impl Into<String>,
    ) {
        self.findings.push(Finding {
            level: Level::Warning,
            code,
            path: path.to_owned(),
            message: message.into(),
            section,
            effect: Effect::None,
        });
    }
}

/// Checks `root` (already resolved) and returns the conformance report.
pub fn check(root: &Path, strict: bool) -> Value {
    let mut report = Report::default();
    let manifest = manifest(root, &mut report);
    let mut skills = Vec::new();
    let mut servers = Vec::new();
    if manifest.is_some() {
        skills = discover_skills(root, &mut report);
        servers = mcp_servers(root, &mut report);
    }
    let errors = report
        .findings
        .iter()
        .filter(|finding| finding.level == Level::Error)
        .count();
    let warnings = report.findings.len() - errors;
    let field = |key: &str| {
        manifest
            .as_ref()
            .and_then(|manifest| manifest.get(key))
            .and_then(Value::as_str)
    };
    json!({
        "spec": SPEC,
        "version": VERSION,
        "passed": errors == 0 && (!strict || warnings == 0),
        "plugin": {"name": field("name"), "version": field("version")},
        "components": {"skills": skills, "mcp_servers": servers},
        "diagnostics": report.findings,
        "summary": {"errors": errors, "warnings": warnings},
    })
}

/// The manifest when a client would load the plugin, else `None`.
fn manifest(root: &Path, report: &mut Report) -> Option<Map<String, Value>> {
    const PATH: &str = "plugin.json";
    let reject = |report: &mut Report, code, section, message: &str| {
        report.error(code, PATH, section, Effect::RejectPlugin, message);
    };
    let text = match read_inside(root, Path::new(PATH)) {
        Read::Missing => {
            reject(
                report,
                "manifest_missing",
                "4.1",
                "A plugin needs plugin.json at its root.",
            );
            return None;
        }
        Read::Outside => {
            reject(
                report,
                "manifest_outside_root",
                "4.1",
                "plugin.json resolves outside the plugin folder.",
            );
            return None;
        }
        Read::NotFile | Read::Unreadable => {
            reject(
                report,
                "manifest_unreadable",
                "5.2",
                "plugin.json must be a readable UTF-8 file of at most 1 MiB.",
            );
            return None;
        }
        Read::Text(text) => text,
    };
    let Ok(Value::Object(document)) = serde_json::from_str::<Value>(&text) else {
        reject(
            report,
            "manifest_invalid_json",
            "5.2",
            "plugin.json must hold one JSON object.",
        );
        return None;
    };
    let mut fatal = false;
    for key in document.keys() {
        if !MANIFEST_FIELDS.contains(&key.as_str()) {
            report.error(
                "manifest_unknown_field",
                PATH,
                "5.2",
                Effect::IgnoreField,
                format!("`{key}` is not an Agent Plugins field; clients ignore it. Client data belongs under `extensions`."),
            );
        }
    }
    match document.get("$schema") {
        Some(Value::String(schema)) if schema == PLUGIN_SCHEMA => {}
        Some(Value::String(schema)) => {
            fatal = true;
            match declared_version(schema, "plugin.schema.json") {
                Some(version) => reject(
                    report,
                    "spec_version_unsupported",
                    "5.2",
                    &format!(
                        "plugin.json targets Agent Plugins {version}; this check covers {VERSION}."
                    ),
                ),
                None => reject(
                    report,
                    "schema_unrecognized",
                    "5.2",
                    &format!("`$schema` must be {PLUGIN_SCHEMA}."),
                ),
            }
        }
        _ => {
            fatal = true;
            reject(
                report,
                "schema_missing",
                "5.3",
                &format!("plugin.json needs `\"$schema\": \"{PLUGIN_SCHEMA}\"`."),
            );
        }
    }
    match document.get("name") {
        Some(Value::String(name)) if valid_plugin_name(name) => {}
        Some(Value::String(_)) => {
            fatal = true;
            reject(
                report,
                "name_invalid",
                "5.5",
                "`name` must be 1-64 lowercase letters, digits, hyphens or periods, start and end with a letter or digit, and have no `--` or `..`.",
            );
        }
        _ => {
            fatal = true;
            reject(
                report,
                "name_missing",
                "5.3",
                "plugin.json needs a `name` string.",
            );
        }
    }
    for key in [
        "version",
        "description",
        "homepage",
        "repository",
        "license",
    ] {
        if document.get(key).is_some_and(|value| !value.is_string()) {
            fatal = true;
            reject(
                report,
                "field_type_invalid",
                "5.4",
                &format!("`{key}` must be a string."),
            );
        }
    }
    if let Some(author) = document.get("author") {
        let valid = author.as_object().is_some_and(|author| {
            author.iter().all(|(key, value)| {
                matches!(key.as_str(), "name" | "email" | "url") && value.is_string()
            })
        });
        if !valid {
            fatal = true;
            reject(
                report,
                "author_invalid",
                "5.4",
                "`author` may hold only `name`, `email` and `url` strings.",
            );
        }
    }
    if let Some(keywords) = document.get("keywords") {
        if !keywords
            .as_array()
            .is_some_and(|keywords| keywords.iter().all(Value::is_string))
        {
            fatal = true;
            reject(
                report,
                "keywords_invalid",
                "5.4",
                "`keywords` must be a list of strings.",
            );
        }
    }
    match document.get("extensions") {
        None => {}
        Some(Value::Object(extensions)) => {
            for (namespace, value) in extensions {
                if !value.is_object() {
                    fatal = true;
                    reject(
                        report,
                        "extension_not_object",
                        "8.1",
                        &format!("`extensions.{namespace}` must be an object."),
                    );
                }
            }
        }
        Some(_) => report.error(
            "extensions_not_object",
            PATH,
            "8.1",
            Effect::IgnoreField,
            "`extensions` must be an object keyed by reverse-domain namespace; clients ignore it.",
        ),
    }
    if let Some(Value::String(version)) = document.get("version") {
        if !crate::check::is_semver(version) {
            report.warning(
                "version_not_semver",
                PATH,
                "10.2",
                "Use a semantic version such as 1.2.0.",
            );
        }
    }
    (!fatal).then_some(document)
}

/// The version in an Agent Plugins schema identifier, such as `1.1.0` in
/// `https://agent-plugins.org/schemas/1.1.0/plugin.schema.json`.
fn declared_version<'a>(schema: &'a str, file: &str) -> Option<&'a str> {
    let version = schema
        .strip_prefix(SCHEMA_PREFIX)?
        .strip_suffix(file)?
        .strip_suffix('/')?;
    (!version.is_empty() && !version.contains('/')).then_some(version)
}

/// §5.5: 1-64 of `a-z0-9.-`, alphanumeric at both ends, no `--` or `..`.
pub(crate) fn valid_plugin_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !name.is_empty()
        && name.len() <= MAX_NAME
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && !name.contains("--")
        && !name.contains("..")
}

#[cfg(test)]
mod tests {
    use super::{declared_version, valid_plugin_name};

    #[test]
    fn plugin_names_follow_section_5_5() {
        for name in ["my-plugin", "acme.tools", "lint3r", "a"] {
            assert!(valid_plugin_name(name), "{name}");
        }
        for name in [
            "My-Plugin",
            "-start",
            "has--double",
            "too.many..dots",
            "",
            "end.",
        ] {
            assert!(!valid_plugin_name(name), "{name}");
        }
        assert!(!valid_plugin_name(&"a".repeat(65)));
    }

    #[test]
    fn schema_versions_are_read_from_the_identifier() {
        assert_eq!(
            declared_version(
                "https://agent-plugins.org/schemas/1.1.0/plugin.schema.json",
                "plugin.schema.json"
            ),
            Some("1.1.0")
        );
        assert_eq!(
            declared_version(
                "https://example.com/plugin.schema.json",
                "plugin.schema.json"
            ),
            None
        );
    }
}
