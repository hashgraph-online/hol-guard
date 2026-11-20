//! `hol-guard plugin check`: what a marketplace reviewer or runtime loader
//! would reject, found before the plugin is published.

use serde::Serialize;

use crate::detect::Detection;
use crate::emit::{self, Runtime};
use crate::model::{Diagnostic, Level, Plugin, SourceKind};

const MAX_DESCRIPTION: usize = 1024;
const MAX_SKILL_NAME: usize = 64;

#[derive(Debug, Serialize)]
pub struct Summary {
    pub errors: usize,
    pub warnings: usize,
    pub skills: usize,
    pub mcp_servers: usize,
    pub commands: usize,
    pub agents: usize,
}

#[derive(Debug, Serialize)]
pub struct RuntimeSupport {
    pub runtime: Runtime,
    pub supported: bool,
    /// Components the runtime has no place for.
    pub dropped: Vec<&'static str>,
}

pub fn diagnostics(detection: &Detection) -> Vec<Diagnostic> {
    let plugin = &detection.plugin;
    let mut found = detection.diagnostics.clone();
    if !detection
        .sources
        .iter()
        .any(|source| source.kind.is_plugin_root() || source.kind == SourceKind::AgentSkill)
    {
        found.push(Diagnostic::error(
            "no_plugin_source",
            "",
            "No plugin manifest, MCP server.json or SKILL.md was found.",
        ));
        return found;
    }
    let manifest = primary_manifest(detection);
    let claude = detection
        .sources
        .iter()
        .any(|source| source.kind == SourceKind::ClaudePlugin);
    match plugin.name.as_deref() {
        None => found.push(Diagnostic::error("name_missing", &manifest, "The plugin has no name.")),
        Some(name) if !is_kebab(name) => found.push(if claude {
            Diagnostic::error(
                "name_not_kebab",
                &manifest,
                "Claude Code requires a kebab-case plugin name (lowercase letters, digits and hyphens).",
            )
        } else {
            Diagnostic::warning(
                "name_not_kebab",
                &manifest,
                "Use a kebab-case name so every runtime accepts it unchanged.",
            )
        }),
        Some(_) => {}
    }
    match plugin.version.as_deref() {
        None => found.push(Diagnostic::warning(
            "version_missing",
            &manifest,
            "Add a version so installs and updates can be told apart.",
        )),
        Some(version) if !is_semver(version) => found.push(Diagnostic::warning(
            "version_not_semver",
            &manifest,
            "Use a semantic version such as 1.2.0.",
        )),
        Some(_) => {}
    }
    // A skills-only repository has no manifest to hold a plugin description;
    // each skill carries its own, checked below.
    let has_manifest = detection
        .sources
        .iter()
        .any(|source| source.kind.is_plugin_root());
    match plugin.description.as_deref() {
        None if !has_manifest => {}
        None => found.push(Diagnostic::error(
            "description_missing",
            &manifest,
            "Add a one-sentence description; marketplaces list plugins by it.",
        )),
        Some(description) if description.chars().count() > MAX_DESCRIPTION => {
            found.push(Diagnostic::warning(
                "description_too_long",
                &manifest,
                format!("Keep the description under {MAX_DESCRIPTION} characters."),
            ))
        }
        Some(_) => {}
    }
    if plugin.license.is_none() {
        found.push(Diagnostic::warning(
            "license_missing",
            &manifest,
            "Add a license; most marketplaces will not list a plugin without one.",
        ));
    }
    if plugin.repository.is_none() {
        found.push(Diagnostic::warning(
            "repository_missing",
            &manifest,
            "Add a repository URL so users and registries can trace the source.",
        ));
    }
    let mut slugs = std::collections::BTreeMap::new();
    for skill in &plugin.skills {
        let path = format!("{}/SKILL.md", skill.dir)
            .trim_start_matches('/')
            .to_owned();
        if let Some(slug) = emit::skill_slug(skill) {
            if let Some(first) = slugs.insert(slug.clone(), path.clone()) {
                found.push(Diagnostic::error(
                    "skill_name_duplicate",
                    &path,
                    format!("Another skill ({first}) is also named {slug}; packages give each skill its own folder by name."),
                ));
            }
        }
        if detection
            .diagnostics
            .iter()
            .any(|item| item.code == "skill_frontmatter_missing" && item.path == path)
        {
            continue;
        }
        match skill.name.as_deref() {
            None => found.push(Diagnostic::error(
                "skill_name_missing",
                &path,
                "The skill frontmatter has no name.",
            )),
            Some(name) if name.chars().count() > MAX_SKILL_NAME || !is_kebab(name) => {
                found.push(Diagnostic::error(
                    "skill_name_invalid",
                    &path,
                    format!("Skill names are kebab-case and at most {MAX_SKILL_NAME} characters."),
                ));
            }
            Some(_) => {}
        }
        match skill.description.as_deref() {
            None => found.push(Diagnostic::error(
                "skill_description_missing",
                &path,
                "The skill frontmatter has no description; agents choose skills by it.",
            )),
            Some(description) if description.chars().count() > MAX_DESCRIPTION => {
                found.push(Diagnostic::error(
                    "skill_description_too_long",
                    &path,
                    format!("Skill descriptions are at most {MAX_DESCRIPTION} characters."),
                ))
            }
            Some(_) => {}
        }
    }
    for (name, server) in &plugin.mcp_servers {
        let path = format!("mcpServers.{name}");
        if server.command.is_none() && server.url.is_none() {
            found.push(Diagnostic::error(
                "mcp_server_incomplete",
                &path,
                "An MCP server needs a command or a url.",
            ));
        }
        for key in server.env.keys() {
            if !env_has_literal(detection, name, key) {
                continue;
            }
            found.push(if looks_secret(key) {
                Diagnostic::warning(
                    "mcp_env_literal_secret",
                    &format!("{path}.env.{key}"),
                    "This variable holds a literal value. Reference it from the user's environment instead of shipping it.",
                )
            } else {
                Diagnostic::warning(
                    "mcp_env_literal_not_carried",
                    &format!("{path}.env.{key}"),
                    format!("Packages never carry literal values, so they read {key} from the user's environment. Document it, or set the default in the server."),
                )
            });
        }
        for header in &server.literal_headers {
            found.push(Diagnostic::warning(
                "mcp_header_literal",
                &format!("{path}.headers.{header}"),
                "This header holds a literal value, so packages leave it out. Reference an environment variable instead, such as Bearer ${API_TOKEN}.",
            ));
        }
    }
    if let Some(document) = &plugin.registry_server {
        let name = document
            .get("name")
            .and_then(|name| name.as_str())
            .unwrap_or("");
        if !name.contains('/') {
            found.push(Diagnostic::warning(
                "server_name_not_namespaced",
                "server.json",
                "MCP Registry names are namespaced, such as io.github.owner/server.",
            ));
        }
    }
    found.sort_by(|left, right| {
        left.level
            .cmp(&right.level)
            .then(left.path.cmp(&right.path))
            .then(left.code.cmp(right.code))
    });
    found.dedup();
    found
}

pub fn summary(plugin: &Plugin, diagnostics: &[Diagnostic]) -> Summary {
    Summary {
        errors: diagnostics
            .iter()
            .filter(|item| item.level == Level::Error)
            .count(),
        warnings: diagnostics
            .iter()
            .filter(|item| item.level == Level::Warning)
            .count(),
        skills: plugin.skills.len(),
        mcp_servers: plugin.mcp_servers.len(),
        commands: plugin.commands.len(),
        agents: plugin.agents.len(),
    }
}

pub fn runtimes(plugin: &Plugin) -> Vec<RuntimeSupport> {
    Runtime::ALL
        .iter()
        .map(|&runtime| {
            let dropped = emit::dropped(runtime, plugin);
            RuntimeSupport {
                runtime,
                supported: emit::supports(runtime, plugin),
                dropped,
            }
        })
        .collect()
}

fn primary_manifest(detection: &Detection) -> String {
    detection
        .sources
        .iter()
        .find(|source| source.kind.is_plugin_root())
        .map(|source| source.path.clone())
        .unwrap_or_default()
}

pub(crate) fn is_kebab(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub(crate) fn is_semver(value: &str) -> bool {
    let core = value.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

fn looks_secret(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "API_KEY",
        "APIKEY",
        "PRIVATE_KEY",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

/// True when an MCP config sets the variable to a literal rather than a
/// `${VAR}` reference or an empty placeholder. Only the shape is inspected.
fn env_has_literal(detection: &Detection, server: &str, key: &str) -> bool {
    detection
        .raw_env
        .iter()
        .any(|(owner, name, literal)| owner == server && name == key && *literal)
}

#[cfg(test)]
mod tests {
    use super::{is_kebab, is_semver, looks_secret};

    #[test]
    fn kebab_and_semver_rules() {
        assert!(is_kebab("pdf-tools2"));
        assert!(!is_kebab("PDF Tools"));
        assert!(!is_kebab("-x"));
        assert!(!is_kebab("a--b"));
        assert!(is_semver("1.2.3"));
        assert!(is_semver("1.2.3-beta.1"));
        assert!(!is_semver("1.2"));
        assert!(!is_semver("v1.2.3"));
    }

    #[test]
    fn secret_markers() {
        assert!(looks_secret("GITHUB_TOKEN"));
        assert!(looks_secret("openai_api_key"));
        assert!(!looks_secret("LOG_LEVEL"));
    }
}
