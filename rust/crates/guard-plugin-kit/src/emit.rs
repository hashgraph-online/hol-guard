//! Runtime emitters: one plugin source, packaged for every runtime that can
//! load it.
//!
//! Emitters are pure. They return the files to write as an ordered plan, so
//! the output is identical for identical input and golden tests can compare
//! it without touching disk. MCP environment variables and header values
//! are emitted as references in each runtime's own syntax; literal values are
//! never carried.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

mod servers;

use crate::agent_plugins;
use crate::check::is_kebab;
use crate::config::Excludes;
use crate::model::Plugin;
use crate::walk;

use servers::{
    agent_plugins_bundled, agent_plugins_servers, gemini_settings, registry_document, servers,
    servers_left_out, Syntax,
};

/// The largest single file a package copies.
const MAX_COPY_BYTES: u64 = 5 * 1024 * 1024;
/// The most bytes one package may copy across all runtimes.
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    ClaudeCode,
    Codex,
    GeminiCli,
    Cursor,
    Vscode,
    Opencode,
    McpRegistry,
    AgentSkills,
    AgentPlugins,
}

impl Runtime {
    pub const ALL: [Runtime; 9] = [
        Runtime::ClaudeCode,
        Runtime::Codex,
        Runtime::GeminiCli,
        Runtime::Cursor,
        Runtime::Vscode,
        Runtime::Opencode,
        Runtime::McpRegistry,
        Runtime::AgentSkills,
        Runtime::AgentPlugins,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Runtime::ClaudeCode => "claude-code",
            Runtime::Codex => "codex",
            Runtime::GeminiCli => "gemini-cli",
            Runtime::Cursor => "cursor",
            Runtime::Vscode => "vscode",
            Runtime::Opencode => "opencode",
            Runtime::McpRegistry => "mcp-registry",
            Runtime::AgentSkills => "agent-skills",
            Runtime::AgentPlugins => "agent-plugins",
        }
    }

    pub fn parse(value: &str) -> Option<Runtime> {
        Runtime::ALL
            .into_iter()
            .find(|runtime| runtime.id() == value)
    }
}

/// One file of a package, relative to the output directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub path: String,
    pub content: Vec<u8>,
}

pub fn supports(runtime: Runtime, plugin: &Plugin) -> bool {
    let named = plugin.name.as_deref().is_some_and(is_kebab);
    match runtime {
        Runtime::ClaudeCode | Runtime::Codex => {
            named
                && (!plugin.skills.is_empty()
                    || !plugin.mcp_servers.is_empty()
                    || has_claude_only(plugin))
        }
        Runtime::GeminiCli => {
            named && (!plugin.mcp_servers.is_empty() || plugin.context_file.is_some())
        }
        Runtime::Cursor | Runtime::Vscode | Runtime::Opencode => !plugin.mcp_servers.is_empty(),
        Runtime::McpRegistry => registry_document(plugin).is_some(),
        Runtime::AgentSkills => plugin
            .skills
            .iter()
            .any(|skill| skill_slug(skill).is_some()),
        Runtime::AgentPlugins => {
            plugin
                .name
                .as_deref()
                .is_some_and(agent_plugins::valid_plugin_name)
                && (plugin.skills.iter().any(agent_plugins_skill)
                    || !agent_plugins_servers(plugin).0.is_empty())
        }
    }
}

/// A skill an Agent Plugins package carries: its folder must match its name.
fn agent_plugins_skill(skill: &crate::model::Skill) -> bool {
    agent_plugins::portable_skill(skill.name.as_deref(), skill.description.as_deref())
}

fn has_claude_only(plugin: &Plugin) -> bool {
    !plugin.commands.is_empty() || !plugin.agents.is_empty() || plugin.hooks.is_some()
}

/// The components a runtime has no place for, among those the plugin has.
pub fn dropped(runtime: Runtime, plugin: &Plugin) -> Vec<&'static str> {
    let present = [
        ("skills", !plugin.skills.is_empty()),
        ("mcp_servers", !plugin.mcp_servers.is_empty()),
        ("commands", !plugin.commands.is_empty()),
        ("agents", !plugin.agents.is_empty()),
        ("hooks", plugin.hooks.is_some()),
        ("context_file", plugin.context_file.is_some()),
    ];
    let kept: &[&str] = match runtime {
        Runtime::ClaudeCode => &["skills", "mcp_servers", "commands", "agents", "hooks"],
        Runtime::Codex => &["skills", "mcp_servers"],
        Runtime::GeminiCli => &["mcp_servers", "context_file"],
        Runtime::Cursor | Runtime::Vscode | Runtime::Opencode | Runtime::McpRegistry => {
            &["mcp_servers"]
        }
        Runtime::AgentSkills => &["skills"],
        Runtime::AgentPlugins => &["skills", "mcp_servers"],
    };
    let mut dropped: Vec<&'static str> = present
        .into_iter()
        .filter(|(name, has)| *has && !kept.contains(name))
        .map(|(name, _)| name)
        .collect();
    let syntax = match runtime {
        Runtime::ClaudeCode | Runtime::Codex => Some(Syntax::Claude),
        Runtime::GeminiCli => Some(Syntax::Gemini),
        Runtime::Cursor => Some(Syntax::Cursor),
        Runtime::Vscode => Some(Syntax::Vscode),
        Runtime::Opencode => Some(Syntax::Opencode),
        Runtime::McpRegistry | Runtime::AgentSkills | Runtime::AgentPlugins => None,
    };
    if syntax.is_some_and(|syntax| servers_left_out(plugin, syntax)) {
        dropped.push("mcp_servers_not_portable");
    }
    if runtime == Runtime::AgentPlugins {
        // Agent Plugins has no user-variable references, so environment
        // variables and headers stay behind; so do skills whose folder
        // cannot match their name and servers with no portable command.
        let (_, loss) = agent_plugins_servers(plugin);
        for (name, lost) in [
            (
                "skills_not_portable",
                plugin
                    .skills
                    .iter()
                    .any(|skill| !agent_plugins_skill(skill)),
            ),
            ("mcp_servers_not_portable", loss.servers),
            ("mcp_env", loss.env),
            ("mcp_headers", loss.headers),
        ] {
            if lost {
                dropped.push(name);
            }
        }
    }
    dropped
}

/// The files to write for each runtime, under `<runtime>/`, in path order.
/// Every source file copied into the package is added to `sources`, relative
/// to `root`, so the provenance digest covers it.
pub(crate) fn plan(
    root: &Path,
    plugin: &Plugin,
    excludes: &Excludes,
    runtimes: &[Runtime],
    sources: &mut BTreeSet<PathBuf>,
) -> Result<Vec<Output>, String> {
    let mut outputs = BTreeMap::new();
    let mut budget = Budget::default();
    for &runtime in runtimes {
        if !supports(runtime, plugin) {
            continue;
        }
        let prefix = runtime.id();
        let mut put_json = |path: &str, value: Value| {
            outputs.insert(format!("{prefix}/{path}"), json_bytes(&value));
        };
        match runtime {
            Runtime::ClaudeCode => {
                put_json(".claude-plugin/plugin.json", manifest(plugin, None));
                if !plugin.mcp_servers.is_empty() {
                    put_json(
                        ".mcp.json",
                        json!({"mcpServers": servers(plugin, Syntax::Claude)}),
                    );
                }
            }
            Runtime::Codex => {
                let mut extra = Map::new();
                if plugin
                    .skills
                    .iter()
                    .any(|skill| skill_slug(skill).is_some())
                {
                    extra.insert("skills".into(), json!("./skills/"));
                }
                if !plugin.mcp_servers.is_empty() {
                    extra.insert("mcpServers".into(), json!("./.mcp.json"));
                    put_json(
                        ".mcp.json",
                        json!({"mcpServers": servers(plugin, Syntax::Claude)}),
                    );
                }
                // Codex requires a version; a source without one gets the
                // same placeholder as Gemini CLI, and check warns about it.
                if plugin.version.is_none() {
                    extra.insert("version".into(), json!("0.1.0"));
                }
                put_json(".codex-plugin/plugin.json", manifest(plugin, Some(extra)));
            }
            Runtime::GeminiCli => {
                let mut extension = Map::new();
                extension.insert("name".into(), json!(plugin.name));
                extension.insert(
                    "version".into(),
                    json!(plugin.version.as_deref().unwrap_or("0.1.0")),
                );
                if let Some(description) = &plugin.description {
                    extension.insert("description".into(), json!(description));
                }
                if !plugin.mcp_servers.is_empty() {
                    extension.insert("mcpServers".into(), servers(plugin, Syntax::Gemini));
                }
                if plugin.context_file.is_some() {
                    extension.insert("contextFileName".into(), json!("GEMINI.md"));
                }
                let settings = gemini_settings(plugin);
                if !settings.is_empty() {
                    extension.insert("settings".into(), Value::Array(settings));
                }
                put_json("gemini-extension.json", Value::Object(extension));
            }
            Runtime::Cursor => put_json(
                ".cursor/mcp.json",
                json!({"mcpServers": servers(plugin, Syntax::Cursor)}),
            ),
            Runtime::Vscode => put_json(
                ".vscode/mcp.json",
                json!({"servers": servers(plugin, Syntax::Vscode)}),
            ),
            Runtime::Opencode => put_json(
                "opencode.json",
                json!({"$schema": "https://opencode.ai/config.json", "mcp": servers(plugin, Syntax::Opencode)}),
            ),
            Runtime::McpRegistry => {
                if let Some(document) = registry_document(plugin) {
                    put_json("server.json", document);
                }
            }
            Runtime::AgentSkills => {}
            Runtime::AgentPlugins => {
                let mut extra = Map::new();
                extra.insert("$schema".into(), json!(agent_plugins::PLUGIN_SCHEMA));
                put_json("plugin.json", manifest(plugin, Some(extra)));
                let (entries, _) = agent_plugins_servers(plugin);
                if !entries.is_empty() {
                    put_json(
                        "mcp.json",
                        json!({"$schema": agent_plugins::MCP_SCHEMA, "mcpServers": entries}),
                    );
                }
            }
        }
        let copies = copies(runtime, root, plugin, excludes, &mut budget, sources)?;
        for (path, content) in copies {
            let path = format!("{prefix}/{path}");
            if outputs.contains_key(&path) {
                return Err("plugin_kit_package_path_conflict".to_owned());
            }
            outputs.insert(path, content);
        }
    }
    Ok(outputs
        .into_iter()
        .map(|(path, content)| Output { path, content })
        .collect())
}

#[derive(Default)]
struct Budget {
    files: usize,
    bytes: u64,
}

/// Source files a runtime carries unchanged: skill folders, Claude Code
/// commands, agents and hooks, and the Gemini context file.
fn copies(
    runtime: Runtime,
    root: &Path,
    plugin: &Plugin,
    excludes: &Excludes,
    budget: &mut Budget,
    sources: &mut BTreeSet<PathBuf>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut found = Vec::new();
    let with_skills = matches!(
        runtime,
        Runtime::ClaudeCode | Runtime::Codex | Runtime::AgentSkills | Runtime::AgentPlugins
    );
    if with_skills {
        for skill in &plugin.skills {
            let Some(slug) = skill_slug(skill) else {
                continue;
            };
            if runtime == Runtime::AgentPlugins && !agent_plugins_skill(skill) {
                continue;
            }
            let dir = root.join(&skill.dir);
            if skill.dir.is_empty() {
                // A SKILL.md at the repository root travels alone.
                found.push((dir.join("SKILL.md"), format!("skills/{slug}/SKILL.md")));
                continue;
            }
            for file in walk::files(&dir, &skill.dir, excludes)? {
                found.push((
                    dir.join(&file),
                    format!("skills/{slug}/{}", walk::display(&file)),
                ));
            }
        }
    }
    if runtime == Runtime::ClaudeCode {
        // Commands and agents keep their subfolders, which Claude Code uses
        // as namespaces.
        let base = if plugin.base.is_empty() {
            String::new()
        } else {
            format!("{}/", plugin.base)
        };
        for path in plugin.commands.iter().chain(&plugin.agents) {
            let target = path.strip_prefix(&base).unwrap_or(path);
            found.push((root.join(path), target.to_owned()));
        }
        if let Some(hooks) = &plugin.hooks {
            // Hook commands usually call scripts beside them, so the whole
            // hooks folder travels with hooks.json.
            let folder = Path::new(hooks)
                .parent()
                .map(walk::display)
                .unwrap_or_default();
            let dir = root.join(&folder);
            for file in walk::files(&dir, &folder, excludes)? {
                found.push((dir.join(&file), format!("hooks/{}", walk::display(&file))));
            }
        }
    }
    // A server's files must all ship: the server is already in mcp.json.
    let mut required = BTreeSet::new();
    if runtime == Runtime::AgentPlugins {
        for (source, target) in agent_plugins_bundled(root, plugin, excludes)? {
            required.insert(target.clone());
            found.push((source, target));
        }
    }
    if runtime == Runtime::GeminiCli {
        // Detection keeps only a context file the walk found inside the
        // extension folder.
        if let Some(context) = &plugin.context_file {
            found.push((root.join(context), "GEMINI.md".to_owned()));
        }
    }
    let mut copied = Vec::new();
    let mut targets: BTreeMap<String, PathBuf> = BTreeMap::new();
    for (source, target) in found {
        // A file reached twice, as a skill file and a server file, is
        // packaged once. Two different files at one path cannot both ship.
        match targets.get(&target) {
            Some(existing) if *existing == source => continue,
            Some(_) => return Err("plugin_kit_package_path_conflict".to_owned()),
            None => {
                targets.insert(target.clone(), source.clone());
            }
        }
        let Some(content) = walk::read_bytes(&source, MAX_COPY_BYTES) else {
            if required.contains(&target) {
                return Err("plugin_kit_package_too_large".to_owned());
            }
            continue;
        };
        budget.files += 1;
        budget.bytes += content.len() as u64;
        if budget.files > MAX_FILES || budget.bytes > MAX_TOTAL_BYTES {
            return Err("plugin_kit_package_too_large".to_owned());
        }
        if let Ok(relative) = source.strip_prefix(root) {
            sources.insert(relative.to_path_buf());
        }
        copied.push((target, content));
    }
    Ok(copied)
}

/// The folder name a skill is packaged under: its kebab-case name, else its
/// source folder name when that is kebab-case.
pub(crate) fn skill_slug(skill: &crate::model::Skill) -> Option<String> {
    if let Some(name) = skill
        .name
        .as_deref()
        .filter(|name| is_kebab(name) && name.len() <= 64)
    {
        return Some(name.to_owned());
    }
    let folder = Path::new(&skill.dir).file_name()?.to_str()?;
    is_kebab(folder).then(|| folder.to_owned())
}

fn manifest(plugin: &Plugin, extra: Option<Map<String, Value>>) -> Value {
    let mut manifest = Map::new();
    manifest.insert("name".into(), json!(plugin.name));
    for (key, value) in [
        ("version", &plugin.version),
        ("description", &plugin.description),
        ("homepage", &plugin.homepage),
        ("repository", &plugin.repository),
        ("license", &plugin.license),
    ] {
        if let Some(value) = value {
            manifest.insert(key.into(), json!(value));
        }
    }
    if let Some(author) = &plugin.author {
        manifest.insert("author".into(), json!({"name": author}));
    }
    if !plugin.keywords.is_empty() {
        manifest.insert("keywords".into(), json!(plugin.keywords));
    }
    manifest.extend(extra.unwrap_or_default());
    Value::Object(manifest)
}

pub(crate) fn json_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// A digest of the source files a package was built from: each relative path
/// and the SHA-256 of its bytes, in path order.
pub fn source_digest(root: &Path, inputs: &[std::path::PathBuf]) -> String {
    let mut hasher = Sha256::new();
    for input in inputs {
        let content = walk::read_bytes(&root.join(input), MAX_COPY_BYTES).unwrap_or_default();
        hasher.update(walk::display(input).as_bytes());
        hasher.update([0]);
        hasher.update(hex::encode(Sha256::digest(&content)).as_bytes());
        hasher.update([b'\n']);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::Runtime;

    #[test]
    fn runtime_ids_round_trip() {
        for runtime in Runtime::ALL {
            assert_eq!(Runtime::parse(runtime.id()), Some(runtime));
        }
        assert_eq!(Runtime::parse("windsurf"), None);
    }
}
