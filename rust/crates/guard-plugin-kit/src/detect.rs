//! Source detection: which plugin formats a repository already ships, and the
//! runtime-neutral [`Plugin`] they describe.
//!
//! The markers match the scanner's ecosystem adapters
//! (`.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`,
//! `gemini-extension.json`, marketplace manifests, `SKILL.md`) and add the MCP
//! Registry `server.json`.

mod servers;
pub(crate) mod skill;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::config::Excludes;
use crate::model::{Diagnostic, Marketplace, Plugin, Source, SourceKind};
use crate::walk;

pub struct Detection {
    pub sources: Vec<Source>,
    pub plugin: Plugin,
    pub diagnostics: Vec<Diagnostic>,
    /// Every file the detection read, for the provenance digest.
    pub inputs: Vec<PathBuf>,
    /// `(server, variable, is_literal)` for each MCP env entry. Values are
    /// never kept; only whether one is a literal rather than a reference.
    pub raw_env: Vec<(String, String, bool)>,
    /// Paths `[plugin_kit] exclude_paths` leaves out, which packaging honours
    /// when it copies whole skill and hooks folders.
    pub(crate) excludes: Excludes,
}

pub fn detect(root: &Path) -> Result<Detection, String> {
    let excludes = Excludes::load(root)?;
    let files = walk::files(root, "", &excludes)?;
    let mut sources = Vec::new();
    for file in &files {
        if let Some(kind) = classify(file) {
            sources.push(Source {
                kind,
                path: walk::display(file),
            });
        }
    }
    sources.sort_by(|left, right| left.kind.cmp(&right.kind).then(left.path.cmp(&right.path)));

    let mut diagnostics = Vec::new();
    let mut documents: BTreeMap<String, Value> = BTreeMap::new();
    for source in &sources {
        if source.kind == SourceKind::AgentSkill {
            continue;
        }
        match walk::read_text(&root.join(&source.path)).map(|text| serde_json::from_str(&text)) {
            Some(Ok(value @ Value::Object(_))) => {
                documents.insert(source.path.clone(), value);
            }
            // Other tools use plugin.json and mcp.json too; only files that
            // name an Agent Plugins schema are sources.
            _ if agent_plugins_candidate(source.kind) => {}
            _ => diagnostics.push(Diagnostic::error(
                "manifest_invalid_json",
                &source.path,
                "The manifest is not a JSON object.",
            )),
        }
    }

    sources.retain(|source| {
        !agent_plugins_candidate(source.kind)
            || documents
                .get(&source.path)
                .and_then(|document| document.get("$schema"))
                .and_then(Value::as_str)
                .is_some_and(|schema| schema.starts_with(AGENT_PLUGINS_SCHEMAS))
    });
    let base = plugin_base(&sources);
    let mut plugin = Plugin {
        base: base.clone(),
        ..Plugin::default()
    };
    for source in sources.iter().filter(|source| source.kind.is_plugin_root()) {
        if source_base(source) != base {
            continue;
        }
        if let Some(document) = documents.get(&source.path) {
            merge_metadata(&mut plugin, source.kind, document);
        }
    }
    let mut inputs: Vec<PathBuf> = sources
        .iter()
        .map(|source| PathBuf::from(&source.path))
        .collect();
    let mut raw_env = Vec::new();

    for source in &sources {
        let Some(document) = documents.get(&source.path) else {
            if source.kind == SourceKind::AgentSkill {
                plugin
                    .skills
                    .push(skill::read_skill(root, source, &mut diagnostics));
            }
            continue;
        };
        match source.kind {
            SourceKind::McpConfig
            | SourceKind::AgentPluginMcp
            | SourceKind::ClaudePlugin
            | SourceKind::GeminiExtension
                if source_base(source) == base =>
            {
                servers::collect_servers(
                    &mut plugin.mcp_servers,
                    &mut raw_env,
                    document.get("mcpServers"),
                    source.kind == SourceKind::GeminiExtension,
                    source.kind == SourceKind::AgentPluginMcp,
                );
            }
            SourceKind::McpServer if source_base(source) == base => {
                servers::registry_server(&mut plugin, document);
            }
            SourceKind::ClaudeMarketplace | SourceKind::CodexMarketplace => {
                if plugin.marketplace(source.kind).is_none() {
                    plugin
                        .marketplaces
                        .push(marketplace(source, document, &mut diagnostics));
                }
            }
            _ => {}
        }
    }
    plugin
        .skills
        .sort_by(|left, right| left.dir.cmp(&right.dir));
    servers::resolve_bundles(&root.join(&base), &base, &files, &mut plugin.mcp_servers);

    let join = |name: &str| {
        if base.is_empty() {
            name.to_owned()
        } else {
            format!("{base}/{name}")
        }
    };
    let known: BTreeSet<String> = files.iter().map(|file| walk::display(file)).collect();
    if let Some(context) = plugin.context_file.take() {
        match context_path(&base, &context).filter(|path| known.contains(path)) {
            Some(path) => {
                inputs.push(PathBuf::from(&path));
                plugin.context_file = Some(path);
            }
            None => diagnostics.push(Diagnostic::warning(
                "context_file_invalid",
                &join("gemini-extension.json"),
                "contextFileName must name a file inside the extension folder.",
            )),
        }
    }
    for file in &files {
        let path = walk::display(file);
        // Claude Code namespaces commands and agents by subfolder.
        if path.starts_with(&join("commands/")) {
            if path.ends_with(".md") {
                plugin.commands.push(path.clone());
                inputs.push(file.clone());
            }
        } else if path.starts_with(&join("agents/")) {
            if path.ends_with(".md") {
                plugin.agents.push(path.clone());
                inputs.push(file.clone());
            }
        } else if path == join("hooks/hooks.json") {
            plugin.hooks = Some(path.clone());
            inputs.push(file.clone());
        } else if path == join("GEMINI.md") && plugin.context_file.is_none() {
            plugin.context_file = Some(path.clone());
            inputs.push(file.clone());
        }
    }
    if plugin.repository.is_none() {
        plugin.repository =
            package_repository(root, &base, &known, &mut inputs).or_else(|| git_origin(root));
    }
    if plugin.name.is_none() && plugin.base.is_empty() && !plugin.skills.is_empty() {
        plugin.name = root
            .file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase());
    }
    inputs.sort();
    inputs.dedup();
    Ok(Detection {
        sources,
        plugin,
        diagnostics,
        inputs,
        raw_env,
        excludes,
    })
}

fn classify(file: &Path) -> Option<SourceKind> {
    let name = file.file_name()?.to_str()?;
    let parent = file
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let grandparent = file
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("");
    match (name, parent) {
        ("plugin.json", ".claude-plugin") => Some(SourceKind::ClaudePlugin),
        ("marketplace.json", ".claude-plugin") => Some(SourceKind::ClaudeMarketplace),
        ("plugin.json", ".codex-plugin") => Some(SourceKind::CodexPlugin),
        ("plugin.json", _) => Some(SourceKind::AgentPlugin),
        ("mcp.json", _) => Some(SourceKind::AgentPluginMcp),
        ("marketplace.json", "plugins") if grandparent == ".agents" => {
            Some(SourceKind::CodexMarketplace)
        }
        ("gemini-extension.json", _) => Some(SourceKind::GeminiExtension),
        ("server.json", _) => Some(SourceKind::McpServer),
        (".mcp.json", _) => Some(SourceKind::McpConfig),
        ("SKILL.md", _) => Some(SourceKind::AgentSkill),
        _ => None,
    }
}

const AGENT_PLUGINS_SCHEMAS: &str = "https://agent-plugins.org/schemas/";

/// Kinds classified by file name alone, kept only when the file names an
/// Agent Plugins schema.
fn agent_plugins_candidate(kind: SourceKind) -> bool {
    matches!(kind, SourceKind::AgentPlugin | SourceKind::AgentPluginMcp)
}

/// The directory a source's manifest describes ("" for the repository root).
fn source_base(source: &Source) -> String {
    let path = Path::new(&source.path);
    let parent = path.parent().unwrap_or(Path::new(""));
    let base = match source.kind {
        SourceKind::ClaudePlugin | SourceKind::CodexPlugin | SourceKind::ClaudeMarketplace => {
            parent.parent().unwrap_or(Path::new(""))
        }
        SourceKind::CodexMarketplace => parent
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("")),
        _ => parent,
    };
    walk::display(base)
}

/// The shallowest plugin root; a tie goes to the earlier [`SourceKind`].
fn plugin_base(sources: &[Source]) -> String {
    sources
        .iter()
        .filter(|source| source.kind.is_plugin_root())
        .map(source_base)
        .min_by_key(|base| {
            (
                if base.is_empty() {
                    0
                } else {
                    base.split('/').count()
                },
                base.clone(),
            )
        })
        .unwrap_or_default()
}

/// A Gemini `contextFileName`, resolved under the extension folder. Only a
/// relative path of plain components is accepted, so a manifest cannot point
/// the package at a file outside the folder.
fn context_path(base: &str, context: &str) -> Option<String> {
    let relative = Path::new(context);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(walk::display(&Path::new(base).join(relative)))
}

pub(super) fn text(document: &Value, key: &str) -> Option<String> {
    document
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn merge_metadata(plugin: &mut Plugin, kind: SourceKind, document: &Value) {
    let fill = |slot: &mut Option<String>, value: Option<String>| {
        if slot.is_none() {
            *slot = value;
        }
    };
    let name = if kind == SourceKind::McpServer {
        // MCP Registry names are reverse-DNS (`io.github.owner/server`); the
        // plugin name is the last segment.
        text(document, "name").map(|name| name.rsplit('/').next().unwrap_or(&name).to_owned())
    } else {
        text(document, "name")
    };
    fill(&mut plugin.name, name);
    fill(&mut plugin.version, text(document, "version"));
    fill(&mut plugin.description, text(document, "description"));
    fill(
        &mut plugin.homepage,
        text(document, "homepage").or_else(|| text(document, "websiteUrl")),
    );
    fill(&mut plugin.license, text(document, "license"));
    let author = match document.get("author") {
        Some(Value::String(name)) => Some(name.trim().to_owned()).filter(|name| !name.is_empty()),
        Some(Value::Object(author)) => author
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned),
        _ => None,
    };
    fill(&mut plugin.author, author);
    let repository = match document.get("repository") {
        Some(Value::String(url)) => Some(url.trim().to_owned()),
        Some(Value::Object(repository)) => repository
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    fill(
        &mut plugin.repository,
        repository.filter(|url| !url.is_empty()),
    );
    if plugin.keywords.is_empty() {
        if let Some(Value::Array(keywords)) = document.get("keywords") {
            plugin.keywords = keywords
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .take(32)
                .collect();
        }
    }
    if kind == SourceKind::GeminiExtension && plugin.context_file.is_none() {
        plugin.context_file = text(document, "contextFileName");
    }
}

fn marketplace(
    source: &Source,
    document: &Value,
    diagnostics: &mut Vec<Diagnostic>,
) -> Marketplace {
    let mut plugins = Vec::new();
    if let Some(Value::Array(entries)) = document.get("plugins") {
        for (index, entry) in entries.iter().enumerate() {
            match text(entry, "name") {
                Some(name) if entry.get("source").is_some() => plugins.push(name),
                _ => diagnostics.push(Diagnostic::error(
                    "marketplace_entry_incomplete",
                    &source.path,
                    format!("plugins[{index}] needs a name and a source."),
                )),
            }
        }
    }
    Marketplace {
        kind: source.kind,
        name: text(document, "name"),
        path: source.path.clone(),
        plugins,
    }
}

/// The `repository` of a `package.json` beside the plugin root, which npm
/// packaged MCP servers and extensions usually set.
fn package_repository(
    root: &Path,
    base: &str,
    known: &BTreeSet<String>,
    inputs: &mut Vec<PathBuf>,
) -> Option<String> {
    let path = Path::new(base).join("package.json");
    // An excluded or unwalked package.json is not part of the plugin.
    if !known.contains(&walk::display(&path)) {
        return None;
    }
    let document: Value = serde_json::from_str(&walk::read_text(&root.join(&path))?).ok()?;
    let url = match document.get("repository")? {
        Value::String(url) => url.clone(),
        Value::Object(repository) => repository.get("url")?.as_str()?.to_owned(),
        _ => return None,
    };
    let full_name = crate::model::github_full_name(&url)?;
    inputs.push(path);
    Some(format!("https://github.com/{full_name}"))
}

/// The `origin` remote from `.git/config`, read as text; Git is never run.
fn git_origin(root: &Path) -> Option<String> {
    let config = walk::read_text(&root.join(".git").join("config"))?;
    let mut in_origin = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_origin = line == "[remote \"origin\"]";
        } else if in_origin {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim() == "url" {
                    return crate::model::github_full_name(value.trim())
                        .map(|full_name| format!("https://github.com/{full_name}"));
                }
            }
        }
    }
    None
}
