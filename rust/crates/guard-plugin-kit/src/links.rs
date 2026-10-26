//! `hol-guard plugin links`: the install commands users paste into each
//! runtime, and where to list the plugin.

use serde::Serialize;

use crate::detect::Detection;
use crate::emit::{self, Runtime};
use crate::model::{Plugin, SourceKind};

/// Campaign parameters on HOL links, so visits from the Kit are counted
/// without the Kit itself reporting anything.
const ATTRIBUTION: &str = "utm_source=hol-guard&utm_medium=cli&utm_campaign=plugin-kit";

#[derive(Debug, Serialize)]
pub struct Install {
    pub runtime: Runtime,
    pub commands: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Step {
    pub id: &'static str,
    pub done: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct Links {
    pub repository: Option<String>,
    pub install: Vec<Install>,
    pub hol: Option<HolLinks>,
    pub checklist: Vec<Step>,
    /// The README install block, only when asked for (`--block`). Null when
    /// Guard cannot install the plugin: no repository, or no Claude Code or
    /// Codex marketplace entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<Option<String>>,
}

#[derive(Debug, Serialize)]
pub struct HolLinks {
    /// Connects the repository to its HOL listing and verifies ownership.
    pub connect: String,
    pub submit: String,
}

/// Where the README block sends readers to learn what Guard does.
const INSTALL_DOCS: &str = "https://hol.org/guard/docs/plugin-scanner/install-with-hol-guard";

/// `block` asks for the README install block; `slug` is the HOL listing it
/// names (default: the repository).
pub fn links(detection: &Detection, block: bool, slug: Option<&str>) -> Result<Links, String> {
    if slug.is_some_and(|slug| !crate::install::valid_slug(slug)) {
        return Err("plugin_kit_links_slug_invalid".to_owned());
    }
    let mut result = base_links(detection);
    if block {
        let slug = slug
            .map(str::to_owned)
            .or_else(|| result.repository.clone());
        result.block = Some(slug.and_then(|slug| install_block(&slug, &result.install)));
    }
    Ok(result)
}

/// The same block the HOL plugin workspace offers, minus the badge (which
/// needs a claimed listing). HOL detects it by the opening marker.
fn install_block(slug: &str, install: &[Install]) -> Option<String> {
    if !install
        .iter()
        .any(|entry| matches!(entry.runtime, Runtime::ClaudeCode | Runtime::Codex))
    {
        return None;
    }
    let rows: Vec<String> = install
        .iter()
        .map(|entry| {
            let label = match entry.runtime {
                Runtime::ClaudeCode => "Claude Code",
                Runtime::Codex => "Codex",
                Runtime::GeminiCli => "Gemini CLI",
                _ => "Agent skills (Cursor, Gemini CLI, OpenCode and others)",
            };
            // The listing shows Claude Code's slash commands; a README reader
            // may be in a terminal, so use the `claude plugin` CLI there.
            let commands: Vec<String> = entry
                .commands
                .iter()
                .map(|command| match command.strip_prefix('/') {
                    Some(rest) if entry.runtime == Runtime::ClaudeCode => {
                        format!("`claude {rest}`")
                    }
                    _ => format!("`{command}`"),
                })
                .collect();
            format!("| {label} | {} |", commands.join("<br>"))
        })
        .collect();
    let listing = format!(
        "https://hol.org/registry/plugins/{}",
        slug.replace('/', "%2F")
    );
    Some(
        [
            format!("<!-- hol-install-block:v1 slug={slug} -->"),
            format!("Install with [HOL Guard]({INSTALL_DOCS}), which checks the [HOL listing]({listing}) and asks before each runtime:"),
            String::new(),
            "```sh".to_owned(),
            format!("hol-guard plugin install {slug} --apply"),
            "```".to_owned(),
            String::new(),
            "<details>".to_owned(),
            "<summary>Install with each runtime's own CLI</summary>".to_owned(),
            String::new(),
            "| Runtime | Commands |".to_owned(),
            "| --- | --- |".to_owned(),
        ]
        .into_iter()
        .chain(rows)
        .chain(
            [String::new(), "</details>".to_owned(), "<!-- /hol-install-block -->".to_owned()],
        )
        .collect::<Vec<_>>()
        .join("\n"),
    )
}

fn base_links(detection: &Detection) -> Links {
    let plugin = &detection.plugin;
    let repository = plugin.github_repository();
    let mut install = Vec::new();
    if let Some(repository) = &repository {
        // Each runtime installs from its own marketplace, which can have a
        // different name from the other. Names that `plugin install` would
        // refuse get no commands, so none can break out of a README cell or a
        // pasted command line.
        let listing = |kind: SourceKind| {
            let marketplace = plugin.marketplace(kind)?.name.clone()?;
            let name = plugin.name.clone().filter(|_| plugin.listed_in(kind))?;
            (crate::install::valid_identifier(&marketplace)
                && crate::install::valid_identifier(&name))
            .then_some((marketplace, name))
        };
        if let Some((marketplace, name)) = listing(SourceKind::ClaudeMarketplace) {
            install.push(Install {
                runtime: Runtime::ClaudeCode,
                commands: vec![
                    format!("/plugin marketplace add {repository}"),
                    format!("/plugin install {name}@{marketplace}"),
                ],
                verify: Some("claude plugin list".to_owned()),
            });
        }
        if let Some((marketplace, name)) = listing(SourceKind::CodexMarketplace) {
            install.push(Install {
                runtime: Runtime::Codex,
                commands: vec![
                    format!("codex plugin marketplace add {repository}"),
                    format!("codex plugin add {name}@{marketplace}"),
                ],
                verify: None,
            });
        }
        if detection.sources.iter().any(|source| {
            source.kind == SourceKind::GeminiExtension && source.path == "gemini-extension.json"
        }) {
            install.push(Install {
                runtime: Runtime::GeminiCli,
                commands: vec![format!(
                    "gemini extensions install https://github.com/{repository}"
                )],
                verify: Some("gemini extensions list".to_owned()),
            });
        }
        if plugin
            .skills
            .iter()
            .any(|skill| emit::skill_slug(skill).is_some())
        {
            install.push(Install {
                runtime: Runtime::AgentSkills,
                commands: vec![format!("npx skills add {repository}")],
                verify: Some("npx skills list".to_owned()),
            });
        }
    }
    Links {
        hol: repository.as_ref().map(|repository| HolLinks {
            connect: format!("https://hol.org/plugins/connect?repo={repository}&{ATTRIBUTION}"),
            submit: format!("https://hol.org/registry/plugins/submit?intent=launch&{ATTRIBUTION}"),
        }),
        checklist: checklist(detection, plugin, repository.is_some()),
        repository,
        install,
        block: None,
    }
}

fn checklist(detection: &Detection, plugin: &Plugin, on_github: bool) -> Vec<Step> {
    let has = |kind: SourceKind| detection.sources.iter().any(|source| source.kind == kind);
    vec![
        Step {
            id: "github_repository",
            done: on_github,
            message: "Publish the source on GitHub and set repository in the manifest.".to_owned(),
        },
        Step {
            id: "claude_marketplace",
            done: plugin.listed_in(SourceKind::ClaudeMarketplace),
            message: "List the plugin in .claude-plugin/marketplace.json so Claude Code can install it from the repository."
                .to_owned(),
        },
        Step {
            id: "codex_marketplace",
            done: plugin.listed_in(SourceKind::CodexMarketplace),
            message: "List the plugin in .agents/plugins/marketplace.json so Codex can install it from the repository."
                .to_owned(),
        },
        // A local server.json is not a publication; the Registry needs an
        // authenticated publish the Kit cannot see, so this stays open.
        Step {
            id: "mcp_registry",
            done: false,
            message: if has(SourceKind::McpServer) {
                "Publish server.json to the MCP Registry with mcp-publisher (https://github.com/modelcontextprotocol/registry)."
            } else {
                "Publish MCP servers to the MCP Registry with server.json (https://github.com/modelcontextprotocol/registry)."
            }
            .to_owned(),
        },
        Step {
            id: "hol_listing",
            done: false,
            message: "Connect the repository on HOL to verify ownership and claim the listing.".to_owned(),
        },
    ]
}
