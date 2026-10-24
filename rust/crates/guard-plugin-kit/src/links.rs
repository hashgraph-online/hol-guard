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
}

#[derive(Debug, Serialize)]
pub struct HolLinks {
    /// Connects the repository to its HOL listing and verifies ownership.
    pub connect: String,
    pub submit: String,
}

pub fn links(detection: &Detection) -> Links {
    let plugin = &detection.plugin;
    let repository = plugin.github_repository();
    let mut install = Vec::new();
    if let Some(repository) = &repository {
        // Each runtime installs from its own marketplace, which can have a
        // different name from the other.
        let listing = |kind: SourceKind| {
            let marketplace = plugin.marketplace(kind)?.name.clone()?;
            let name = plugin.name.clone().filter(|_| plugin.listed_in(kind))?;
            Some((marketplace, name))
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
