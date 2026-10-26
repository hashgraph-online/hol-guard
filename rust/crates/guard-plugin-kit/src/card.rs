//! `hol-guard plugin card`: a draft `.well-known` card that describes the
//! plugin to directories and runtimes that read one.
//!
//! The MCP roadmap names server cards at `.well-known` URLs, but no schema is
//! published yet, so the card carries its own draft schema id and changes it
//! when the shape changes. Everything in it comes from the repository's own
//! manifests: what the plugin declares, not what Guard has verified. The HOL
//! listing serves the same card with the verified owner and release
//! attestations added, which a repository cannot claim for itself.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::check;
use crate::detect::Detection;
use crate::emit::Runtime;
use crate::model::ROOT_PLACEHOLDERS;

pub const SCHEMA: &str = "hol.plugin-card.v0-draft";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub schema: &'static str,
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub license: Option<String>,
    pub homepage: Option<String>,
    pub identity: Identity,
    pub capabilities: Capabilities,
    pub permissions: Permissions,
    /// Runtimes the Kit can package the plugin for.
    pub runtimes: Vec<Runtime>,
    pub links: CardLinks,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    /// `owner/name` on GitHub, from the manifest.
    pub repository: Option<String>,
    /// Always false here: only HOL's served card can state a verified owner.
    pub verified: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub skills: Vec<String>,
    pub mcp_servers: Vec<CardServer>,
    pub commands: usize,
    pub agents: usize,
    pub hooks: bool,
}

#[derive(Debug, Serialize)]
pub struct CardServer {
    pub name: String,
    /// `stdio`, `http` or `sse`.
    pub transport: String,
}

/// What the manifests declare the plugin can do on a user's machine.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Permissions {
    /// Programs a local (stdio) MCP server starts, by name only.
    pub starts_programs: Vec<String>,
    /// Hosts remote MCP servers connect to; templated hosts are left out.
    pub network_hosts: Vec<String>,
    /// Environment variables the plugin reads, by name. Values never appear.
    pub environment: Vec<String>,
    /// Whether the plugin registers hooks, which run commands on events.
    pub runs_hooks: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardLinks {
    pub repository: Option<String>,
    /// The HOL listing, named by `--slug` or the repository.
    pub listing: Option<String>,
    /// HOL's served card, which adds the verified owner and attestations.
    pub hol_card: Option<String>,
}

pub fn card(detection: &Detection, slug: Option<&str>) -> Result<Card, String> {
    if slug.is_some_and(|slug| !listing_slug(slug)) {
        return Err("plugin_kit_card_slug_invalid".to_owned());
    }
    let plugin = &detection.plugin;
    let repository = plugin.github_repository();
    let mut skills: Vec<String> = plugin
        .skills
        .iter()
        .filter_map(|skill| {
            skill
                .name
                .clone()
                .or_else(|| crate::emit::skill_slug(skill))
        })
        .collect();
    skills.sort();
    skills.dedup();
    let mut programs = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    let mut environment = BTreeSet::new();
    let mut servers = Vec::new();
    for (name, server) in &plugin.mcp_servers {
        let transport = match (&server.command, &server.url) {
            (Some(_), _) => "stdio".to_owned(),
            (None, Some(_)) => server
                .transport
                .clone()
                .unwrap_or_else(|| "http".to_owned()),
            (None, None) => continue,
        };
        if let Some(program) = server.command.as_deref().and_then(program_name) {
            programs.insert(program);
        }
        if let Some(host) = server.url.as_deref().and_then(host) {
            hosts.insert(host);
        }
        environment.extend(server.referenced_variables());
        // Runtimes expand `${NAME}` in args and remote URLs too; the
        // plugin-root placeholders are paths, not user variables.
        for value in server.args.iter().chain(server.url.as_ref()) {
            environment.extend(
                crate::reference::template_variables(value)
                    .into_iter()
                    .filter(|name| {
                        !ROOT_PLACEHOLDERS
                            .iter()
                            .any(|placeholder| placeholder[2..placeholder.len() - 1] == **name)
                    }),
            );
        }
        servers.push(CardServer {
            name: name.clone(),
            transport,
        });
    }
    let slug = slug.map(str::to_owned).or_else(|| repository.clone());
    let listing = slug.as_ref().map(|slug| {
        format!(
            "https://hol.org/registry/plugins/{}",
            slug.replace('/', "%2F")
        )
    });
    Ok(Card {
        schema: SCHEMA,
        name: plugin.name.clone(),
        version: plugin.version.clone(),
        description: plugin.description.clone(),
        license: plugin.license.clone(),
        homepage: plugin.homepage.clone(),
        identity: Identity {
            repository: repository.clone(),
            verified: false,
        },
        capabilities: Capabilities {
            skills,
            mcp_servers: servers,
            commands: plugin.commands.len(),
            agents: plugin.agents.len(),
            hooks: plugin.hooks.is_some(),
        },
        permissions: Permissions {
            starts_programs: programs.into_iter().collect(),
            network_hosts: hosts.into_iter().collect(),
            environment: environment.into_iter().collect(),
            runs_hooks: plugin.hooks.is_some(),
        },
        runtimes: check::runtimes(plugin)
            .into_iter()
            .filter(|support| support.supported)
            .map(|support| support.runtime)
            .collect(),
        links: CardLinks {
            repository: repository.map(|repository| format!("https://github.com/{repository}")),
            hol_card: listing
                .as_ref()
                .map(|listing| format!("{listing}/.well-known/card.json")),
            listing,
        },
    })
}

/// `owner/name`, or a longer path for a plugin inside a repository, with no
/// empty segment.
fn listing_slug(slug: &str) -> bool {
    crate::install::valid_slug(slug)
        && slug.split('/').count() >= 2
        && slug.split('/').all(|segment| !segment.is_empty())
}

/// The program's file name, without any directory a manifest put in front.
fn program_name(command: &str) -> Option<String> {
    let first = command.split_whitespace().next()?;
    let name = first.rsplit(['/', '\\']).next()?;
    (!name.is_empty() && !name.contains('$')).then(|| name.to_owned())
}

/// The host of an `http(s)` URL, unless it is templated.
fn host(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next()?,
        None => authority.split(':').next()?,
    };
    (!host.is_empty() && !host.contains(['$', '{', '}'])).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{host, listing_slug, program_name};

    #[test]
    fn program_names_drop_directories_and_templates() {
        assert_eq!(program_name("npx -y server").as_deref(), Some("npx"));
        assert_eq!(program_name("./bin/server").as_deref(), Some("server"));
        assert_eq!(
            program_name("${PLUGIN_ROOT}/server").as_deref(),
            Some("server")
        );
        assert_eq!(program_name("${SERVER}"), None);
        assert_eq!(program_name("   "), None);
    }

    #[test]
    fn hosts_skip_credentials_ports_and_templates() {
        assert_eq!(
            host("https://user:pw@API.example.com:8443/mcp?x=1").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(host("http://[::1]:3000/sse").as_deref(), Some("::1"));
        assert_eq!(host("https://${HOST}/mcp"), None);
        assert_eq!(host("ftp://example.com"), None);
        assert_eq!(
            host("HTTPS://MCP.example/mcp").as_deref(),
            Some("mcp.example")
        );
    }

    #[test]
    fn listing_slugs_need_an_owner_and_a_name() {
        assert!(listing_slug("acme/tools"));
        assert!(listing_slug("acme/tools/search"));
        for slug in ["acme", "acme/", "acme//tools", "acme/tools/", "/acme/tools"] {
            assert!(!listing_slug(slug), "{slug}");
        }
    }
}
