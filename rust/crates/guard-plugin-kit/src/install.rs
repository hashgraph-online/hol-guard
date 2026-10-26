//! `hol-guard plugin install|uninstall`: turn a listing's install spec into
//! the argument vectors each runtime's own CLI takes.
//!
//! The spec comes from the HOL registry and is untrusted. It carries only
//! identifiers (repository, marketplace and plugin names), never command
//! text. Every identifier is checked here and the argv is built from fixed
//! program names, so a listing cannot make Guard run anything else. The Kit
//! still runs nothing itself: the CLI shows the plan and runs it only on
//! `--apply`, one runtime at a time.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SPEC_SCHEMA: &str = "hol.plugin-install-spec.v1";

/// Runtimes the spec may name, in the order the plan lists them.
const RUNTIMES: [&str; 3] = ["claude-code", "codex", "agent-skills"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Uninstall,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    slug: String,
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(rename = "listingUrl")]
    listing_url: String,
    #[serde(default, rename = "trustScore")]
    trust_score: Option<f64>,
    targets: Vec<Target>,
    #[serde(default)]
    manual: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    runtime: String,
    #[serde(default)]
    marketplace: Option<Marketplace>,
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marketplace {
    repository: String,
    name: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Step {
    pub runtime: &'static str,
    /// The program each command starts with; the CLI checks it is on PATH.
    pub program: &'static str,
    /// True when the program was found on this machine.
    pub available: bool,
    /// False when Guard only prints the commands and never runs them.
    pub automatic: bool,
    pub commands: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub action: &'static str,
    pub slug: String,
    pub name: String,
    pub version: Option<String>,
    pub repository: Option<String>,
    pub listing_url: String,
    pub trust_score: Option<f64>,
    pub steps: Vec<Step>,
    /// Runtimes the listing supports that Guard cannot install for you.
    pub manual: Vec<String>,
}

/// GitHub `owner/name`: owner 1–39 of `[A-Za-z0-9-]` not starting with `-`,
/// name 1–100 of `[A-Za-z0-9._-]` not starting with `.` or `-`.
pub fn valid_repository(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    let owner_ok = (1..=39).contains(&owner.len())
        && !owner.starts_with('-')
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let name_ok = (1..=100).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    owner_ok && name_ok
}

/// Marketplace and plugin entry names: 1–128 of `[A-Za-z0-9._-]`, starting
/// with a letter or digit, so none can be read as a flag.
pub fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

const INVALID: &str = "plugin_kit_install_spec_invalid";

fn parse(spec: Value) -> Result<Spec, String> {
    let spec: Spec = serde_json::from_value(spec).map_err(|_| INVALID.to_owned())?;
    if spec.schema != SPEC_SCHEMA {
        return Err("plugin_kit_install_spec_unsupported".to_owned());
    }
    let listing_ok = spec
        .listing_url
        .strip_prefix("https://hol.org/")
        .is_some_and(|rest| valid_text(rest, 300) && !rest.contains(char::is_whitespace));
    let version_ok = spec.version.as_deref().is_none_or(|v| valid_text(v, 64));
    let repository_ok = spec.repository.as_deref().is_none_or(valid_repository);
    let manual_ok = spec.manual.iter().all(|m| valid_identifier(m));
    if !valid_slug(&spec.slug)
        || !valid_text(&spec.name, 128)
        || !listing_ok
        || !version_ok
        || !repository_ok
        || !manual_ok
        || spec.targets.len() > RUNTIMES.len()
    {
        return Err(INVALID.to_owned());
    }
    let mut seen = BTreeSet::new();
    for target in &spec.targets {
        if !seen.insert(target.runtime.as_str()) {
            return Err(INVALID.to_owned());
        }
        let ok = match target.runtime.as_str() {
            "claude-code" | "codex" => {
                target.repository.is_none()
                    && target.plugin.as_deref().is_some_and(valid_identifier)
                    && target.marketplace.as_ref().is_some_and(|m| {
                        valid_repository(&m.repository) && valid_identifier(&m.name)
                    })
            }
            "agent-skills" => {
                target.marketplace.is_none()
                    && target.plugin.is_none()
                    && target.repository.as_deref().is_some_and(valid_repository)
            }
            _ => false,
        };
        if !ok {
            return Err(INVALID.to_owned());
        }
    }
    Ok(spec)
}

/// Check a spec with the same rules as a plan, without building one.
pub(crate) fn validate(spec: &Value) -> Result<(), String> {
    parse(spec.clone()).map(|_| ())
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn step(target: &Target, action: Action, available: &BTreeSet<String>) -> Step {
    let marketplace_install = |program: &'static str, add: &str, remove: &str, list: &[&str]| {
        let market = target.marketplace.as_ref().expect("validated");
        let plugin = target.plugin.as_deref().expect("validated");
        let id = format!("{plugin}@{}", market.name);
        let commands = match action {
            Action::Install => vec![
                argv(&[program, "plugin", "marketplace", "add", &market.repository]),
                argv(&[program, "plugin", add, &id]),
            ],
            Action::Uninstall => vec![argv(&[program, "plugin", remove, &id])],
        };
        Step {
            runtime: "",
            program,
            available: available.contains(program),
            automatic: true,
            commands,
            verify: Some(argv(list)),
            note: (action == Action::Uninstall)
                .then_some("The marketplace stays registered, since other plugins may use it."),
        }
    };
    match target.runtime.as_str() {
        "claude-code" => Step {
            runtime: "claude-code",
            ..marketplace_install(
                "claude",
                "install",
                "uninstall",
                &["claude", "plugin", "list"],
            )
        },
        "codex" => Step {
            runtime: "codex",
            ..marketplace_install("codex", "add", "remove", &["codex", "plugin", "list"])
        },
        _ => {
            let repository = target.repository.as_deref().expect("validated");
            let commands = match action {
                Action::Install => vec![argv(&["npx", "skills", "add", repository])],
                Action::Uninstall => vec![argv(&["npx", "skills", "list"])],
            };
            Step {
                runtime: "agent-skills",
                program: "npx",
                available: available.contains("npx"),
                automatic: false,
                commands,
                verify: Some(argv(&["npx", "skills", "list"])),
                note: Some(match action {
                    Action::Install => "Run this yourself: the Skills CLI downloads a package from npm and installs for every agent it detects.",
                    Action::Uninstall => "Remove the skills with the Skills CLI; it lists what it installed.",
                }),
            }
        }
    }
}

/// Build the plan. `available` names the programs found on PATH and
/// `requested` limits it to some runtimes (empty means every target).
pub fn plan(
    spec: Value,
    action: Action,
    available: &[String],
    requested: &[String],
) -> Result<Plan, String> {
    let spec = parse(spec)?;
    if requested.iter().any(|r| !RUNTIMES.contains(&r.as_str())) {
        return Err("plugin_kit_install_runtime_unknown".to_owned());
    }
    let offered: BTreeSet<&str> = spec.targets.iter().map(|t| t.runtime.as_str()).collect();
    if requested.iter().any(|r| !offered.contains(r.as_str())) {
        return Err("plugin_kit_install_runtime_not_offered".to_owned());
    }
    let available: BTreeSet<String> = available.iter().cloned().collect();
    let mut steps: Vec<Step> = spec
        .targets
        .iter()
        .filter(|t| requested.is_empty() || requested.contains(&t.runtime))
        .map(|t| step(t, action, &available))
        .collect();
    steps.sort_by_key(|s| RUNTIMES.iter().position(|r| *r == s.runtime));
    Ok(Plan {
        action: match action {
            Action::Install => "install",
            Action::Uninstall => "uninstall",
        },
        slug: spec.slug,
        name: spec.name,
        version: spec.version,
        repository: spec.repository,
        listing_url: spec.listing_url,
        trust_score: spec.trust_score.filter(|s| s.is_finite()),
        steps,
        manual: spec.manual,
    })
}
