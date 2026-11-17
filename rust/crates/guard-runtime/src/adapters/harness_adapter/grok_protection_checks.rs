//! Whether Grok's protection is in place: the hook files, the permission
//! rules in `.grok/config.toml` and the launcher shim, with the repair
//! instruction for each gap. `cli/native_install_checks.py` decided all of
//! this before it moved here; Python renders the answer.
//!
//! - `grok_protection_checks` answers `{"checks": {...}}`, the verification
//!   `hol-guard apps test grok` shows.
//! - `grok_hooks_ready` answers `{"ready": bool}`: hook files, permission
//!   rules and no hook warning (a missing launcher shim does not count).
//! - `grok_hooks_verified` answers `{"verified": bool}`: only the two hook
//!   files, since the permission rules are a second layer and a missing
//!   config must not fail local protection health.
//!
//! Each runs as the owner of the context's Guard home, home and workspace.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::grok::{config_path, hooks_dir, PRETOOL_FILE, PROMPT_FILE};
use super::grok_hook_command::{Checker, Owner};
use super::grok_hook_files::{event_has_catchall_hook, pretool_is_catchall, prompt_is_observe};
use super::{path_text, Ctx, Step};
use crate::codex_toml_read::{self, TomlVal};
use crate::grok_user_config::MANAGED_DENY_RULES;
use crate::native_install_verdict::{Runner, SystemRunner};
use crate::pyjson::PyVal;

const BACKUP_HOOK_EVENTS: [&str; 4] = [
    "PreToolUse",
    "UserPromptSubmit",
    "SessionStart",
    "SubagentStart",
];
const LEGACY_PREFIX: &str = "Read(**/";

const MISSING_HOOKS: &str =
    "Grok Guard hook files are missing from ~/.grok/hooks/. Re-run `hol-guard apps connect grok`.";
const STALE_MATCHER: &str = "Grok Guard pre-tool hook still uses a stale per-tool matcher list. \
    Re-run `hol-guard apps repair grok`.";
const PROMPT_MISSING: &str =
    "The Grok prompt gate or lifecycle hooks are missing. Re-run `hol-guard apps repair grok`.";
const UNREADABLE: &str =
    "Grok managed config could not be read. Re-run `hol-guard apps repair grok`.";
const LEGACY_RULES: &str = "Grok managed deny rules still use literal home prefixes that Grok \
    does not expand. Re-run `hol-guard apps repair grok`.";
const STALE_CONFIG: &str = "Grok protection settings are missing or stale in .grok/config.toml. \
    Re-run `hol-guard apps connect grok`.";

pub(super) fn handles(op: &str) -> bool {
    matches!(
        op,
        "grok_protection_checks" | "grok_hooks_ready" | "grok_hooks_verified"
    )
}

pub(super) fn dispatch(op: &str, ctx: &Ctx) -> Step<Value> {
    let owner = Owner {
        guard_home: &ctx.guard_home,
        home: &ctx.home,
        workspace: ctx.workspace.as_deref(),
    };
    let mut runner = SystemRunner;
    let mut checker = Checker::new(ctx, cfg!(target_os = "macos"), &mut runner);
    let checks = Probe { ctx, owner: &owner };
    Ok(match op {
        "grok_hooks_verified" => {
            let files = checks.hook_files(&mut checker);
            json!({ "verified": files.pretool_catchall && files.prompt_observe })
        }
        "grok_hooks_ready" => json!({ "ready": hooks_ready(&checks.assess(&mut checker)) }),
        _ => json!({ "checks": checks.assess(&mut checker).to_json() }),
    })
}

struct Probe<'a> {
    ctx: &'a Ctx,
    owner: &'a Owner<'a>,
}

struct Files {
    pretool: PathBuf,
    prompt: PathBuf,
    pretool_catchall: bool,
    prompt_observe: bool,
}

impl Probe<'_> {
    fn hook_files<R: Runner>(&self, checker: &mut Checker<'_, R>) -> Files {
        let hooks = hooks_dir(self.ctx);
        let (pretool, prompt) = (hooks.join(PRETOOL_FILE), hooks.join(PROMPT_FILE));
        Files {
            pretool_catchall: pretool_is_catchall(checker, self.ctx, &pretool, Some(self.owner)),
            prompt_observe: prompt_is_observe(checker, self.ctx, &prompt, Some(self.owner)),
            pretool,
            prompt,
        }
    }

    fn is_file(&self, path: &Path) -> bool {
        self.ctx.absolute(path).is_file()
    }

    fn assess<R: Runner>(&self, checker: &mut Checker<'_, R>) -> Assessment {
        let files = self.hook_files(checker);
        let config = config_path(self.ctx);
        let managed = if self.is_file(&config) {
            fs::read(self.ctx.absolute(&config))
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        } else {
            Some(String::new())
        };
        let shim = self.ctx.guard_home.join("bin").join("guard-grok");
        let (pretool_file, prompt_file) =
            (self.is_file(&files.pretool), self.is_file(&files.prompt));
        let config_is_file = self.is_file(&config);
        let owner = self.owner;
        let (managed_active, legacy_rules) = match &managed {
            Some(text) => (
                managed_config_active(text, &MANAGED_DENY_RULES, |events| {
                    events.iter().all(|entries| {
                        entries.is_some_and(|entries| {
                            event_has_catchall_hook(checker, entries, Some(owner))
                        })
                    })
                }),
                has_legacy_deny_rules(text, &MANAGED_DENY_RULES),
            ),
            None => (false, false),
        };
        Assessment::new(Facts {
            pretool_file,
            prompt_file,
            pretool_catchall: files.pretool_catchall,
            prompt_observe: files.prompt_observe,
            config_is_file,
            config_unreadable: managed.is_none(),
            legacy_rules,
            managed_active,
            shim_installed: self.is_file(&shim),
            shim_dir: path_text(&self.ctx.guard_home.join("bin")),
        })
    }
}

/// What the checks read from the machine.
struct Facts {
    pretool_file: bool,
    prompt_file: bool,
    pretool_catchall: bool,
    prompt_observe: bool,
    config_is_file: bool,
    config_unreadable: bool,
    legacy_rules: bool,
    managed_active: bool,
    shim_installed: bool,
    shim_dir: String,
}

struct Assessment {
    facts: Facts,
    warnings: Vec<String>,
}

impl Assessment {
    fn new(facts: Facts) -> Self {
        let mut warnings = Vec::new();
        if !facts.pretool_file || !facts.prompt_file {
            warnings.push(MISSING_HOOKS.to_owned());
        } else if !facts.pretool_catchall {
            warnings.push(STALE_MATCHER.to_owned());
        } else if !facts.prompt_observe {
            warnings.push(PROMPT_MISSING.to_owned());
        }
        if facts.config_unreadable {
            warnings.push(UNREADABLE.to_owned());
        } else if facts.legacy_rules {
            warnings.push(LEGACY_RULES.to_owned());
        } else if !facts.config_is_file || !facts.managed_active {
            warnings.push(STALE_CONFIG.to_owned());
        }
        if !facts.shim_installed {
            warnings.push(format!(
                "guard-grok launcher shim is missing. Add {} to PATH or launch with \
                 `hol-guard run grok` for pre-launch checks.",
                facts.shim_dir
            ));
        }
        Self { facts, warnings }
    }

    fn to_json(&self) -> Value {
        let facts = &self.facts;
        json!({
            "pretool_hook_installed": facts.pretool_file,
            "prompt_hook_installed": facts.prompt_file,
            "pretool_catchall_installed": facts.pretool_catchall,
            "managed_config_installed": facts.managed_active,
            "launch_shim_installed": facts.shim_installed,
            "warnings": self.warnings,
            "ready": self.warnings.is_empty(),
        })
    }
}

/// Live hook files and managed permission rules are active, whatever the
/// launcher shim says: only a warning that names neither counts.
fn hooks_ready(assessment: &Assessment) -> bool {
    let facts = &assessment.facts;
    let hook_warning = assessment.warnings.iter().any(|warning| {
        let lowered = warning.to_lowercase();
        !lowered.contains("shim") && !lowered.contains("launcher")
    });
    facts.pretool_catchall && facts.prompt_file && facts.managed_active && !hook_warning
}

fn entry<'a>(entries: &'a [(String, TomlVal)], key: &str) -> Option<&'a TomlVal> {
    entries
        .iter()
        .find_map(|(name, value)| (name == key).then_some(value))
}

fn table(value: Option<&TomlVal>) -> Option<&[(String, TomlVal)]> {
    match value {
        Some(TomlVal::Table(entries)) => Some(entries),
        _ => None,
    }
}

fn deny_list(entries: &[(String, TomlVal)]) -> Option<&[TomlVal]> {
    match table(entry(entries, "permission")).and_then(|permission| entry(permission, "deny")) {
        Some(TomlVal::List(items)) => Some(items),
        _ => None,
    }
}

fn denies(denied: &[TomlVal], rule: &str) -> bool {
    denied
        .iter()
        .any(|item| matches!(item, TomlVal::Str(text) if text == rule))
}

/// Durable permission floors, compatibility, and catch-all backup hooks.
/// `hooks_valid` is handed the four backup events' configurations.
fn managed_config_active(
    text: &str,
    deny_rules: &[&str],
    hooks_valid: impl FnOnce(&[Option<&PyVal>]) -> bool,
) -> bool {
    let Ok(entries) = codex_toml_read::read(text) else {
        return false;
    };
    let Some(denied) = deny_list(&entries) else {
        return false;
    };
    let compat = table(entry(&entries, "compat"));
    let Some(compat) = compat.filter(|_| deny_rules.iter().all(|rule| denies(denied, rule))) else {
        return false;
    };
    for vendor in ["claude", "cursor"] {
        let off = table(entry(compat, vendor))
            .and_then(|settings| entry(settings, "hooks"))
            .is_some_and(|hooks| matches!(hooks, TomlVal::Bool(false)));
        if !off {
            return false;
        }
    }
    if table(entry(&entries, "hooks")).is_none() {
        return false;
    }
    let (payload, _tokens) = codex_toml_read::wire(&entries);
    let Some(hooks) = payload.get("hooks") else {
        return false;
    };
    let events: Vec<Option<&PyVal>> = BACKUP_HOOK_EVENTS
        .iter()
        .map(|event| hooks.get(event))
        .collect();
    hooks_valid(&events)
}

/// A rule written with the literal home prefix Grok does not expand: the
/// `~/` spelling of a `Read(**/` rule is denied and the rule itself is not.
fn has_legacy_deny_rules(text: &str, deny_rules: &[&str]) -> bool {
    let Ok(entries) = codex_toml_read::read(text) else {
        return false;
    };
    let Some(denied) = deny_list(&entries) else {
        return false;
    };
    deny_rules
        .iter()
        .filter(|rule| rule.starts_with(LEGACY_PREFIX))
        .any(|rule| !denies(denied, rule) && denies(denied, &rule.replacen("**/", "~/", 1)))
}

#[cfg(test)]
#[path = "tests_grok_protection_checks.rs"]
mod tests;
