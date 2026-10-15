//! Codex skill enablement rules from `config.toml` `[[skills.config]]`
//! entries, layered home first and workspace second so later rules win.

use std::fs;
use std::path::{Path, PathBuf};

use super::aibom_paths::{is_file, py_join, py_path, resolve, ERR_NON_UTF8};
use super::context_digest::python_strip;

pub(crate) const ERR_RULES: &str = "native_runner_authority_aibom_skill_rules_invalid";

pub(crate) struct Rule {
    enabled: bool,
    name: Option<String>,
    path: Option<String>,
}

/// `Path.expanduser()` for `~`, `~/...` and `~name/...`. A named user that the
/// system cannot resolve, like CPython, is left unexpanded; the caller's own
/// home is supplied so the resident never reads its own environment for a
/// client's home.
fn expanduser(value: &str, user_home: Option<&str>) -> PathBuf {
    let path = py_path(value);
    let mut parts = path.components();
    let Some(std::path::Component::Normal(first)) = parts.next() else {
        return path;
    };
    if first == "~" {
        let Some(home) = user_home else {
            return path;
        };
        let mut out = PathBuf::from(home.trim_end_matches('/'));
        if out.as_os_str().is_empty() {
            out.push("/");
        }
        out.extend(parts);
        return out;
    }
    if let Some(name) = first.to_str().and_then(|text| text.strip_prefix('~')) {
        if let Some(mut out) = named_user_home(name) {
            out.extend(parts);
            return out;
        }
    }
    path
}

/// `pwd.getpwnam(name).pw_dir`: `~name` expands only on Unix; Windows Python
/// leaves it alone, so the resident does too.
#[cfg(unix)]
fn named_user_home(name: &str) -> Option<PathBuf> {
    nix::unistd::User::from_name(name).ok()??.dir.into()
}

#[cfg(not(unix))]
fn named_user_home(_name: &str) -> Option<PathBuf> {
    None
}

fn absolute_resolved(
    value: &str,
    base_dir: &Path,
    user_home: Option<&str>,
) -> Result<String, &'static str> {
    let expanded = expanduser(value, user_home);
    let candidate = if expanded.is_absolute() {
        expanded
    } else {
        py_join(base_dir, expanded.to_str().ok_or(ERR_NON_UTF8)?)
    };
    let resolved = resolve(&candidate).map_err(|()| ERR_RULES)?;
    resolved.to_str().map(str::to_owned).ok_or(ERR_NON_UTF8)
}

fn stripped(value: Option<&toml::Value>) -> Option<String> {
    let text = value?.as_str()?;
    let text = python_strip(text);
    (!text.is_empty()).then(|| text.to_owned())
}

fn rules_from_file(
    path: &Path,
    base_dir: &Path,
    user_home: Option<&str>,
    out: &mut Vec<Rule>,
) -> Result<(), &'static str> {
    if !is_file(path) {
        return Ok(());
    }
    let Ok(bytes) = fs::read(path) else {
        return Ok(());
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return Ok(());
    };
    let Ok(payload) = text.parse::<toml::Table>() else {
        return Ok(());
    };
    let Some(entries) = payload
        .get("skills")
        .and_then(toml::Value::as_table)
        .and_then(|skills| skills.get("config"))
        .and_then(toml::Value::as_array)
    else {
        return Ok(());
    };
    for entry in entries {
        let Some(entry) = entry.as_table() else {
            continue;
        };
        let Some(enabled_value) = entry.get("enabled") else {
            continue;
        };
        let enabled = enabled_value.as_bool() != Some(false);
        let raw_path = stripped(entry.get("path"));
        let name = stripped(entry.get("name"));
        let path = match raw_path {
            Some(raw) => Some(absolute_resolved(&raw, base_dir, user_home)?),
            None => None,
        };
        if path.is_none() && name.is_none() {
            continue;
        }
        out.push(Rule {
            enabled,
            name,
            path,
        });
    }
    Ok(())
}

/// `load_codex_skill_config_rules`.
pub(crate) fn load_rules(
    home_dir: &Path,
    workspace: Option<&Path>,
    user_home: Option<&str>,
) -> Result<Vec<Rule>, &'static str> {
    let mut rules = Vec::new();
    let home_config = py_join(home_dir, ".codex/config.toml");
    rules_from_file(&home_config, home_dir, user_home, &mut rules)?;
    if let Some(workspace) = workspace {
        let config = py_join(workspace, ".codex/config.toml");
        rules_from_file(&config, workspace, user_home, &mut rules)?;
    }
    Ok(rules)
}

/// `resolve_codex_skill_enabled`.
pub(crate) fn resolve_enabled(
    config_path: &str,
    display_name: &str,
    rules: &[Rule],
    home_dir: &Path,
    user_home: Option<&str>,
) -> Result<bool, &'static str> {
    if rules.is_empty() {
        return Ok(true);
    }
    let skill_path = absolute_resolved(config_path, home_dir, user_home)?;
    let skill_dir = Path::new(&skill_path)
        .parent()
        .and_then(Path::to_str)
        .unwrap_or("")
        .to_owned();
    let normalized_name = python_strip(display_name).to_lowercase();
    let mut resolved: Option<bool> = None;
    for rule in rules {
        if let Some(rule_path) = &rule.path {
            if skill_path == *rule_path
                || skill_dir == *rule_path
                || skill_path.ends_with(rule_path.as_str())
                || skill_dir.ends_with(rule_path.as_str())
            {
                resolved = Some(rule.enabled);
                continue;
            }
        }
        if let Some(name) = &rule.name {
            if python_strip(name).to_lowercase() == normalized_name {
                resolved = Some(rule.enabled);
            }
        }
    }
    Ok(resolved.unwrap_or(true))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn named_user_tilde_expands_to_that_users_home() {
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let name = me.name;
        assert_eq!(
            expanduser(&format!("~{name}/skills/s"), Some("/ignored")),
            me.dir.join("skills/s")
        );
        assert_eq!(
            expanduser("~no-such-user-hol-guard/skills/s", Some("/base")),
            py_path("~no-such-user-hol-guard/skills/s")
        );
    }

    #[test]
    fn named_user_rule_disables_a_matching_skill() {
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let skill_dir = me.dir.join("skills/off");
        let rule = Rule {
            enabled: false,
            name: None,
            path: Some(
                expanduser(&format!("~{}/skills/off", me.name), None)
                    .to_str()
                    .unwrap()
                    .to_owned(),
            ),
        };
        assert!(!resolve_enabled(
            &format!("{}/SKILL.md", skill_dir.to_str().unwrap()),
            "off",
            &[rule],
            Path::new("/home"),
            None,
        )
        .unwrap());
    }
}
