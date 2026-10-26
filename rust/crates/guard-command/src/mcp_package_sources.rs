//! Source selectors and launcher configuration must not inherit default-source grants.

use serde_json::json;

use crate::mcp_decision::{package_launcher_name, package_token, stable_digest};

const LEGACY_SOURCE_FLAGS: &[&str] = &["--registry", "--index-url", "--extra-index-url", "--index"];

/// Recognize value-bearing source options in both source and package parsing.
pub(crate) fn source_option_name(launcher: &str, option: &str) -> Option<String> {
    let normalized = option.to_ascii_lowercase();
    if LEGACY_SOURCE_FLAGS.contains(&normalized.as_str())
        || matches!(
            normalized.as_str(),
            "--userconfig"
                | "--globalconfig"
                | "--config"
                | "--config-file"
                | "--use-yarnrc"
                | "--default-index"
                | "--find-links"
                | "--pip-args"
                | "--env-file"
        )
        || (normalized.starts_with("--@") && normalized.ends_with(":registry"))
    {
        return Some(normalized);
    }
    if matches!(launcher, "npm" | "npx" | "pnpm") {
        // npm accepts unambiguous abbreviations of its configuration keys.
        for canonical in ["--registry", "--userconfig", "--globalconfig"] {
            if normalized.len() >= 5 && canonical.starts_with(&normalized) {
                return Some(canonical.to_owned());
            }
        }
    }
    match (launcher, option) {
        ("uvx" | "pipx", "-i") => Some("--index-url".to_owned()),
        ("uvx", "-f") => Some("--find-links".to_owned()),
        _ => None,
    }
}

fn neutral_switch(option: &str) -> bool {
    matches!(
        option,
        "-y" | "--yes"
            | "--no"
            | "-q"
            | "--quiet"
            | "--silent"
            | "--verbose"
            | "-v"
            | "-h"
            | "--help"
            | "-V"
            | "--version"
            | "--"
    )
}

pub(crate) fn package_source_token(command: &str, args: &[String]) -> String {
    let launcher = package_launcher_name(command);
    let launcher_name = launcher.as_deref().unwrap_or("");
    let target = launcher
        .as_deref()
        .and_then(|name| package_token(name, args));
    let mut sources = Vec::new();
    let mut before_package = true;
    let mut options_ended = false;
    let mut unreviewed_option = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].trim();
        let (option, inline_value) = argument
            .split_once('=')
            .map_or((argument, None), |(name, value)| (name, Some(value)));
        if let Some(name) = source_option_name(launcher_name, option) {
            let value = if let Some(value) = inline_value {
                value.trim()
            } else if let Some(value) = args.get(index + 1) {
                index += 1;
                value.trim()
            } else {
                // A malformed source option is still not the default source.
                ""
            };
            if LEGACY_SOURCE_FLAGS.contains(&option) {
                // Retain the existing token contract for explicit registry/index grants.
                sources.push(format!("{name}={value}"));
            } else {
                // Config paths and forwarded pip arguments may contain secrets.
                sources.push(format!("{name}=sha256:{}", stable_digest(&json!(value))));
            }
        } else {
            if target.as_deref() == Some(argument) {
                before_package = false;
            }
            if launcher.is_some()
                && (before_package || (launcher_name == "npm" && !options_ended))
                && argument.starts_with('-')
                && !neutral_switch(argument)
            {
                // An unfamiliar launcher option may redirect config/source resolution.
                // Bind the whole argv so changing its separate operand cannot reuse a grant.
                unreviewed_option = true;
            }
            if argument == "--" {
                options_ended = true;
            }
        }
        index += 1;
    }
    if unreviewed_option {
        sources.push(format!(
            "launcher-argv=sha256:{}",
            stable_digest(&json!(args))
        ));
    }
    if sources.is_empty() {
        "default".to_owned()
    } else {
        sources.join("|")
    }
}
