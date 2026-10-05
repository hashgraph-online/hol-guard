//! `homebrew_intent.py` — Homebrew package intent parsing (203 lines — verbatim port).

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::command_launcher_floors::shlex_split;
use crate::package_intent_common::{
    existing_relative_paths, first_positional, flag_tokens, homebrew_tap_target, homebrew_target,
    option_value, redacted_command, IntentKind, PackageIntent, PackageIntentTarget,
};
use crate::package_manager_command::strip_package_manager_global_options;

static BREWFILE_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(brew|cask|tap)\s+(.+)$").unwrap());

/// `parse_brew_intent` (:24-35).
pub fn parse_brew_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    let verb = working_tokens[1].to_lowercase();
    if matches!(verb.as_str(), "install" | "reinstall" | "upgrade") {
        return Some(parse_brew_install_intent(tokens, &working_tokens));
    }
    if verb == "tap" {
        return parse_brew_tap_intent(tokens, &working_tokens);
    }
    if verb == "bundle" {
        return parse_brew_bundle_intent(tokens, &working_tokens, workspace);
    }
    None
}

/// `_parse_brew_install_intent` (:38-47).
fn parse_brew_install_intent(tokens: &[String], working_tokens: &[String]) -> PackageIntent {
    let cask = brew_command_uses_cask(working_tokens);
    let specs = collect_brew_specs(&working_tokens[2.min(working_tokens.len())..]);
    let targets: Vec<PackageIntentTarget> = specs
        .iter()
        .map(|spec| homebrew_target(spec, cask))
        .collect();
    build_brew_intent("install", tokens, targets, Vec::new())
}

/// `_parse_brew_tap_intent` (:50-63).
fn parse_brew_tap_intent(tokens: &[String], working_tokens: &[String]) -> Option<PackageIntent> {
    let tap_name = first_positional(
        &working_tokens[2.min(working_tokens.len())..],
        &["--custom-remote", "--repair"],
    )?;
    let source_url = brew_tap_source_url(working_tokens, &tap_name);
    Some(build_brew_intent(
        "install",
        tokens,
        vec![homebrew_tap_target(&tap_name, source_url.as_deref())],
        Vec::new(),
    ))
}

/// `_parse_brew_bundle_intent` (:66-80).
fn parse_brew_bundle_intent(
    tokens: &[String],
    working_tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if working_tokens.len() >= 3
        && !matches!(working_tokens[2].as_str(), "install" | "upgrade")
        && !working_tokens[2].starts_with('-')
    {
        return None;
    }
    let manifest_paths = existing_relative_paths(workspace, &[brew_bundle_file(working_tokens)]);
    let targets = brewfile_targets(workspace, &manifest_paths);
    Some(build_brew_intent("sync", tokens, targets, manifest_paths))
}

/// `_build_brew_intent` (:83-100).
fn build_brew_intent(
    intent_kind: IntentKind,
    tokens: &[String],
    targets: Vec<PackageIntentTarget>,
    manifest_paths: Vec<String>,
) -> PackageIntent {
    PackageIntent {
        package_manager: "brew".to_owned(),
        intent_kind,
        command_tokens: tokens.to_vec(),
        redacted_command: redacted_command(tokens),
        targets,
        manifest_paths,
        lockfile_paths: Vec::new(),
        flags: flag_tokens(&tokens[1.min(tokens.len())..]),
        notes: if intent_kind == "sync" {
            vec!["brew-bundle".to_owned()]
        } else {
            Vec::new()
        },
        local_executions: Vec::new(),
        execution_context_hashes: Vec::new(),
        execution_context_cwds: Vec::new(),
        execution_context_reason_codes: Vec::new(),
    }
}

/// `_collect_brew_specs` (:103-125).
fn collect_brew_specs(tokens: &[String]) -> Vec<String> {
    const SKIP_VALUE_OPTIONS: &[&str] = &[
        "--appdir",
        "--caskroom",
        "--display-times",
        "--env",
        "--language",
        "--prefix",
        "--requirement",
    ];
    let mut specs: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if SKIP_VALUE_OPTIONS.contains(&token.as_str()) && index + 1 < tokens.len() {
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        specs.push(token.clone());
        index += 1;
    }
    specs
}

/// `_brew_command_uses_cask` (:128-129).
fn brew_command_uses_cask(tokens: &[String]) -> bool {
    tokens[2.min(tokens.len())..]
        .iter()
        .any(|token| token == "--cask" || token.starts_with("--cask="))
}

/// `_brew_tap_source_url` (:132-140).
fn brew_tap_source_url(tokens: &[String], tap_name: &str) -> Option<String> {
    let mut seen_tap = false;
    for token in &tokens[2.min(tokens.len())..] {
        if token == tap_name && !seen_tap {
            seen_tap = true;
            continue;
        }
        if seen_tap && !token.starts_with('-') {
            return Some(token.clone());
        }
    }
    option_value(tokens, "--custom-remote")
}

/// `_brew_bundle_file` (:143-144).
fn brew_bundle_file(tokens: &[String]) -> String {
    option_value(tokens, "--file").unwrap_or_else(|| "Brewfile".to_owned())
}

/// `_brewfile_targets` (:147-159).
fn brewfile_targets(
    workspace: Option<&Path>,
    manifest_paths: &[String],
) -> Vec<PackageIntentTarget> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };
    let mut targets: Vec<PackageIntentTarget> = Vec::new();
    for manifest_path in manifest_paths {
        let candidate = expanduser(&workspace.join(manifest_path));
        let Ok(candidate) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        let Ok(workspace_root) = std::fs::canonicalize(expanduser(workspace)) else {
            continue;
        };
        if !candidate.starts_with(&workspace_root) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        targets.extend(brewfile_line_targets(&text));
    }
    targets
}

/// `Path.expanduser` subset — `~`/`~/` only; identical to
/// `package_intent_common::expanduser` (duplicated since that one is private).
fn expanduser(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            if text == "~" {
                return PathBuf::from(home);
            }
            return PathBuf::from(home).join(&text[2..]);
        }
    }
    path.to_path_buf()
}

/// `_brewfile_line_targets` (:162-175).
fn brewfile_line_targets(text: &str) -> Vec<PackageIntentTarget> {
    let mut targets: Vec<PackageIntentTarget> = Vec::new();
    for line in text.split('\n').flat_map(|l| l.split('\r')) {
        let Some((command, args)) = parse_brewfile_literal_call(line) else {
            continue;
        };
        if command == "brew" && !args.is_empty() {
            targets.push(homebrew_target(&args[0], false));
        } else if command == "cask" && !args.is_empty() {
            targets.push(homebrew_target(&args[0], true));
        } else if command == "tap" && !args.is_empty() {
            targets.push(homebrew_tap_target(
                &args[0],
                brewfile_tap_source_url(&args).as_deref(),
            ));
        }
    }
    targets
}

/// `_parse_brewfile_literal_call` (:178-190).
fn parse_brewfile_literal_call(line: &str) -> Option<(String, Vec<String>)> {
    let stripped = line.trim();
    if stripped.is_empty() || stripped.starts_with('#') {
        return None;
    }
    let matched = BREWFILE_CALL_RE.captures(stripped)?;
    let arg_text = matched.get(2)?.as_str();
    let tokens = shlex_split(arg_text).ok()?;
    let args: Vec<String> = tokens
        .iter()
        .filter(|token| brewfile_token_is_dependency_arg(token))
        .map(|token| token.trim_end_matches(',').to_owned())
        .collect();
    if args.is_empty() {
        return None;
    }
    Some((matched.get(1)?.as_str().to_owned(), args))
}

/// `_brewfile_token_is_dependency_arg` (:193-196).
fn brewfile_token_is_dependency_arg(token: &str) -> bool {
    if token == "," || token.starts_with(',') || token.starts_with(':') {
        return false;
    }
    !(token.starts_with("args:")
        || token.starts_with("postinstall:")
        || token.starts_with("restart_service:"))
}

/// `_brewfile_tap_source_url` (:199-203).
fn brewfile_tap_source_url(args: &[String]) -> Option<String> {
    if args.len() < 2 {
        return None;
    }
    let candidate = &args[1];
    if candidate.contains("://") || candidate.starts_with("git@") || candidate.starts_with("ssh:") {
        Some(candidate.clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn brew_install_collects_specs() {
        let intent = parse_brew_intent(&t(&["brew", "install", "wget", "jq"]), None).unwrap();
        assert_eq!(intent.package_manager, "brew");
        assert_eq!(intent.intent_kind, "install");
        assert_eq!(intent.targets.len(), 2);
        assert_eq!(intent.targets[0].package_name.as_deref(), Some("wget"));
        assert_eq!(intent.targets[0].ecosystem, "homebrew");
    }

    #[test]
    fn brew_cask_marks_ecosystem() {
        let intent = parse_brew_intent(&t(&["brew", "install", "--cask", "alfred"]), None).unwrap();
        assert_eq!(intent.targets[0].ecosystem, "homebrew-cask");
    }

    #[test]
    fn brew_tap_with_custom_remote() {
        let intent = parse_brew_intent(
            &t(&[
                "brew",
                "tap",
                "acme/taps",
                "--custom-remote",
                "https://example.com/t.git",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(intent.targets[0].ecosystem, "homebrew-tap");
        assert_eq!(intent.targets[0].package_name.as_deref(), Some("acme/taps"));
        assert_eq!(
            intent.targets[0].source_url.as_deref(),
            Some("https://example.com/t.git")
        );
    }

    #[test]
    fn brew_unknown_verb_returns_none() {
        assert!(parse_brew_intent(&t(&["brew", "search", "wget"]), None).is_none());
    }

    #[test]
    fn brewfile_line_targets_literal_call() {
        let targets = brewfile_line_targets(
            "brew \"wget\"\ncask 'alfred'\ntap \"acme/taps\", \"https://example.com/t.git\"\n",
        );
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].ecosystem, "homebrew");
        assert_eq!(targets[1].ecosystem, "homebrew-cask");
        assert_eq!(targets[2].ecosystem, "homebrew-tap");
    }
}
