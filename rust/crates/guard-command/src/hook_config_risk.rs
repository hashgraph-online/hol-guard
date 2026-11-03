//! Risky commands in an agent hook configuration.
//!
//! A project can configure shell commands that an agent runs on its own at
//! session start, before or after each tool call, or when it stops. These
//! rules read that configuration only: they never run a hook or resolve its
//! program.
//!
//! Each command runs the shared launch screen, so a hook that pipes a
//! download into a shell or sends the environment over the network is named
//! the same way as in an agent's shell commands and MCP server launches.

use crate::launch_screen::{screen_argv, screen_script, LaunchRisk};

#[cfg(test)]
#[path = "hook_config_risk_tests.rs"]
mod tests;

/// One rule's fixed wording. Nothing in it quotes the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookConfigRule {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub title: &'static str,
    pub reason: &'static str,
    pub false_positive_hint: Option<&'static str>,
}

pub const REMOTE_CODE_HOOK: HookConfigRule = HookConfigRule {
    id: "hook.config.remote-code",
    category: "execution",
    severity: "critical",
    confidence: "strong",
    title: "Agent hook runs downloaded code",
    reason: "A hook the agent runs on its own pipes a download into a shell or interpreter, so opening the project runs remote code without review.",
    false_positive_hint: None,
};

pub const ENVIRONMENT_EXFILTRATION_HOOK: HookConfigRule = HookConfigRule {
    id: "hook.config.environment-exfiltration",
    category: "exfiltration",
    severity: "critical",
    confidence: "strong",
    title: "Agent hook sends environment variables",
    reason: "A hook the agent runs on its own pipes the process environment, which often holds secrets, to a network sender.",
    false_positive_hint: None,
};

pub const PRIVILEGED_HOOK: HookConfigRule = HookConfigRule {
    id: "hook.config.privileged-launch",
    category: "privilege",
    severity: "high",
    confidence: "strong",
    title: "Agent hook runs with elevated privileges",
    reason: "A hook the agent runs on its own starts through sudo or a similar wrapper, so it runs with administrator rights whenever it fires.",
    false_positive_hint: Some("Expected only in a project that manages the machine itself."),
};

/// The rules a hook `command` matches, in rule order and each at most once.
/// With `args` the command is a program and its arguments; without, it is a
/// shell command line.
pub fn detect_hook_config_risk(command: &str, args: Option<&[String]>) -> Vec<HookConfigRule> {
    if command.trim().is_empty() {
        return Vec::new();
    }
    let risk = match args {
        Some(args) => screen_argv(
            &std::iter::once(command.to_owned())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>(),
        ),
        None => screen_script(command),
    };
    rules(risk)
}

fn rules(risk: LaunchRisk) -> Vec<HookConfigRule> {
    [
        (risk.remote_code, REMOTE_CODE_HOOK),
        (risk.environment_exfiltration, ENVIRONMENT_EXFILTRATION_HOOK),
        (risk.privileged, PRIVILEGED_HOOK),
    ]
    .into_iter()
    .filter_map(|(found, rule)| found.then_some(rule))
    .collect()
}
