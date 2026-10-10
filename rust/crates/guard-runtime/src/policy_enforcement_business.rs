//! Native business floors. Hook arguments are never authenticated business facts.

#[cfg(test)]
#[path = "policy_enforcement_business_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "policy_enforcement_business_golden_tests.rs"]
mod golden_tests;

use super::{ActionFloor, AdmittedPolicySnapshot};
use guard_contracts::{BusinessActionV1, PreToolActionTypeV1, PreToolResultV1};
use guard_policy_snapshot::business_policy::BusinessPolicyBindingV1;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub(super) struct CompiledBusinessPolicy {
    binding: BusinessPolicyBindingV1,
    default_action: ActionFloor,
    actions: Vec<ActionFloor>,
    expirations: Vec<Option<i128>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct BusinessFloor {
    pub(super) action: ActionFloor,
    pub(super) matched_rule_ids: Vec<String>,
}

impl CompiledBusinessPolicy {
    pub(super) fn new(binding: &BusinessPolicyBindingV1) -> Result<Self, String> {
        binding
            .validate()
            .map_err(|_| "native_business_policy_invalid".to_owned())?;
        let actions = binding
            .rules
            .iter()
            .map(|rule| {
                ActionFloor::parse(&rule.action)
                    .ok_or_else(|| "native_business_policy_invalid".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let expirations = binding
            .rules
            .iter()
            .map(|rule| {
                rule.expires_at
                    .as_deref()
                    .map(|expiry| {
                        guard_contracts::canonical_policy_timestamp_nanos(expiry)
                            .ok_or_else(|| "native_business_policy_invalid".to_owned())
                    })
                    .transpose()
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            binding: binding.clone(),
            default_action: ActionFloor::parse(&binding.default_action)
                .ok_or_else(|| "native_business_policy_invalid".to_owned())?,
            actions,
            expirations,
        })
    }

    // Facts here must eventually come from an authenticated native producer.
    // The ordinary hook path below deliberately supplies None, even if the
    // caller provides a complete-looking business_action object.
    pub(super) fn floor(
        &self,
        intrinsic: ActionFloor,
        facts: Option<&BusinessActionV1>,
    ) -> BusinessFloor {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i128::try_from(duration.as_nanos()).ok());
        self.floor_at(intrinsic, facts, now)
    }

    fn floor_at(
        &self,
        intrinsic: ActionFloor,
        facts: Option<&BusinessActionV1>,
        now: Option<i128>,
    ) -> BusinessFloor {
        let blocked = || BusinessFloor {
            action: ActionFloor::Block,
            matched_rule_ids: Vec::new(),
        };
        // A signed budget declaration is not a durable reservation. Preserve
        // the reviewed refusal until the authenticated executor is integrated.
        if self.binding.budgets.is_some() {
            return blocked();
        }
        let Some(facts) = facts else {
            return blocked();
        };
        if facts.require_complete_facts().is_err() {
            return blocked();
        }
        let mut action = intrinsic;
        let mut matched_rule_ids = Vec::new();
        for ((rule, rule_action), expiry) in self
            .binding
            .rules
            .iter()
            .zip(&self.actions)
            .zip(&self.expirations)
        {
            if let Some(expiry) = expiry {
                let Some(now) = now else {
                    return blocked();
                };
                if now >= *expiry {
                    continue;
                }
            }
            match rule.selector.matches(facts) {
                Ok(true) => {
                    action = action.max(*rule_action);
                    matched_rule_ids.push(rule.id.clone());
                }
                Ok(false) => {}
                Err(_) => return blocked(),
            }
        }
        if matched_rule_ids.is_empty() {
            action = action.max(self.default_action);
        }
        matched_rule_ids.sort_unstable();
        BusinessFloor {
            action,
            matched_rule_ids,
        }
    }
}

fn requires_business_context(
    payload: &Value,
    action_type: PreToolActionTypeV1,
) -> Result<bool, String> {
    let Some(root) = payload.as_object() else {
        return Ok(false);
    };
    let mut envelopes = vec![root];
    for key in ["tool_call", "toolCall", "preToolUse", "pre_tool_use"] {
        if let Some(record) = root.get(key).and_then(Value::as_object) {
            envelopes.push(record);
        }
    }
    for record in &envelopes {
        if record.contains_key("business_action") || record.contains_key("businessAction") {
            return Ok(true);
        }
    }
    if !matches!(
        action_type,
        PreToolActionTypeV1::Command
            | PreToolActionTypeV1::ProcessService
            | PreToolActionTypeV1::Network
            | PreToolActionTypeV1::Browser
            | PreToolActionTypeV1::Unknown
    ) {
        return Ok(false);
    }
    let context = match guard_command::pretool::generic::extract_untrusted_command_context(payload)
    {
        Ok(context) => context,
        Err(_) => return Ok(true),
    };
    if context.business_action_present {
        return Ok(true);
    }
    let Some(command) = context.command else {
        return Ok(false);
    };
    let request = guard_command::CommandModelRequestV1 {
        command,
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "native-business-context-v1".into(),
    };
    let parsed = match guard_command::parse_command(&request) {
        Ok(parsed) if parsed.confidence == "exact" => parsed,
        _ => return Ok(true),
    };
    // Unresolved extraction/parsing cannot prove execution stays outside
    // business operations. No inference covers renamed binaries or HTTP.
    Ok(parsed.segments.iter().any(|segment| {
        let Some(program) = segment.executable.as_deref() else {
            return false;
        };
        if is_business_cli(program) {
            return true;
        }
        is_package_launcher(program) && launcher_runs_business_cli(program, &segment.arguments)
    }))
}

/// Package launchers run the CLI as an argument or inside a shell string
/// (`npx -c 'gws …'`, `pnpm exec sh -c 'gog …'`). Every word of every
/// argument counts, so launcher option parsing cannot hide the CLI. Only a
/// bare package name given to an install-style subcommand is not a call.
fn launcher_runs_business_cli(program: &str, arguments: &[String]) -> bool {
    let installs = installs_packages(program, arguments);
    arguments.iter().any(|argument| {
        let shell_string =
            argument.contains(|c: char| c.is_whitespace() || SHELL_SEPARATORS.contains(&c));
        if installs && !shell_string {
            return false;
        }
        words_name_business_cli(argument)
    })
}

fn words_name_business_cli(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || SHELL_SEPARATORS.contains(&c) || c == '=')
        .filter(|word| !word.is_empty())
        .any(|word| {
            let spec = word.rsplit(['/', '\\']).next().unwrap_or(word);
            is_business_cli(spec.split('@').next().unwrap_or(spec))
        })
}

/// Whether the payload positively names a business operation, including a business
/// CLI inside a shell string the parser cannot model (`sh -c 'gws …'`).
fn names_business_operation(payload: &Value) -> bool {
    guard_command::pretool::generic::extract_untrusted_command_context(payload).is_ok_and(
        |context| {
            context.business_action_present
                || context
                    .command
                    .as_deref()
                    .is_some_and(words_name_business_cli)
        },
    )
}

const SHELL_SEPARATORS: &[char] = &[';', '&', '|', '`', '$', '(', ')', '<', '>', '\'', '"'];

fn installs_packages(program: &str, arguments: &[String]) -> bool {
    let name = executable_basename(program);
    let name = name
        .strip_suffix(".cmd")
        .or_else(|| name.strip_suffix(".exe"))
        .unwrap_or(&name);
    if !matches!(name, "npm" | "pnpm" | "yarn" | "bun") {
        return false;
    }
    // An option ahead of the subcommand may take the install word as its value
    // (`npm --prefix install exec gws`), so only a leading subcommand counts.
    let Some(subcommand) = arguments.first() else {
        return false;
    };
    matches!(
        subcommand.as_str(),
        "install"
            | "i"
            | "add"
            | "ci"
            | "uninstall"
            | "remove"
            | "rm"
            | "update"
            | "up"
            | "upgrade"
            | "outdated"
            | "view"
            | "info"
            | "why"
            | "list"
            | "ls"
            | "audit"
    )
}

fn executable_basename(program: &str) -> String {
    program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase()
}

fn is_business_cli(program: &str) -> bool {
    matches!(
        executable_basename(program).as_str(),
        "gws" | "gws.exe" | "gws.cmd" | "gog" | "gog.exe" | "gog.cmd"
    )
}

fn is_package_launcher(program: &str) -> bool {
    let name = executable_basename(program);
    let name = name
        .strip_suffix(".cmd")
        .or_else(|| name.strip_suffix(".exe"))
        .unwrap_or(&name);
    matches!(
        name,
        "npx" | "pnpx" | "bunx" | "npm" | "pnpm" | "yarn" | "bun" | "uvx" | "pipx"
    )
}

pub(super) fn guard_untrusted_business_context(
    snapshot: &AdmittedPolicySnapshot,
    payload: &Value,
    result: &mut PreToolResultV1,
) -> Result<(), String> {
    let Some(policy) = &snapshot.business_policy else {
        return Ok(());
    };
    if !requires_business_context(payload, result.action.action_type)? {
        return Ok(());
    }
    let intrinsic = ActionFloor::parse(&result.minimum_action)
        .ok_or_else(|| "native_policy_action_invalid".to_owned())?;
    let floor = policy.floor(intrinsic, None);
    // A failed extension evaluation blocks without naming a finding. Commands the
    // parser cannot model, such as `sh -c 'gws …'`, land there; when the payload
    // names a business operation, the missing business facts are the actionable
    // reason. Unrelated opaque commands keep the extension diagnostic.
    let unattributed_business_block = result.reason_code
        == "native_command_extension_evaluation_failed"
        && names_business_operation(payload);
    if floor.action > intrinsic || unattributed_business_block {
        result.reason_code = "native_business_context_unavailable".into();
        result.reason = "HOL Guard requires authenticated account, audience and content facts for this business operation.".into();
    }
    result.minimum_action = "block".into();
    result.policy_action = "block".into();
    result.decision = "deny".into();
    result.explicitly_benign = false;
    Ok(())
}
