//! Synthetic generic-command selectors and independently declared results.

use super::policy_vector_fixtures::{base, managed, put, setting, Settings, ACTIONS, REAPPROVAL};
use serde_json::{json, Value};

const SELECTORS: [&str; 4] = ["default", "harness", "publisher", "artifact"];
const COMMANDS: [&str; 2] = ["ssh synthetic@example.invalid", "printf '%s' Synthetic"];

struct Configuration {
    name: String,
    local: Settings,
    managed: Settings,
    selected: &'static str,
}

fn generic_setting(selector: &str, action: &str) -> Settings {
    setting(selector, action, "codex", "codex:project:Shell")
}

fn configuration(
    name: String,
    local: Settings,
    managed: Settings,
    selected: &'static str,
) -> Configuration {
    Configuration {
        name,
        local,
        managed,
        selected,
    }
}

fn configurations() -> Vec<Configuration> {
    let mut cases = Vec::new();
    for local in SELECTORS {
        for managed in SELECTORS {
            for restricted in ["local", "managed"] {
                cases.push(configuration(
                    format!("{restricted}-block-local-{local}-managed-{managed}"),
                    generic_setting(
                        local,
                        if restricted == "local" {
                            "block"
                        } else {
                            "allow"
                        },
                    ),
                    generic_setting(
                        managed,
                        if restricted == "managed" {
                            "block"
                        } else {
                            "allow"
                        },
                    ),
                    "block",
                ));
            }
        }
    }
    for (index, broad) in SELECTORS.into_iter().enumerate() {
        for narrow in SELECTORS.iter().skip(index + 1) {
            for origin in ["local", "managed"] {
                let mut settings = generic_setting(broad, "block");
                settings.extend(generic_setting(narrow, "allow"));
                let (local, managed) = if origin == "local" {
                    (settings, generic_setting("default", "allow"))
                } else {
                    (Vec::new(), settings)
                };
                cases.push(configuration(
                    format!("{origin}-{narrow}-allow-over-{broad}-block"),
                    local,
                    managed,
                    "allow",
                ));
            }
        }
    }
    for action in ACTIONS {
        cases.push(configuration(
            format!("managed-default-{action}"),
            Vec::new(),
            generic_setting("default", action),
            action,
        ));
    }
    cases.push(configuration(
        "managed-default-absent-local-warn".to_owned(),
        generic_setting("default", "warn"),
        Vec::new(),
        "warn",
    ));
    cases.push(configuration(
        "managed-default-explicit-allow-local-warn".to_owned(),
        generic_setting("default", "warn"),
        generic_setting("default", "allow"),
        "warn",
    ));
    cases.push(configuration(
        "unrelated-managed-artifact".to_owned(),
        Vec::new(),
        vec![("artifacts".to_owned(), json!({"synthetic:other": "block"}))],
        "allow",
    ));
    cases.push(configuration(
        "unrelated-managed-publisher".to_owned(),
        Vec::new(),
        vec![("publishers".to_owned(), json!({"synthetic-other": "block"}))],
        "allow",
    ));
    cases
}

fn append(
    cases: &mut Vec<Value>,
    case: &Configuration,
    command: &str,
    mode: &str,
    tool: &str,
    relax: bool,
) {
    let posture = if mode == "observe" {
        "watch"
    } else {
        "protected"
    };
    let mut policy = base("balanced", posture, false);
    policy["unknown_publisher_action"] = json!("allow");
    put(&mut policy, &case.local);
    let current = if relax { "warn" } else { case.selected };
    let observed = (mode == "observe" && !matches!(current, "allow" | "warn")).then_some(current);
    let final_action = if observed.is_some() { "allow" } else { current };
    cases.push(json!({
        "name": format!("{tool}-{mode}-{}-{command}", case.name),
        "harness": "codex", "mode": mode,
        "payload": {
            "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": command},
            "source_scope": "project", "publisher": "synthetic-publisher", "approval_requests": []
        },
        "artifactId": format!("codex:project:{tool}"),
        "localEffectivePolicy": policy, "managedConfiguration": managed(&case.managed, mode),
        "expected": {
            "configuredPolicyAction": case.selected, "currentConfigAction": current,
            "observedPolicyAction": observed, "finalPolicyAction": final_action,
            "exitCode": if matches!(final_action, "allow" | "warn") { 0 } else { 1 }
        }
    }));
}

pub(crate) fn vectors() -> Value {
    let mut cases = Vec::new();
    for case in configurations() {
        for command in COMMANDS {
            for mode in ["enforce", "observe"] {
                append(&mut cases, &case, command, mode, "Shell", false);
            }
        }
    }
    for tool in ["Shell", "Bash", "shell", "exec_command"] {
        for action in ["review", REAPPROVAL] {
            for selector in ["default", "artifact"] {
                let case = configuration(
                    format!("pwd-{selector}-{action}"),
                    Vec::new(),
                    setting(selector, action, "codex", &format!("codex:project:{tool}")),
                    action,
                );
                for mode in ["enforce", "observe"] {
                    append(
                        &mut cases,
                        &case,
                        "pwd",
                        mode,
                        tool,
                        selector == "default" && tool != "exec_command",
                    );
                }
            }
        }
    }
    for tool in ["Bash", "shell", "exec_command"] {
        for command in COMMANDS {
            for mode in ["enforce", "observe"] {
                let case = configuration(
                    "tool-contract".to_owned(),
                    Vec::new(),
                    generic_setting("default", "review"),
                    "review",
                );
                append(&mut cases, &case, command, mode, tool, false);
            }
        }
    }
    json!({"cases": cases})
}
