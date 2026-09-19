//! Synthetic reciprocal-origin cases with independent expected actions.

use super::policy_vector_fixtures::{
    base, expected, managed, put, setting, source_case, sources, Settings, ACTIONS,
};
use serde_json::{json, Value};

struct Configuration {
    name: String,
    local: Settings,
    managed: Settings,
    action: &'static str,
    observe: &'static str,
}

impl Configuration {
    fn new(name: String, local: Settings, managed: Settings, action: &'static str) -> Self {
        Self {
            name,
            local,
            managed,
            action,
            observe: if action == "warn" { "warn" } else { "allow" },
        }
    }
}

fn configurations(harness: &str, artifact: &str) -> Vec<Configuration> {
    let selectors = ["default", "harness", "artifact", "risk", "harness-risk"];
    let mut cases = Vec::new();
    for local in selectors {
        for managed in selectors {
            if harness != "codex" && local != managed {
                continue;
            }
            for restricted in ["local", "managed"] {
                let la = if restricted == "local" {
                    "block"
                } else {
                    "allow"
                };
                let ma = if restricted == "managed" {
                    "block"
                } else {
                    "allow"
                };
                cases.push(Configuration::new(
                    format!("local-{local}-{la}-managed-{managed}-{ma}"),
                    setting(local, la, harness, artifact),
                    setting(managed, ma, harness, artifact),
                    "block",
                ));
            }
        }
    }
    if harness == "codex" {
        for origin in ["local", "managed"] {
            for (broad, narrow) in [
                ("default", "artifact"),
                ("harness", "artifact"),
                ("risk", "harness-risk"),
            ] {
                let mut settings = setting(broad, "block", harness, artifact);
                settings.extend(setting(narrow, "allow", harness, artifact));
                let (local, managed) = if origin == "local" {
                    (settings, setting("default", "allow", harness, artifact))
                } else {
                    (Vec::new(), settings)
                };
                cases.push(Configuration::new(
                    format!("{origin}-{broad}-block-{narrow}-allow-exception"),
                    local,
                    managed,
                    "allow",
                ));
            }
        }
        for action in ACTIONS {
            cases.push(Configuration::new(
                format!("managed-risk-{action}"),
                Vec::new(),
                setting("risk", action, harness, artifact),
                action,
            ));
        }
        for present in [false, true] {
            let mut local = setting("default", "warn", harness, artifact);
            local.extend(setting("risk", "allow", harness, artifact));
            let mut managed = setting("risk", "block", harness, artifact);
            if present {
                managed.extend(setting("default", "allow", harness, artifact));
            }
            let mut case = Configuration::new(
                format!(
                    "managed-risk-block-default-{}",
                    if present { "explicit-allow" } else { "absent" }
                ),
                local,
                managed,
                "block",
            );
            case.observe = if present { "warn" } else { "allow" };
            cases.push(case);
        }
    }
    cases
}

pub(crate) fn vectors() -> Value {
    let mut cases = Vec::new();
    for source in sources() {
        let harness = source["harness"].as_str().unwrap();
        for case in configurations(harness, source["artifactId"].as_str().unwrap()) {
            for mode in ["enforce", "observe"] {
                let posture = if mode == "observe" {
                    "watch"
                } else {
                    "protected"
                };
                let mut policy = base("balanced", posture, false);
                policy["risk_actions"]["local_secret_read"] = json!("allow");
                put(&mut policy, &case.local);
                let mut value = source_case(
                    &source,
                    &case.name,
                    mode,
                    policy.clone(),
                    expected(harness, mode, case.action, case.observe),
                );
                let _ = value.as_object_mut().unwrap().remove("effectivePolicy");
                value["localEffectivePolicy"] = policy;
                value["managedConfiguration"] = managed(&case.managed, mode);
                cases.push(value);
            }
        }
    }
    json!({"cases": cases})
}
