//! Declared sensitive-read selector, posture and risk cases.

use super::policy_vector_fixtures::{base, expected, source_case, sources, ACTIONS, REAPPROVAL};
use serde_json::{json, Value};

struct Configuration {
    name: String,
    default_action: &'static str,
    harness_action: Option<&'static str>,
    artifact_action: Option<&'static str>,
    risk_action: Option<&'static str>,
    harness_risk_action: Option<&'static str>,
    level: &'static str,
    posture: Option<&'static str>,
    evaluated: &'static str,
    observe: &'static str,
}

impl Configuration {
    fn new(name: impl Into<String>, evaluated: &'static str, observe: &'static str) -> Self {
        Self {
            name: name.into(),
            default_action: "allow",
            harness_action: None,
            artifact_action: None,
            risk_action: None,
            harness_risk_action: None,
            level: "balanced",
            posture: None,
            evaluated,
            observe,
        }
    }

    fn set(&mut self, selector: &str, action: &'static str) {
        match selector {
            "default" => self.default_action = action,
            "harness" => self.harness_action = Some(action),
            "artifact" => self.artifact_action = Some(action),
            "risk" => self.risk_action = Some(action),
            "harness-risk" => self.harness_risk_action = Some(action),
            _ => panic!("undeclared sensitive selector"),
        }
    }
}

fn configurations() -> Vec<Configuration> {
    let mut cases = Vec::new();
    let broad_answers = [
        REAPPROVAL,
        REAPPROVAL,
        REAPPROVAL,
        REAPPROVAL,
        "sandbox-required",
        "block",
    ];
    for (index, action) in ACTIONS.into_iter().enumerate() {
        for selector in ["default", "harness", "artifact", "risk", "harness-risk"] {
            let evaluated = if matches!(selector, "risk" | "harness-risk") {
                action
            } else {
                broad_answers[index]
            };
            let observe = if evaluated == "warn"
                || (action == "warn" && matches!(selector, "harness" | "artifact"))
            {
                "warn"
            } else {
                "allow"
            };
            let mut case = Configuration::new(format!("{selector}-{action}"), evaluated, observe);
            case.set(selector, action);
            cases.push(case);
        }
    }
    type Conflict = (
        &'static str,
        &'static [(&'static str, &'static str)],
        &'static str,
    );
    let conflicts: [Conflict; 8] = [
        (
            "artifact-allow-harness-block-risk-allow",
            &[
                ("harness", "block"),
                ("artifact", "allow"),
                ("risk", "allow"),
            ],
            "allow",
        ),
        (
            "artifact-block-harness-allow-risk-allow",
            &[
                ("harness", "allow"),
                ("artifact", "block"),
                ("risk", "allow"),
            ],
            "block",
        ),
        (
            "harness-allow-default-block-risk-allow",
            &[
                ("default", "block"),
                ("harness", "allow"),
                ("risk", "allow"),
            ],
            "allow",
        ),
        (
            "artifact-allow-default-block-risk-allow",
            &[
                ("default", "block"),
                ("artifact", "allow"),
                ("risk", "allow"),
            ],
            "allow",
        ),
        (
            "risk-block-artifact-allow",
            &[("artifact", "allow"), ("risk", "block")],
            "block",
        ),
        (
            "harness-risk-allow-global-risk-block",
            &[("risk", "block"), ("harness-risk", "allow")],
            "allow",
        ),
        (
            "harness-risk-block-global-risk-allow",
            &[("risk", "allow"), ("harness-risk", "block")],
            "block",
        ),
        (
            "harness-risk-allow-artifact-block",
            &[("artifact", "block"), ("harness-risk", "allow")],
            "block",
        ),
    ];
    for (name, settings, evaluated) in conflicts {
        let mut case = Configuration::new(name, evaluated, "allow");
        for (selector, action) in settings {
            case.set(selector, action);
        }
        cases.push(case);
    }
    for (name, level, risk, evaluated, observe) in [
        ("level-relaxed", "relaxed", None, "warn", "warn"),
        ("level-strict", "strict", None, REAPPROVAL, "allow"),
        (
            "level-relaxed-explicit-warn",
            "relaxed",
            Some("warn"),
            "warn",
            "warn",
        ),
        ("level-gentle", "gentle", None, "warn", "warn"),
        ("level-paranoid", "paranoid", None, "block", "allow"),
        ("level-custom", "custom", None, REAPPROVAL, "allow"),
    ] {
        let mut case = Configuration::new(name, evaluated, observe);
        case.level = level;
        case.risk_action = risk;
        cases.push(case);
    }
    for posture in ["protected", "extra_careful", "watch"] {
        for risk in [None, Some("allow"), Some("block")] {
            let mut case = Configuration::new(
                format!("posture-{posture}-risk-{}", risk.unwrap_or("default")),
                risk.unwrap_or(REAPPROVAL),
                "allow",
            );
            case.posture = Some(posture);
            case.level = if posture == "extra_careful" {
                "strict"
            } else {
                "balanced"
            };
            case.risk_action = risk;
            cases.push(case);
        }
    }
    cases
}

fn policy(case: &Configuration, harness: &str, artifact: &str) -> Value {
    let mut value = base(
        case.level,
        case.posture.unwrap_or("protected"),
        case.posture.is_some(),
    );
    value["default_action"] = json!(case.default_action);
    if let Some(action) = case.harness_action {
        value["harness_actions"][harness] = json!(action);
    }
    if let Some(action) = case.artifact_action {
        value["artifact_actions"][artifact] = json!(action);
    }
    if let Some(action) = case.risk_action {
        value["risk_actions"]["local_secret_read"] = json!(action);
    }
    if let Some(action) = case.harness_risk_action {
        value["harness_risk_actions"][harness] = json!({"local_secret_read": action});
    }
    value
}

pub(crate) fn vectors() -> Value {
    let mut cases = Vec::new();
    for source in sources() {
        let harness = source["harness"].as_str().unwrap();
        let configurations = if harness == "codex" {
            configurations()
        } else {
            ACTIONS
                .into_iter()
                .map(|action| {
                    let mut case = Configuration::new(
                        format!("risk-{action}"),
                        action,
                        if action == "warn" { "warn" } else { "allow" },
                    );
                    case.risk_action = Some(action);
                    case
                })
                .collect()
        };
        for case in configurations {
            let modes: &[&str] = if case.posture.is_some() {
                &["enforce"]
            } else {
                &["enforce", "observe"]
            };
            for requested in modes {
                let mode = if case.posture == Some("watch") {
                    "observe"
                } else {
                    requested
                };
                cases.push(source_case(
                    &source,
                    &case.name,
                    mode,
                    policy(&case, harness, source["artifactId"].as_str().unwrap()),
                    expected(harness, mode, case.evaluated, case.observe),
                ));
            }
        }
    }
    json!({"cases": cases})
}
