//! Paired local/cloud fixtures for one remote MCP tool.
//!
//! Each case states the facts both paths share: the starting action, the
//! catalog tool state, whether an external contribution is activated, global
//! lockdown, the binding effect and the capabilities the hosted target lacks.
//! The local side runs the contributed MCP decision a local hook applies to
//! the same tool call. The cloud side runs the hosted evaluator end to end.
//! Where the two differ, the fixture names the relation and the reason code
//! that explains it, and the hosted path may only ever be the stricter one.

use super::activation::{payload, sign, signer, Signer};
use super::*;
use crate::cloud_action::ProgramView;
use crate::contributed_mcp_decision::{decide_contributed_mcp, ContributedMcpInput, Contribution};
use crate::extension_control::{
    ControlLayerKind, ControlState, ControlTarget, ControlTargetKind, ExtensionControl,
    ExtensionControlLayer, CONTROL_SCHEMA_VERSION,
};
use crate::native_command_program::{ProgramMcp, ProgramMcpLaunch, ProgramMcpTool};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const PARITY: &str = include_str!("../../tests/fixtures/cloud-action/local-cloud-parity.json");
/// The fixture binding set's remote MCP binding.
const BINDING_INDEX: usize = 4;
const ENDPOINT: &str = "https://mcp.example.invalid/v1";
const TOOL: &str = "search_docs";
const EXTENSION: &str = "command.mcp-synthetic-remote";
const ALL_CAPABILITIES: [&str; 5] = [
    "egress-pinned",
    "bounded-output",
    "resource-allowlist",
    "no-filesystem",
    "no-subprocess",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityDocument {
    schema: String,
    action_id: String,
    relations: BTreeMap<String, String>,
    cases: Vec<ParityCase>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityCase {
    id: String,
    why: String,
    facts: Facts,
    expect: Expect,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Facts {
    tool_state: String,
    trust_class: String,
    extension_enabled: bool,
    baseline: GuardAction,
    cloud_rule: bool,
    effect: ActionEffect,
    global_lockdown: bool,
    missing_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    local: GuardAction,
    cloud: GuardAction,
    relation: String,
    explanation: Option<String>,
}

fn document() -> ParityDocument {
    serde_json::from_str(PARITY).unwrap()
}

fn mcp(state: &str) -> ProgramMcp {
    ProgramMcp {
        surface: "mcp".to_owned(),
        mcp_launch: ProgramMcpLaunch {
            kind: "remote-http".to_owned(),
            command: None,
            package: None,
            url: Some(ENDPOINT.to_owned()),
            server_names: vec!["example-docs".to_owned()],
        },
        mcp_tools: vec![ProgramMcpTool {
            name: TOOL.to_owned(),
            state: state.to_owned(),
        }],
    }
}

fn extension_id(facts: &Facts) -> String {
    match facts.trust_class.as_str() {
        "external" => format!("{EXTENSION}-external"),
        _ => EXTENSION.to_owned(),
    }
}

/// The local hook: the same contributed decision over the same identity,
/// with activation and lockdown carried by a local-admin control layer.
fn local_action(facts: &Facts) -> GuardAction {
    let mcp = mcp(&facts.tool_state);
    let id = extension_id(facts);
    let catalog = [Contribution {
        catalog_id: &id,
        trust_class: &facts.trust_class,
        mcp: &mcp,
    }];
    let controls = facts
        .extension_enabled
        .then(|| ExtensionControl {
            target: ControlTarget::new(ControlTargetKind::Extension, id.clone()).unwrap(),
            state: ControlState::Enabled,
        })
        .into_iter()
        .collect();
    let layers = [ExtensionControlLayer {
        schema_version: CONTROL_SCHEMA_VERSION.to_owned(),
        kind: ControlLayerKind::LocalAdmin,
        catalog_digest: packaged_command_program().unwrap().catalog_digest.clone(),
        global_lockdown: facts.global_lockdown,
        controls,
    }];
    let mut identity = serde_json::Map::new();
    identity.insert("transport".into(), "http".into());
    identity.insert("command".into(), ENDPOINT.into());
    let tool = Value::from(TOOL);
    let input = ContributedMcpInput {
        current_action: facts.baseline.as_str(),
        server_identity: Some(&identity),
        artifact_transport: None,
        server_name: None,
        tool_name: Some(&tool),
        layers: &layers,
    };
    decide_contributed_mcp(&catalog, &input).map_or(facts.baseline, |outcome| {
        serde_json::from_value(outcome.action.into()).unwrap()
    })
}

/// How the hosted evaluator is wired up for a run; a test may break it on
/// purpose to show the comparison notices.
struct CloudWiring {
    signer: Signer,
    include_catalog: bool,
    effect_override: Option<ActionEffect>,
    dropped_capability: Option<&'static str>,
}

impl CloudWiring {
    fn faithful() -> Self {
        Self {
            signer: signer(),
            include_catalog: true,
            effect_override: None,
            dropped_capability: None,
        }
    }

    fn evaluate(&self, action_id: &str, facts: &Facts) -> Value {
        let mut set: Value = serde_json::from_str(BINDINGS).unwrap();
        let effect = self.effect_override.unwrap_or(facts.effect);
        set["bindings"][BINDING_INDEX]["effect"] = serde_json::to_value(effect).unwrap();
        if let Some(dropped) = self.dropped_capability {
            let required = &mut set["bindings"][BINDING_INDEX]["required_capabilities"];
            required.as_array_mut().unwrap().retain(|c| c != dropped);
        }
        let evaluator = CloudActionEvaluator::new(
            load_binding_set(set.to_string().as_bytes()).unwrap(),
            Some(self.signer.public),
        );
        let mut request = request_for(&evaluator);
        request["connection"]["provider"] = "example".into();
        set_action(&mut request, action_id, json!({"query": "parity"}));
        request["target_capabilities"] = ALL_CAPABILITIES
            .iter()
            .filter(|capability| !facts.missing_capabilities.iter().any(|m| m == *capability))
            .map(|capability| Value::from(*capability))
            .collect();
        if facts.cloud_rule {
            request["policy"]["rules"] =
                json!([rule("baseline", facts.baseline.as_str(), action_id)]);
        }
        let mut body = payload("ws-synthetic-1");
        body["global_lockdown"] = facts.global_lockdown.into();
        body["controls"] = if facts.extension_enabled {
            json!([{"extension_id": extension_id(facts), "state": "enabled"}])
        } else {
            json!([])
        };
        request["activation"] = sign(&self.signer, &body);

        let program = packaged_command_program().unwrap();
        let mcp = mcp(&facts.tool_state);
        let id = extension_id(facts);
        let mut view = ProgramView::of(&program);
        view.catalog = if self.include_catalog {
            vec![Contribution {
                catalog_id: &id,
                trust_class: &facts.trust_class,
                mcp: &mcp,
            }]
        } else {
            Vec::new()
        };
        evaluator.evaluate_with(request.to_string().as_bytes(), &view)
    }
}

/// Compare one case's two outcomes with each other and with the fixture.
fn check(case: &ParityCase, action_id: &str, cloud: &CloudWiring) -> Result<(), String> {
    let local = local_action(&case.facts);
    let result = cloud.evaluate(action_id, &case.facts);
    let fail = |what: String| Err(format!("{}: {what}; result {result}", case.id));
    if result.get("error").is_some() {
        return fail("hosted evaluation failed".into());
    }
    let hosted: GuardAction = serde_json::from_value(result["action"].clone()).unwrap();
    let reasons: Vec<&str> = result["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if local != case.expect.local || hosted != case.expect.cloud {
        return fail(format!(
            "expected local {:?} / cloud {:?}, got {local:?} / {hosted:?}",
            case.expect.local, case.expect.cloud
        ));
    }
    if hosted.severity() < local.severity() {
        return fail("hosted path is looser than the local one".into());
    }
    if result["dispatch_permitted"] != matches!(hosted, GuardAction::Allow | GuardAction::Warn) {
        return fail("dispatch_permitted disagrees with the action".into());
    }
    let explained =
        |code: &str| case.expect.explanation.as_deref() == Some(code) && reasons.contains(&code);
    let relation_holds = match case.expect.relation.as_str() {
        "same" => hosted == local && case.expect.explanation.is_none(),
        "cloud-stricter" => {
            hosted.severity() > local.severity()
                && case.expect.explanation.as_deref().is_some_and(explained)
        }
        "cloud-unavailable" => {
            let mut missing: Vec<&str> = result["missing_capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect();
            missing.sort_unstable();
            let mut withheld: Vec<&str> = case
                .facts
                .missing_capabilities
                .iter()
                .map(String::as_str)
                .collect();
            withheld.sort_unstable();
            hosted == GuardAction::SandboxRequired
                && !missing.is_empty()
                && missing == withheld
                && explained("capability_unavailable")
        }
        other => return fail(format!("unknown relation {other}")),
    };
    if relation_holds {
        Ok(())
    } else {
        fail(format!(
            "relation {} with explanation {:?} does not hold; reasons {reasons:?}",
            case.expect.relation, case.expect.explanation
        ))
    }
}

fn mismatches(cloud: &CloudWiring) -> Vec<String> {
    let document = document();
    document
        .cases
        .iter()
        .filter_map(|case| check(case, &document.action_id, cloud).err())
        .collect()
}

#[test]
fn the_fixture_is_well_formed() {
    let document = document();
    assert_eq!(document.schema, "guard.cloud-action-local-parity.v1");
    let set = load_binding_set(BINDINGS.as_bytes()).unwrap();
    let binding = &set.get(&document.action_id).unwrap().binding;
    assert_eq!(binding.remote_mcp.as_ref().unwrap().url, ENDPOINT);
    assert_eq!(binding.remote_mcp.as_ref().unwrap().tool_name, TOOL);
    let mut ids = BTreeSet::new();
    for case in &document.cases {
        assert!(ids.insert(case.id.as_str()), "duplicate case {}", case.id);
        assert!(!case.why.trim().is_empty(), "{} has no why", case.id);
        assert!(
            document.relations.contains_key(&case.expect.relation),
            "{} names an undefined relation",
            case.id
        );
        assert!(
            case.facts
                .missing_capabilities
                .iter()
                .all(|missing| ALL_CAPABILITIES.contains(&missing.as_str())),
            "{} lists an unknown capability",
            case.id
        );
    }
    for relation in document.relations.keys() {
        assert!(
            document
                .cases
                .iter()
                .any(|case| &case.expect.relation == relation),
            "no case covers {relation}"
        );
    }
}

#[test]
fn equivalent_facts_reach_equivalent_outcomes_and_differences_are_explained() {
    assert_eq!(mismatches(&CloudWiring::faithful()), Vec::<String>::new());
}

#[test]
fn every_tool_state_and_starting_action_agrees_without_target_restrictions() {
    let wiring = CloudWiring::faithful();
    let starts = [
        GuardAction::Allow,
        GuardAction::Warn,
        GuardAction::Review,
        GuardAction::RequireReapproval,
        GuardAction::SandboxRequired,
        GuardAction::Block,
    ];
    for state in ["inherit", "allow", "review", "block"] {
        for (trust_class, extension_enabled) in [
            ("first-party", false),
            ("external", false),
            ("external", true),
        ] {
            for baseline in starts {
                let facts = Facts {
                    tool_state: state.to_owned(),
                    trust_class: trust_class.to_owned(),
                    extension_enabled,
                    baseline,
                    cloud_rule: true,
                    effect: ActionEffect::Read,
                    global_lockdown: false,
                    missing_capabilities: Vec::new(),
                };
                let result = wiring.evaluate(&document().action_id, &facts);
                assert_eq!(
                    result["action"],
                    local_action(&facts).as_str(),
                    "{state} {trust_class} enabled={extension_enabled} from {baseline:?}: {result}"
                );
            }
        }
    }
}

#[test]
fn a_wrong_mapping_fails_the_comparison() {
    // Dropping the catalog contribution loses every tightening case.
    let without_catalog = CloudWiring {
        include_catalog: false,
        ..CloudWiring::faithful()
    };
    let lost = mismatches(&without_catalog);
    assert!(
        lost.iter().any(|m| m.starts_with("block-tightens-allow:")),
        "{lost:?}"
    );
    assert!(
        lost.iter().any(|m| m.starts_with("review-tightens-warn:")),
        "{lost:?}"
    );
    // A binding compiled with the wrong effect moves the native floors.
    let wrong_effect = CloudWiring {
        effect_override: Some(ActionEffect::Write),
        ..CloudWiring::faithful()
    };
    let moved = mismatches(&wrong_effect);
    assert!(
        moved
            .iter()
            .any(|m| m.starts_with("read-floor-matches-baseline:")),
        "{moved:?}"
    );
    assert!(
        moved
            .iter()
            .any(|m| m.starts_with("admin-effect-is-never-hosted:")),
        "{moved:?}"
    );
    // A binding that stops requiring filesystem isolation lets a target
    // without it dispatch.
    let unisolated = CloudWiring {
        dropped_capability: Some("no-filesystem"),
        ..CloudWiring::faithful()
    };
    let exposed = mismatches(&unisolated);
    assert!(
        exposed
            .iter()
            .any(|m| m.starts_with("missing-filesystem-isolation:")),
        "{exposed:?}"
    );
}
