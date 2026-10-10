use serde_json::{json, Map, Value};

use super::*;
use crate::extension_control::{ControlTarget, ExtensionControl, CONTROL_SCHEMA_VERSION};
use crate::native_command_program::{ProgramMcp, ProgramMcpLaunch, ProgramMcpTool};

const PARITY: &str = include_str!("../testdata/contributed-mcp-decision-parity-v1.json");
const MATCHING: &str = include_str!("../testdata/contributed-mcp-matching-v1.json");
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

struct Owned {
    catalog_id: String,
    trust_class: String,
    mcp: ProgramMcp,
}

fn owned(value: &Value) -> Owned {
    Owned {
        catalog_id: value["catalog_id"].as_str().unwrap().to_owned(),
        trust_class: value["trust_class"].as_str().unwrap().to_owned(),
        mcp: serde_json::from_value(value["mcp"].clone()).unwrap(),
    }
}

fn borrowed(items: &[Owned]) -> Vec<Contribution<'_>> {
    items
        .iter()
        .map(|item| Contribution {
            catalog_id: &item.catalog_id,
            trust_class: &item.trust_class,
            mcp: &item.mcp,
        })
        .collect()
}

fn layers(value: &Value) -> Vec<ExtensionControlLayer> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|layer| ExtensionControlLayer {
            schema_version: CONTROL_SCHEMA_VERSION.to_owned(),
            kind: match layer["kind"].as_str().unwrap() {
                "local-admin" => ControlLayerKind::LocalAdmin,
                "signed-cloud" => ControlLayerKind::SignedCloud,
                other => panic!("unknown layer kind {other}"),
            },
            catalog_digest: ZERO_DIGEST.to_owned(),
            global_lockdown: layer["global_lockdown"].as_bool().unwrap(),
            controls: layer["controls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|control| ExtensionControl {
                    target: ControlTarget::new(
                        ControlTargetKind::Extension,
                        control["target_id"].as_str().unwrap().to_owned(),
                    )
                    .unwrap(),
                    state: match control["state"].as_str().unwrap() {
                        "enabled" => ControlState::Enabled,
                        _ => ControlState::Disabled,
                    },
                })
                .collect(),
        })
        .collect()
}

fn identity_map(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

#[test]
fn decisions_match_recorded_parity_fixture() {
    let fixture: Value = serde_json::from_str(PARITY).unwrap();
    let owned_items: Vec<Owned> = fixture["contributions"]
        .as_array()
        .unwrap()
        .iter()
        .map(owned)
        .collect();
    let contributions = borrowed(&owned_items);
    let layer_sets: std::collections::HashMap<&str, Vec<ExtensionControlLayer>> = fixture["layers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| (name.as_str(), layers(value)))
        .collect();
    let scenarios = fixture["scenarios"].as_array().unwrap();
    assert!(scenarios.len() > 10_000);
    let mut mismatches = Vec::new();
    let mut decided = 0_usize;
    for scenario in scenarios {
        let row = scenario.as_array().unwrap();
        let input = ContributedMcpInput {
            current_action: row[4].as_str().unwrap(),
            server_identity: identity_map(&row[0]),
            artifact_transport: Some(&row[1]).filter(|value| !value.is_null()),
            server_name: Some(&row[2]).filter(|value| !value.is_null()),
            tool_name: Some(&row[3]).filter(|value| !value.is_null()),
            layers: &layer_sets[row[5].as_str().unwrap()],
        };
        let outcome = decide_contributed_mcp(&contributions, &input);
        let expected = row[6].as_str();
        if outcome.map(|item| item.action) != expected {
            mismatches.push(format!("{scenario} -> {outcome:?}"));
        }
        if let Some(item) = outcome {
            decided += 1;
            assert_eq!(item.source, CONTRIBUTED_MCP_SOURCE);
        }
    }
    assert!(decided > 1_000, "fixture must exercise decided outcomes");
    assert!(
        mismatches.is_empty(),
        "{} mismatches, first: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(5)]
    );
}

fn program_item(launch: ProgramMcpLaunch, tools: &[(&str, &str)], trust: &str) -> Owned {
    Owned {
        catalog_id: "command.mcp-unit".to_owned(),
        trust_class: trust.to_owned(),
        mcp: ProgramMcp {
            surface: "mcp".to_owned(),
            mcp_launch: launch,
            mcp_tools: tools
                .iter()
                .map(|(name, state)| ProgramMcpTool {
                    name: (*name).to_owned(),
                    state: (*state).to_owned(),
                })
                .collect(),
        },
    }
}

fn launch(kind: &str, command: Option<&str>, package: Option<&str>) -> ProgramMcpLaunch {
    ProgramMcpLaunch {
        kind: kind.to_owned(),
        command: command.map(str::to_owned),
        package: package.map(str::to_owned),
        url: None,
        server_names: Vec::new(),
    }
}

fn decide_one(
    item: &Owned,
    identity: Value,
    action: &str,
    tool: &str,
    lockdown: bool,
) -> Option<&'static str> {
    let items = [Owned {
        catalog_id: item.catalog_id.clone(),
        trust_class: item.trust_class.clone(),
        mcp: ProgramMcp {
            surface: item.mcp.surface.clone(),
            mcp_launch: ProgramMcpLaunch {
                kind: item.mcp.mcp_launch.kind.clone(),
                command: item.mcp.mcp_launch.command.clone(),
                package: item.mcp.mcp_launch.package.clone(),
                url: item.mcp.mcp_launch.url.clone(),
                server_names: item.mcp.mcp_launch.server_names.clone(),
            },
            mcp_tools: item
                .mcp
                .mcp_tools
                .iter()
                .map(|t| ProgramMcpTool {
                    name: t.name.clone(),
                    state: t.state.clone(),
                })
                .collect(),
        },
    }];
    let contributions = borrowed(&items);
    let control_layers = layers(&json!([{
        "kind": "local-admin", "global_lockdown": lockdown,
        "controls": [{"target_id": "command.mcp-unit", "state": "enabled"}]
    }]));
    let tool = json!(tool);
    let input = ContributedMcpInput {
        current_action: action,
        server_identity: identity.as_object(),
        artifact_transport: None,
        server_name: None,
        tool_name: Some(&tool),
        layers: &control_layers,
    };
    decide_contributed_mcp(&contributions, &input).map(|outcome| outcome.action)
}

fn package_identity() -> Value {
    json!({"package_name": "pkg", "command": "npx", "transport": "stdio",
           "package_source": "default", "package_version": "1.0.0", "env_keys": []})
}

#[test]
fn package_allow_requires_reviewed_launcher_and_no_lockdown() {
    let item = program_item(
        launch("package-launcher", Some("npx"), Some("pkg")),
        &[("read", "allow")],
        "external",
    );
    assert_eq!(
        decide_one(&item, package_identity(), "review", "read", false),
        Some("allow")
    );
    assert_eq!(
        decide_one(&item, package_identity(), "block", "read", false),
        None
    );
    assert_eq!(
        decide_one(&item, package_identity(), "allow", "read", false),
        None
    );
    assert_eq!(
        decide_one(&item, package_identity(), "review", "read", true),
        None
    );
    let mut other_launcher = package_identity();
    other_launcher["command"] = json!("uvx");
    assert_eq!(
        decide_one(&item, other_launcher, "review", "read", false),
        None
    );
    let mut registry_env = package_identity();
    registry_env["env_keys"] = json!(["NPM_CONFIG_REGISTRY"]);
    assert_eq!(
        decide_one(&item, registry_env, "review", "read", false),
        None
    );
    let mut tarball = package_identity();
    tarball["package_version"] = json!("pkg.TGZ");
    assert_eq!(decide_one(&item, tarball, "review", "read", false), None);
}

#[test]
fn block_and_review_tighten_but_never_loosen() {
    let item = program_item(
        launch("package-launcher", Some("npx"), Some("pkg")),
        &[("drop", "block"), ("look", "review"), ("other", "inherit")],
        "external",
    );
    assert_eq!(
        decide_one(&item, package_identity(), "allow", "drop", false),
        Some("block")
    );
    assert_eq!(
        decide_one(&item, package_identity(), "block", "drop", false),
        None
    );
    assert_eq!(
        decide_one(&item, package_identity(), "warn", "look", false),
        Some("review")
    );
    assert_eq!(
        decide_one(&item, package_identity(), "review", "look", false),
        None
    );
    assert_eq!(
        decide_one(&item, package_identity(), "allow", "unlisted", false),
        None
    );
}

#[test]
fn external_contribution_needs_local_admin_enable() {
    let item = program_item(
        launch("package-launcher", Some("npx"), Some("pkg")),
        &[("drop", "block")],
        "external",
    );
    let items = borrowed(std::slice::from_ref(&item));
    let identity = package_identity();
    let tool = json!("drop");
    let input = |layers: &'static [ExtensionControlLayer]| ContributedMcpInput {
        current_action: "allow",
        server_identity: identity.as_object(),
        artifact_transport: None,
        server_name: None,
        tool_name: Some(&tool),
        layers,
    };
    assert!(decide_contributed_mcp(&items, &input(&[])).is_none());
    let first_party = Owned {
        trust_class: "first-party".to_owned(),
        catalog_id: item.catalog_id.clone(),
        mcp: ProgramMcp {
            surface: "mcp".to_owned(),
            mcp_launch: launch("package-launcher", Some("npx"), Some("pkg")),
            mcp_tools: vec![ProgramMcpTool {
                name: "drop".to_owned(),
                state: "block".to_owned(),
            }],
        },
    };
    let items = borrowed(std::slice::from_ref(&first_party));
    assert!(decide_contributed_mcp(&items, &input(&[])).is_some());
}

#[test]
fn direct_command_names_follow_python_rules() {
    for (raw, expected) in [
        ("/opt/bin/Tool.EXE", Some("tool")),
        ("C:\\bin\\tool.cmd", Some("tool")),
        ("tool.bat", Some("tool")),
        ("npx", None),
        ("python3.12", None),
        ("http://tool", None),
        ("", None),
        ("-tool", None),
        ("a..b", None),
        ("tool.", None),
    ] {
        assert_eq!(direct_mcp_command_name(raw).as_deref(), expected, "{raw}");
    }
}

fn unit_item(launch: Value, tools: Value) -> Owned {
    owned(&json!({
        "catalog_id": "command.mcp-unit",
        "trust_class": "external",
        "mcp": {"surface": "mcp", "mcp_launch": launch, "mcp_tools": tools},
    }))
}

fn enabled_unit(lockdown: bool) -> Vec<ExtensionControlLayer> {
    layers(&json!([{
        "kind": "local-admin", "global_lockdown": lockdown,
        "controls": [{"target_id": "command.mcp-unit", "state": "enabled"}]
    }]))
}

fn package_identity_for_matrix() -> Value {
    json!({"package_name": "pkg", "command": "npx", "transport": "stdio",
           "package_source": "default", "package_version": null, "env_keys": []})
}

#[test]
fn decision_table_matches_recorded_expectations() {
    let fixture: Value = serde_json::from_str(MATCHING).unwrap();
    let item = unit_item(
        json!({"kind": "package-launcher", "command": "npx", "package": "pkg"}),
        json!([
            {"name": "t_allow", "state": "allow"},
            {"name": "t_review", "state": "review"},
            {"name": "t_block", "state": "block"},
            {"name": "t_inherit", "state": "inherit"},
        ]),
    );
    let items = borrowed(std::slice::from_ref(&item));
    let identity = package_identity_for_matrix();
    let rows = fixture["decision_table"].as_array().unwrap();
    assert_eq!(rows.len(), 40);
    for row in rows {
        let state = row["state"].as_str().unwrap();
        let control_layers = enabled_unit(row["lockdown"].as_bool().unwrap());
        let tool = json!(format!("t_{state}"));
        let input = ContributedMcpInput {
            current_action: row["action"].as_str().unwrap(),
            server_identity: identity.as_object(),
            artifact_transport: None,
            server_name: None,
            tool_name: Some(&tool),
            layers: &control_layers,
        };
        let outcome = decide_contributed_mcp(&items, &input);
        assert_eq!(
            outcome.map(|item| item.action),
            row["expected"].as_str(),
            "{row}"
        );
        if let Some(outcome) = outcome {
            assert_eq!(outcome.source, fixture["source"].as_str().unwrap());
            assert_eq!(
                outcome.reason,
                fixture["reasons"][outcome.action].as_str().unwrap()
            );
        }
    }
}

#[test]
fn contribution_matching_follows_recorded_cases() {
    let fixture: Value = serde_json::from_str(MATCHING).unwrap();
    let cases = fixture["matching_cases"].as_array().unwrap();
    assert!(cases.len() > 40);
    let mut matched = 0_usize;
    for case in cases {
        let item = unit_item(case["launch"].clone(), json!([]));
        let items = borrowed(std::slice::from_ref(&item));
        let no_layers: Vec<ExtensionControlLayer> = Vec::new();
        let optional = |key: &str| Some(&case[key]).filter(|value| !value.is_null());
        let input = ContributedMcpInput {
            current_action: "allow",
            server_identity: identity_map(&case["identity"]),
            artifact_transport: optional("transport"),
            server_name: optional("server_name"),
            tool_name: optional("tool_name"),
            layers: &no_layers,
        };
        let found = matching_contribution(&items, &input).is_some();
        assert_eq!(
            found,
            case["matches"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        matched += usize::from(found);
    }
    assert!(matched > 20, "fixture must exercise matching cases");
}
