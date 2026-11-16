//! Pinned catalog identity is recognition, never package authenticity.
use super::*;
use crate::mcp_decision::build_mcp_server_identity;

fn rei() -> Owned {
    let payload: Value = serde_json::from_str(include_str!(
        "../../../../contributions/mcp-servers/mcp.rei-skills.json"
    ))
    .unwrap();
    assert_eq!(payload["trustClass"], "external");
    assert_eq!(payload["activation"], "opt-in");
    assert_eq!(payload["launch"]["package"], "rei-skills@6.2.0");
    owned(&json!({
        "catalog_id": "command.mcp-unit", "trust_class": payload["trustClass"],
        "mcp": {"surface": "mcp", "mcp_launch": payload["launch"], "mcp_tools": payload["tools"]}
    }))
}

fn identity(args: &[&str]) -> Value {
    let args = args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let identity = build_mcp_server_identity("", "npx", &args, "stdio", None, &[]);
    json!({"command": identity.command, "transport": identity.transport,
        "package_name": identity.package_name, "package_version": identity.package_version,
        "package_source": identity.package_source, "env_keys": identity.env_keys})
}

#[test]
fn pinned_rei_launch_tightens_install_and_unknown_tools_for_all_versions() {
    let item = rei();
    for selector in ["rei-skills@6.2.0", "rei-skills", "rei-skills@6.3.0"] {
        let identity = identity(&["-y", selector, "mcp"]);
        assert_eq!(identity["package_name"], "rei-skills");
        for lockdown in [false, true] {
            for tool in ["rei_install_skill", "unlisted_tool"] {
                for action in ["allow", "warn"] {
                    assert_eq!(
                        decide_one(&item, identity.clone(), action, tool, lockdown),
                        Some("review"),
                        "{selector} {tool} {action} {lockdown}"
                    );
                }
                for action in ["review", "require-reapproval", "block"] {
                    assert_eq!(
                        decide_one(&item, identity.clone(), action, tool, lockdown),
                        None
                    );
                }
            }
            for tool in item.mcp.mcp_tools.iter().filter(|t| t.state == "inherit") {
                assert_eq!(
                    decide_one(&item, identity.clone(), "review", &tool.name, lockdown),
                    None
                );
            }
        }
    }
}

#[test]
fn pinned_rei_is_inert_without_local_admin_enable_or_when_disabled() {
    let item = rei();
    let items = borrowed(std::slice::from_ref(&item));
    let identity = identity(&["-y", "rei-skills@6.2.0", "mcp"]);
    let tool = json!("rei_install_skill");
    for control_layers in [
        vec![],
        layers(&json!([{
            "kind": "signed-cloud", "global_lockdown": false,
            "controls": [{"target_id": "command.mcp-unit", "state": "enabled"}]
        }])),
        layers(&json!([{
            "kind": "local-admin", "global_lockdown": false,
            "controls": [{"target_id": "command.mcp-unit", "state": "enabled"}]
        }, {
            "kind": "signed-cloud", "global_lockdown": false,
            "controls": [{"target_id": "command.mcp-unit", "state": "disabled"}]
        }])),
    ] {
        let input = ContributedMcpInput {
            current_action: "allow",
            server_identity: identity.as_object(),
            artifact_transport: None,
            server_name: None,
            tool_name: Some(&tool),
            layers: &control_layers,
        };
        assert!(decide_contributed_mcp(&items, &input).is_none());
    }
}

#[test]
fn pinned_package_allow_requires_the_declared_selector_and_existing_source_checks() {
    // Synthetic allow row probes the shared boundary; REI declares no allow rows.
    let item = program_item(
        launch("package-launcher", Some("npx"), Some("rei-skills@6.2.0")),
        &[("read", "allow"), ("other", "review")],
        "external",
    );
    assert_eq!(
        decide_one(
            &item,
            identity(&["-y", "rei-skills@6.2.0", "mcp"]),
            "review",
            "read",
            false
        ),
        Some("allow")
    );
    for args in [
        vec!["-y", "rei-skills", "mcp"],
        vec!["-y", "rei-skills@6.3.0", "mcp"],
        vec!["-y", "other-package@6.2.0", "mcp"],
        vec!["-y", "rei-skills@npm:other-package@6.2.0", "mcp"],
        vec!["-y", "alias@npm:rei-skills@6.2.0", "mcp"],
        vec!["-y", "rei-skills@", "mcp"],
        vec!["-y", "rei-skills@@6.2.0", "mcp"],
        vec!["-y", "rei-skills@file:../local", "mcp"],
        vec![
            "-y",
            "--registry",
            "https://registry.example",
            "rei-skills@6.2.0",
            "mcp",
        ],
        vec![
            "-y",
            "--userconfig",
            "/tmp/npmrc",
            "rei-skills@6.2.0",
            "mcp",
        ],
    ] {
        assert_eq!(
            decide_one(&item, identity(&args), "review", "read", false),
            None,
            "{args:?}"
        );
    }
    for (key, value) in [
        ("transport", json!("http")),
        ("transport", Value::Null),
        ("command", json!("uvx")),
        ("package_name", Value::Null),
        ("package_source", json!("custom")),
        ("env_keys", json!(["NPM_CONFIG_REGISTRY"])),
    ] {
        let mut id = identity(&["-y", "rei-skills@6.2.0", "mcp"]);
        id[key] = value;
        assert_eq!(
            decide_one(&item, id, "review", "read", false),
            None,
            "{key}"
        );
    }
    assert_eq!(
        decide_one(&item, Value::Null, "review", "read", false),
        None
    );
    assert_eq!(
        decide_one(
            &item,
            identity(&["-y", "rei-skills@6.2.0", "mcp"]),
            "review",
            "read",
            true
        ),
        None
    );
}

#[test]
fn pinned_catalog_does_not_claim_another_package() {
    for selector in [
        "different-package@6.2.0",
        "alias@npm:rei-skills@6.2.0",
        "rei-skills@@6.2.0",
        "https://example.com/rei-skills.tgz",
    ] {
        assert_eq!(
            decide_one(
                &rei(),
                identity(&["-y", selector, "mcp"]),
                "allow",
                "rei_install_skill",
                false
            ),
            None,
            "{selector}"
        );
    }
}
