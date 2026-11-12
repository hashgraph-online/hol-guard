//! Catalog MCP contributions on a remote MCP binding: they only tighten, an
//! `allow` tool state never relaxes one, and an external contribution counts
//! only once a signed activation enables it.

use super::activation::{activation_with_controls, verify};
use super::*;
use crate::cloud_action::catalog_tightening;
use crate::cloud_action_activation::VerifiedActivation;
use crate::cloud_action_binding::{AdmittedBinding, BindingSet};
use crate::contributed_mcp_decision::Contribution;
use crate::native_command_program::{ProgramMcp, ProgramMcpLaunch, ProgramMcpTool};

const SEARCH: &str = "example.docs.search";
/// The fixture's remote MCP binding calls `search_docs` here.
const ENDPOINT: &str = "https://mcp.example.invalid/v1";
const EXTERNAL: &str = "command.mcp-synthetic-remote-external";
const FIRST_PARTY: &str = "command.mcp-synthetic-remote";

fn bindings() -> BindingSet {
    load_binding_set(BINDINGS.as_bytes()).unwrap()
}

/// A `remote-http` contribution at `url` giving `search_docs` this state.
fn remote_http(url: &str, state: &str) -> ProgramMcp {
    ProgramMcp {
        surface: "mcp".to_owned(),
        mcp_launch: ProgramMcpLaunch {
            kind: "remote-http".to_owned(),
            command: None,
            package: None,
            url: Some(url.to_owned()),
            server_names: vec!["example-docs".to_owned()],
        },
        mcp_tools: [("search_docs", state), ("other", "inherit")]
            .into_iter()
            .map(|(name, state)| ProgramMcpTool {
                name: name.to_owned(),
                state: state.to_owned(),
            })
            .collect(),
    }
}

fn absent_activation() -> VerifiedActivation {
    let digest = packaged_command_program().unwrap().catalog_digest.clone();
    verify_activation(
        None,
        None,
        &ActivationContext {
            workspace_id: "ws-synthetic-1",
            catalog_digest: &digest,
            now: "2026-11-01T12:00:00Z",
        },
    )
    .unwrap()
}

fn signed_activation(controls: Value) -> VerifiedActivation {
    let (signer, signed) = activation_with_controls(controls);
    verify(&signed, &signer.public).unwrap()
}

fn tighten(
    admitted: &AdmittedBinding,
    catalog_id: &str,
    trust_class: &str,
    mcp: &ProgramMcp,
    activation: &VerifiedActivation,
    current: GuardAction,
) -> Option<GuardAction> {
    let catalog = [Contribution {
        catalog_id,
        trust_class,
        mcp,
    }];
    catalog_tightening(admitted, &catalog, activation, current)
}

#[test]
fn a_matching_contribution_tightens_a_remote_mcp_action() {
    let set = bindings();
    let search = set.get(SEARCH).unwrap();
    let none = absent_activation();
    for (state, current, expected) in [
        ("review", GuardAction::Allow, GuardAction::Review),
        ("review", GuardAction::Warn, GuardAction::Review),
        ("block", GuardAction::Allow, GuardAction::Block),
        ("block", GuardAction::Review, GuardAction::Block),
    ] {
        let mcp = remote_http(ENDPOINT, state);
        assert_eq!(
            tighten(search, FIRST_PARTY, "first-party", &mcp, &none, current),
            Some(expected),
            "{state} over {current:?}"
        );
    }
}

#[test]
fn a_contribution_never_relaxes_or_restates_the_current_action() {
    let set = bindings();
    let search = set.get(SEARCH).unwrap();
    let none = absent_activation();
    for (state, current) in [
        // A remote endpoint never takes the package-launcher allow path.
        ("allow", GuardAction::Review),
        ("allow", GuardAction::Warn),
        ("allow", GuardAction::RequireReapproval),
        ("allow", GuardAction::Block),
        ("inherit", GuardAction::Allow),
        ("inherit", GuardAction::Review),
        ("review", GuardAction::Review),
        ("review", GuardAction::Block),
        ("block", GuardAction::Block),
    ] {
        let mcp = remote_http(ENDPOINT, state);
        assert_eq!(
            tighten(search, FIRST_PARTY, "first-party", &mcp, &none, current),
            None,
            "{state} over {current:?}"
        );
    }
}

#[test]
fn an_external_contribution_tightens_only_once_a_signed_activation_enables_it() {
    let set = bindings();
    let search = set.get(SEARCH).unwrap();
    let mcp = remote_http(ENDPOINT, "block");
    let enable = json!({"extension_id": EXTERNAL, "state": "enabled"});
    let disable = json!({"extension_id": EXTERNAL, "state": "disabled"});
    let other = json!({"extension_id": "command.mcp-synthetic-other", "state": "enabled"});
    for activation in [
        absent_activation(),
        signed_activation(json!([])),
        signed_activation(json!([other])),
        signed_activation(json!([enable, disable])),
    ] {
        assert_eq!(
            tighten(
                search,
                EXTERNAL,
                "external",
                &mcp,
                &activation,
                GuardAction::Allow
            ),
            None
        );
    }
    let enabled = signed_activation(json!([enable]));
    assert_eq!(
        tighten(
            search,
            EXTERNAL,
            "external",
            &mcp,
            &enabled,
            GuardAction::Allow
        ),
        Some(GuardAction::Block)
    );
}

#[test]
fn only_a_remote_mcp_binding_at_the_contributed_endpoint_matches() {
    let set = bindings();
    let search = set.get(SEARCH).unwrap();
    let none = absent_activation();
    for url in [
        "https://mcp.example.invalid/v2",
        "https://other.example.invalid/v1",
        "https://mcp.example.invalid:8443/v1",
    ] {
        let mcp = remote_http(url, "block");
        assert_eq!(
            tighten(
                search,
                FIRST_PARTY,
                "first-party",
                &mcp,
                &none,
                GuardAction::Allow
            ),
            None,
            "{url}"
        );
    }
    let mcp = remote_http(ENDPOINT, "block");
    let native = set.get(POST).unwrap();
    assert_eq!(
        tighten(
            native,
            FIRST_PARTY,
            "first-party",
            &mcp,
            &none,
            GuardAction::Allow
        ),
        None
    );
}
