//! The tool policy pass of one relay decision, with its saved lookups read
//! from the store as the proxy reads them.

use super::provider;
use super::store;
use super::POLICY_NEED;
use crate::mcp_tool_policy_decision::Decision;
use crate::mcp_tool_policy_flow::{evaluate_pass, Ctx, Pass, PassMemo, Phase, Stop};
use guard_contracts::McpToolPolicyObservationV1;
use rusqlite::Connection;
use serde_json::{json, Value};

/// Saved lookups one decision may name before it is left to the proxy.
const MAX_POLICY_ROUNDS: usize = 8;
const POLICY_FAILED: &str = "mcp_relay_policy_failed";

/// Run the tool policy, answering each saved lookup it names from the store:
/// the saved rows when there are any, the empty store's answer otherwise.
/// Each round replays the pass over the same subject, so the parts no
/// observation steers are evaluated once for the call.
///
/// A provider lookup is read from the connection rather than from the saved
/// rows: a store that holds no saved policy at all can still hold the
/// provider grants and the catalogue hash a reviewed provider action is
/// steered by.
pub(super) fn run_policy(
    subject: &guard_contracts::McpToolPolicySubjectV1,
    saved: Option<&store::Saved<'_>>,
    connection: Option<&Connection>,
    catalog: &crate::contributed_mcp_decision_op::Catalog<'_>,
) -> Result<Decision, &'static str> {
    let mut observations: Vec<McpToolPolicyObservationV1> = Vec::new();
    let memo = PassMemo::with_catalog(subject, catalog);
    for _ in 0..MAX_POLICY_ROUNDS {
        let ctx = Ctx {
            observations: &observations,
            lookup: None,
            memo: Some(&memo),
            catalog: Some(catalog),
        };
        match evaluate_pass(&ctx, subject, Phase::Initial, false) {
            Ok(Pass::Final(decision)) => return Ok(*decision),
            Ok(Pass::Claimed { .. }) | Err(Stop::Fail(_)) => return Err(POLICY_FAILED),
            Err(Stop::Need(need)) => {
                let result = match provider::answer(connection, &need) {
                    Some(answer) => answer?,
                    None => match saved {
                        Some(saved) => saved.answer(&need)?,
                        None => empty_store_answer(&need)?,
                    },
                };
                observations.push(McpToolPolicyObservationV1 { need, result });
            }
        }
    }
    Err(POLICY_NEED)
}

/// What the proxy observes for a saved lookup against a store with no saved
/// policy rows and no one-shot approvals. Any other effect defers.
pub(super) fn empty_store_answer(need: &Value) -> Result<Value, &'static str> {
    match need.get("kind").and_then(Value::as_str) {
        Some("grant_lookup") => Ok(json!({"decision": null})),
        Some("policy_lookup") => Ok(json!({
            "decision": null,
            "ignored_local_integrity": false,
            "reuse_diagnostic": {"reason": null},
        })),
        _ => Err(POLICY_NEED),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn relay_policy_uses_the_captured_active_mcp_collection() {
        use crate::contributed_mcp_decision_op::Catalog;
        use guard_contracts::{
            LocalMcpServerMaterialV1, McpExtensionInputV1, McpToolPolicySubjectV1,
        };
        use serde_json::{json, Value};
        let home =
            std::env::temp_dir().join(format!("hol-guard-mcp-relay-active-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let home = home.canonicalize().unwrap();
        let controls = crate::contributed_mcp_catalog_test_support::controls(&home, false);
        let document: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/mcp_tool_policy/parity_vectors.json"
        ))
        .unwrap();
        let mut subject: McpToolPolicySubjectV1 =
            serde_json::from_value(document["subjects"]["r0"].clone()).unwrap();
        subject.extension = Some(McpExtensionInputV1 {
            store_path:home.join("guard.db").to_string_lossy().into_owned(),guard_home:home.to_string_lossy().into_owned(),
            harness:"codex".into(),tool_name:"write_file".into(),server:LocalMcpServerMaterialV1::default(),
            connection_identity_hash:None,tool_authority_hash:None,launcher_path:None,launcher_home:None,local_unavailable:false,
            server_identity:json!({"package_name":"@modelcontextprotocol/server-filesystem","command":"npx","transport":"stdio",
                "package_source":"default","package_version":null,"env_keys":[]}).as_object().cloned(),
            artifact_transport:None,server_name:None,contributed_tool_name:Some(json!("write_file")),
            layers:vec![],layers_unavailable:true,
        });
        let active = Catalog {
            guard_home: home.to_str().unwrap(),
            controls: Some(&controls),
        };
        let inactive = Catalog {
            guard_home: home.to_str().unwrap(),
            controls: None,
        };
        assert_eq!(
            super::run_policy(&subject, None, None, &active)
                .unwrap()
                .to_value()["action"],
            "block"
        );
        assert_ne!(
            super::run_policy(&subject, None, None, &inactive)
                .unwrap()
                .to_value()["action"],
            "block"
        );
    }
}
