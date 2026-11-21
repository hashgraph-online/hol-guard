//! Read-only connector setup advice for a local approval detail.

use guard_contracts::{ApprovalExtensionControlViewV1, ApprovalExtensionRecommendationSnapshotV1};
use serde_json::{json, Map, Value};

use crate::approval_extension_recommendation_op::caution_risk_classes;
use crate::approval_gate_settings::public_config_locked;
use crate::runner_sync_url::urlencode;

use super::{NativeReads, ReadConfig};

pub(super) fn recommendation(
    approval: &Map<String, Value>,
    hint: &Value,
    view: &ApprovalExtensionControlViewV1,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Value> {
    let identity = hint["identity_hash"].as_str()?;
    let request_id = eligible_request_id(approval, identity, &view.snapshot)?;
    let item = reads.store_call(
        config,
        "connector_setup_item",
        json!({
            "cli_id": hint["cli_id"],
            "identity_hash": identity,
            "cwd": config.daemon_cwd.as_deref()?,
        }),
    )?;
    if !awaiting_setup(&item, hint) {
        return None;
    }
    let scan = reads.store_call(
        config,
        "connector_group_risk_classes",
        json!({"identity_hash": identity, "risk_classes": hint["risk_classes"]}),
    )?;
    let risk_classes: Vec<String> =
        serde_json::from_value(scan.get("risk_classes")?.clone()).ok()?;
    let caution = caution_risk_classes(&risk_classes).ok()?;
    let gate = public_config_locked(config.guard_home(), None);
    Some(project(
        request_id,
        hint,
        &item,
        &view.snapshot,
        gate.configured && gate.enabled,
        caution,
        scan["complete"].as_bool()?,
    ))
}

fn eligible_request_id<'a>(
    approval: &'a Map<String, Value>,
    identity: &str,
    snapshot: &ApprovalExtensionRecommendationSnapshotV1,
) -> Option<&'a str> {
    if approval.get("status").and_then(Value::as_str) != Some("pending")
        || snapshot.layers.iter().any(|layer| layer.global_lockdown)
    {
        return None;
    }
    approval
        .get("queue_group_id")?
        .as_str()?
        .starts_with(&format!("connector:{identity}:"))
        .then(|| approval.get("request_id")?.as_str())?
}

fn awaiting_setup(item: &Value, hint: &Value) -> bool {
    item.is_object()
        && item["surface"] == hint["surface"]
        && (item["state"] == "unset"
            || (item["state"] == "allowed" && item["stale"] == true && item["surface"] == "cli"))
}

fn project(
    request_id: &str,
    hint: &Value,
    item: &Value,
    snapshot: &ApprovalExtensionRecommendationSnapshotV1,
    gate_configured: bool,
    caution: Vec<String>,
    scan_complete: bool,
) -> Value {
    let status = if snapshot.health != "protected" {
        "authority_unavailable"
    } else if !gate_configured {
        "approval_gate_required"
    } else {
        "available"
    };
    let mut setup_request = json!({
        "cli_id": hint["cli_id"],
        "identity_hash": hint["identity_hash"],
        "name": item["name"],
        "kind": item["kind"],
        "state": "allowed",
        "connector_group_request_id": request_id,
    });
    for key in ["example_label", "interpreter_name"] {
        if item[key].is_string() {
            setup_request[key] = item[key].clone();
        }
    }
    let href = hint["deep_link"].as_str().unwrap_or_default();
    let query = urlencode(&[
        ("setup".to_owned(), request_id.to_owned()),
        (
            "identity".to_owned(),
            hint["identity_hash"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        ),
    ]);
    json!({
        "schema": "guard.approval-connector-recommendation.v1",
        "status": status,
        "identity_hash": hint["identity_hash"],
        "cli_id": hint["cli_id"],
        "surface": item["surface"],
        "display_name": hint["display_name"],
        "deep_link": href,
        "setup_href": format!("{href}?{query}"),
        "card_recommendation": {"state": "allowed", "capabilities": []},
        "setup_request": setup_request,
        "approval_gate_configured": gate_configured,
        "caution": !caution.is_empty() || !scan_complete,
        "caution_risk_classes": caution,
        "revision": snapshot.revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advice_requires_a_pending_matching_group_and_respects_lockdown() {
        let mut snapshot = ApprovalExtensionRecommendationSnapshotV1 {
            health: "protected".to_owned(),
            revision: 1,
            catalog_digest: "d".to_owned(),
            layers: Vec::new(),
        };
        let row = json!({
            "request_id": "request", "status": "pending",
            "queue_group_id": "connector:identity:command",
        });
        let approval = row.as_object().unwrap();
        assert_eq!(
            eligible_request_id(approval, "identity", &snapshot),
            Some("request")
        );
        assert_eq!(eligible_request_id(approval, "ident", &snapshot), None);
        let mut resolved = approval.clone();
        resolved.insert("status".to_owned(), json!("resolved"));
        assert_eq!(eligible_request_id(&resolved, "identity", &snapshot), None);
        snapshot
            .layers
            .push(guard_contracts::NativeExtensionControlLayerV1 {
                schema_version: "v1".to_owned(),
                kind: "local".to_owned(),
                catalog_digest: "d".to_owned(),
                global_lockdown: true,
                controls: Vec::new(),
            });
        assert_eq!(eligible_request_id(approval, "identity", &snapshot), None);
    }

    #[test]
    fn stale_cli_setup_and_incomplete_risk_scans_remain_advisory() {
        let snapshot = ApprovalExtensionRecommendationSnapshotV1 {
            health: "tampered".to_owned(),
            revision: 9,
            catalog_digest: "d".to_owned(),
            layers: Vec::new(),
        };
        for (surface, state, stale, expected) in [
            ("cli", "allowed", true, true),
            ("cli", "blocked", true, false),
            ("cli", "allowed", false, false),
            ("mcp", "allowed", true, false),
            ("package-scripts", "allowed", true, false),
            ("cli", "unset", false, true),
        ] {
            assert_eq!(
                awaiting_setup(
                    &json!({"surface": surface, "state": state, "stale": stale}),
                    &json!({"surface": surface}),
                ),
                expected,
                "{surface} {state} {stale}",
            );
        }
        let hint = json!({"identity_hash": "identity", "deep_link": "/extensions/local-cli/id"});
        let result = project(
            "r +/1",
            &hint,
            &json!({}),
            &snapshot,
            true,
            Vec::new(),
            false,
        );
        assert_eq!(result["status"], "authority_unavailable");
        assert_eq!(result["caution"], true);
        assert_eq!(
            result["setup_href"],
            "/extensions/local-cli/id?setup=r+%2B%2F1&identity=identity"
        );
    }
}
