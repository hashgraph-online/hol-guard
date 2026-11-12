use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const RESOURCE: &str = "https://hol.org/api/guard/gateway/mcp";
const WS: &str = "6f1c2a52-6a4e-4b8e-9f0e-3f3d6c1b2a10";

fn answer(changes: Value) -> Value {
    let mut request = json!({
        "op": "access",
        "token": true,
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "gateway:discover gateway:invoke",
        "audience": [RESOURCE],
        "workspace": {"workspaceId": WS},
        "resource": RESOURCE,
        "workspace_id": WS,
    });
    for (key, value) in changes.as_object().expect("changes") {
        request[key] = value.clone();
    }
    request
}

fn refusal(changes: Value) -> Value {
    dispatch(&answer(changes)).expect("answer")["refused"].clone()
}

#[test]
fn cloud_actions_access_for_the_paired_workspace_is_accepted() {
    let accepted = dispatch(&answer(json!({
        "token_type": "bearer",
        "scope": " gateway:invoke\tgateway:execution.read\u{1f}gateway:invoke ",
        "audience": RESOURCE,
        "workspace": {"workspaceId": " 6F1C2A52-6A4E-4B8E-9F0E-3F3D6C1B2A10 "},
    })))
    .expect("answer");

    assert_eq!(
        accepted,
        json!({"accepted": {
            "workspace_id": WS,
            "scopes": ["gateway:invoke", "gateway:execution.read", "gateway:invoke"],
            "expires_in": 300,
        }})
    );
}

#[test]
fn any_workspace_is_accepted_when_the_pairing_names_none() {
    let accepted = dispatch(&answer(json!({
        "workspace_id": null,
        "workspace": {"workspaceId": "Other-Workspace"},
    })))
    .expect("answer");

    assert_eq!(
        accepted["accepted"]["workspace_id"],
        json!("other-workspace")
    );
}

#[test]
fn an_answer_that_is_not_cloud_actions_access_is_refused() {
    let not_access = json!("Guard Cloud's answer was not Cloud actions access.");
    for changes in [
        json!({"token": false}),
        json!({"token_type": "DPoP"}),
        json!({"token_type": null}),
        json!({"expires_in": 0}),
        json!({"expires_in": -5}),
        json!({"expires_in": 300.0}),
        json!({"expires_in": true}),
        json!({"expires_in": "300"}),
        json!({"expires_in": u64::MAX}),
    ] {
        assert_eq!(refusal(changes.clone()), not_access, "{changes}");
    }
}

#[test]
fn access_other_than_cloud_actions_is_refused() {
    let other_scope = json!("Guard Cloud granted access other than Cloud actions.");
    for changes in [
        json!({"scope": "gateway:invoke guard:sync"}),
        json!({"scope": ""}),
        json!({"scope": "   "}),
        json!({"scope": null}),
        json!({"scope": ["gateway:invoke"]}),
    ] {
        assert_eq!(refusal(changes.clone()), other_scope, "{changes}");
    }
}

#[test]
fn access_for_another_audience_or_workspace_is_refused() {
    let other_audience = json!("Guard Cloud granted access for something else.");
    for changes in [
        json!({"audience": ["https://hol.org/api/guard/sync"]}),
        json!({"audience": null}),
        json!({"audience": {"aud": RESOURCE}}),
        json!({"audience": [[RESOURCE]]}),
    ] {
        assert_eq!(refusal(changes.clone()), other_audience, "{changes}");
    }
    let other_workspace = json!("Guard Cloud granted access for another workspace.");
    for changes in [
        json!({"workspace": {"workspaceId": "11111111-1111-4111-8111-111111111111"}}),
        json!({"workspace": {}}),
        json!({"workspace": {"workspaceId": "  "}}),
        json!({"workspace": {"workspaceId": 7}}),
        json!({"workspace": WS}),
        json!({"workspace": null}),
    ] {
        assert_eq!(refusal(changes.clone()), other_workspace, "{changes}");
    }
}

#[test]
fn a_refused_exchange_names_why() {
    let cases = [
        (400, json!("invalid_grant"), "cloud_actions_not_allowed"),
        (503, json!("invalid_target"), "not_available"),
        (429, Value::Null, "cloud_unreachable"),
        (504, json!(["invalid_grant"]), "cloud_unreachable"),
        (400, json!("invalid_request"), "exchange_refused"),
    ];
    for (status, error, reason) in cases {
        let answer = dispatch(&json!({"op": "refused", "status": status, "error": error.clone()}))
            .expect("answer");
        assert_eq!(answer["reason"], json!(reason), "{status} {error}");
    }
    let not_allowed = dispatch(&json!({"op": "refused", "status": 400, "error": "invalid_grant"}))
        .expect("answer");
    assert_eq!(
        not_allowed["message"],
        json!(
            "Guard Cloud did not allow Cloud actions for this computer. Check that this computer \
             is still paired and that your role in the workspace may use Cloud actions, then run \
             hol-guard connect again and choose \"Let AI tools on this computer use Cloud actions\"."
        )
    );
    let other = dispatch(&json!({"op": "refused", "status": 418, "error": null})).expect("answer");
    assert_eq!(
        other["message"],
        json!("Guard Cloud refused Cloud actions access (HTTP 418).")
    );
}

#[test]
fn only_a_well_formed_request_is_answered() {
    let mut with_token = answer(json!({}));
    with_token["access_token"] = json!("header.claims.signature");
    let mut without_resource = answer(json!({}));
    without_resource
        .as_object_mut()
        .expect("request")
        .remove("resource");
    for request in [
        with_token,
        without_resource,
        json!({"op": "exchange"}),
        json!({"op": "refused", "status": "400", "error": null}),
        json!({"op": "refused", "status": 400}),
        json!([]),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
