use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const WS: &str = "6f1c2a52-6a4e-4b8e-9f0e-3f3d6c1b2a10";
const OTHER_WS: &str = "0b6e7f8a-1c2d-4e3f-8a9b-0c1d2e3f4a5b";

fn answer(request: Value) -> Value {
    dispatch(&request).expect("answer")
}

#[test]
fn only_an_on_or_off_answer_is_a_report() {
    assert_eq!(
        answer(json!({"op": "report", "value": {"status": "on", "workspace_id": " 6F1C\u{a0}"}})),
        json!({"report": {"status": "on", "workspace_id": "6F1C"}})
    );
    assert_eq!(
        answer(
            json!({"op": "report", "value": {"status": "off", "workspace_id": "  ", "extra": 1}})
        ),
        json!({"report": {"status": "off", "workspace_id": null}})
    );
    assert_eq!(
        answer(json!({"op": "report", "value": {"status": "off", "workspace_id": 7}})),
        json!({"report": {"status": "off", "workspace_id": null}})
    );
    for value in [
        json!(null),
        json!("on"),
        json!({}),
        json!({"status": "maybe"}),
        json!({"status": "ON"}),
        json!({"status": true}),
        json!(["on"]),
    ] {
        assert_eq!(
            answer(json!({"op": "report", "value": value.clone()})),
            json!({"report": null}),
            "{value}"
        );
    }
}

#[test]
fn the_summary_separates_pairing_from_cloud_actions() {
    let on = json!({"status": "on", "workspace_id": WS});
    assert_eq!(
        answer(json!({"op": "summary", "report": on, "paired": true})),
        json!({
            "status": "on",
            "workspace_id": WS,
            "message": "Ready. Set up an AI tool with hol-guard cloud-actions ai-tools configure <ai-tool>.",
        })
    );
    assert_eq!(
        answer(
            json!({"op": "summary", "report": {"status": "off", "workspace_id": null}, "paired": true})
        ),
        json!({
            "status": "off",
            "workspace_id": null,
            "message": "Off. To turn them on, run hol-guard connect again and choose \"Let AI tools \
                        on this computer use Cloud actions\".",
        })
    );
    assert_eq!(
        answer(json!({"op": "summary", "report": null, "paired": true})),
        json!({
            "status": "unknown",
            "workspace_id": null,
            "message": "Guard Cloud did not report Cloud actions for this pairing.",
        })
    );
    assert_eq!(
        answer(json!({"op": "summary", "report": on, "paired": false})),
        json!({
            "status": "off",
            "workspace_id": null,
            "message": "This computer is not paired. Run hol-guard connect first.",
        })
    );
}

#[test]
fn another_workspace_is_a_problem_only_when_one_was_asked_for() {
    let problem = |workspace_id: Value, cloud_workspace_id: Value| {
        answer(json!({
            "op": "workspace",
            "workspace_id": workspace_id,
            "cloud_workspace_id": cloud_workspace_id,
        }))["problem"]
            .clone()
    };

    assert_eq!(
        problem(json!(OTHER_WS), json!(WS)),
        json!(format!(
            "Guard Cloud paired this computer to workspace {OTHER_WS}, not {WS}. HOL Guard \
             disconnected it before sending anything. Run hol-guard connect --cloud-workspace \
             {WS} again and pick that workspace in the browser."
        ))
    );
    assert_eq!(problem(json!(WS.to_uppercase()), json!(WS)), Value::Null);
    assert_eq!(problem(json!(OTHER_WS), Value::Null), Value::Null);
    for workspace_id in [Value::Null, json!("")] {
        let named = problem(workspace_id, json!(WS));
        assert!(named.as_str().expect("problem").starts_with(&format!(
            "Guard Cloud paired this computer to workspace unknown, not {WS}."
        )));
    }
}

#[test]
fn cloud_actions_turned_on_despite_a_decline_is_a_problem() {
    let problem = |report: Value, declined: bool| {
        answer(json!({"op": "declined", "report": report, "declined": declined}))["problem"].clone()
    };
    let on = json!({"status": "on", "workspace_id": WS});

    assert_eq!(
        problem(on.clone(), true),
        json!(
            "Cloud actions were turned on in the browser although --no-cloud-actions was set. \
             HOL Guard disconnected this computer before sending anything. Run hol-guard connect \
             --no-cloud-actions again and leave Cloud actions off in the browser."
        )
    );
    assert_eq!(
        problem(json!({"status": "off", "workspace_id": WS}), true),
        Value::Null
    );
    assert_eq!(problem(Value::Null, true), Value::Null);
    assert_eq!(problem(on, false), Value::Null);
}

#[test]
fn only_a_well_formed_request_is_answered() {
    for request in [
        json!({"op": "report"}),
        json!({"op": "summary", "report": {"status": "maybe", "workspace_id": null}, "paired": true}),
        json!({"op": "summary", "report": {"status": "on", "workspace_id": null, "x": 1}, "paired": true}),
        json!({"op": "summary", "report": null, "paired": "yes"}),
        json!({"op": "workspace", "workspace_id": 7, "cloud_workspace_id": null}),
        json!({"op": "declined", "report": null}),
        json!({"op": "record"}),
        json!([]),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
