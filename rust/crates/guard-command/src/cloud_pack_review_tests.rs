use crate::cloud_pack::{pack_from_value, parse_pack};
use crate::cloud_pack_diff::diff;
use crate::cloud_pack_request::{render, MAX_BODY_BYTES};
use serde_json::{json, Value};

const NOTION: &str = include_str!("../../../../contributions/cloud-actions/notion.json");
const SLACK: &str = include_str!("../../../../contributions/cloud-actions/slack.json");

fn action_mut<'a>(pack: &'a mut Value, id: &str) -> &'a mut Value {
    pack["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["actionId"] == id)
        .unwrap()
}

#[test]
fn diff_reports_a_lowered_response_list_limit() {
    let old = parse_pack(SLACK.as_bytes()).unwrap();
    let mut lowered = serde_json::from_str::<Value>(SLACK).unwrap();
    action_mut(&mut lowered, "slack.conversations.list")["response"]["fields"][0]["value"]
        ["list"]["maxItems"] = json!(50);
    let report = diff(&old, &pack_from_value(lowered).unwrap()).unwrap();
    let codes: Vec<_> = report
        .changes
        .iter()
        .map(|change| (change.code, change.widening))
        .collect();
    assert!(!report.widening);
    assert_eq!(codes, vec![("response_limit_lowered", false)]);
}

#[test]
fn an_array_argument_may_accept_an_empty_list() {
    let mut pack = serde_json::from_str::<Value>(NOTION).unwrap();
    action_mut(&mut pack, "notion.blocks.children.append")["arguments"]["paragraphs"]["minItems"] =
        json!(0);
    assert!(pack_from_value(pack.clone()).is_ok());
    action_mut(&mut pack, "notion.blocks.children.append")["arguments"]["paragraphs"]["maxItems"] =
        json!(0);
    assert_eq!(
        pack_from_value(pack).unwrap_err().code,
        "cloud_pack_argument_bounds_invalid"
    );
}

#[test]
fn an_error_fixture_cannot_carry_a_projection_it_never_checks() {
    let mut pack = serde_json::from_str::<Value>(SLACK).unwrap();
    let action = action_mut(&mut pack, "slack.chat.post_message");
    let fixture = action["fixtures"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|fixture| fixture["expect"]["error"].is_string())
        .unwrap();
    fixture["expect"]["response"] = json!("{\"ok\": true}");
    fixture["expect"]["projection"] = json!({});
    assert_eq!(
        pack_from_value(pack).unwrap_err().code,
        "cloud_pack_fixtures_invalid"
    );
}

#[test]
fn a_body_that_repeats_an_argument_per_element_is_bounded() {
    let mut pack = serde_json::from_str::<Value>(NOTION).unwrap();
    let action = action_mut(&mut pack, "notion.blocks.children.append");
    action["arguments"]["paragraphs"]["maxItems"] = json!(40);
    action["executor"]["request"]["body"]["object"][0]["value"]["each"]["item"] =
        json!({"arg": "paragraphs"});
    let pack = pack_from_value(pack).unwrap();
    let action = pack.action("notion.blocks.children.append").unwrap();
    let paragraphs: Vec<String> = (0..40).map(|_| "p".repeat(2_000)).collect();
    let args = json!({
        "page_id": "0123456789abcdef0123456789abcdef",
        "paragraphs": paragraphs,
    });
    const _: () = assert!(40 * 40 * 2_000 > MAX_BODY_BYTES);
    assert_eq!(render(action, &args).unwrap_err().code, "render_refused");
}
