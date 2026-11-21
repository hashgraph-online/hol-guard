use crate::cloud_pack::{pack_from_value, parse_pack, PackAction};
use crate::cloud_pack_request::render;
use serde_json::{json, Value};

const NOTION: &str = include_str!("../../../../contributions/cloud-actions/notion.json");

fn action(id: &str) -> PackAction {
    parse_pack(NOTION.as_bytes())
        .unwrap()
        .actions
        .into_iter()
        .find(|action| action.action_id == id)
        .unwrap()
}

fn body(id: &str, args: Value) -> Value {
    let request = render(&action(id), &args).unwrap();
    serde_json::from_str(request.body.as_deref().unwrap()).unwrap()
}

/// The Notion pack with `id` changed by `change`, and the code validation refuses it with.
fn edited(id: &str, change: impl FnOnce(&mut Value)) -> &'static str {
    let mut pack: Value = serde_json::from_str(NOTION).unwrap();
    let action = pack["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["actionId"] == id)
        .unwrap();
    change(action);
    pack_from_value(pack).unwrap_err().code
}

const PAGE: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const SET: &str = "notion.pages.set_select";

#[test]
fn a_keyed_field_is_named_by_its_argument() {
    let value = body(
        SET,
        json!({"page_id": PAGE, "property": "Status", "option": "Done"}),
    );
    assert_eq!(
        value,
        json!({"properties": {"Status": {"select": {"name": "Done"}}}})
    );
}

#[test]
fn a_keyed_name_is_written_as_json_text() {
    let value = body(
        SET,
        json!({"page_id": PAGE, "property": "a\"}, \"archived\": true, \"x", "option": "Done"}),
    );
    let properties = value["properties"].as_object().unwrap();
    assert_eq!(properties.len(), 1);
    assert!(value.get("archived").is_none());
}

#[test]
fn keyed_fields_nest() {
    let value = body(
        "notion.databases.change_property_type",
        json!({"database_id": PAGE, "property": "Estimate", "type": "number"}),
    );
    assert_eq!(value, json!({"properties": {"Estimate": {"number": {}}}}));
}

#[test]
fn a_keyed_name_needs_a_required_bounded_pattern_argument() {
    for change in [
        (|spec: &mut Value| spec["required"] = json!(false)) as fn(&mut Value),
        |spec| {
            spec.as_object_mut().unwrap().remove("pattern");
        },
        |spec| spec["maxLength"] = json!(257),
        |spec| *spec = json!({"type": "integer", "required": true, "minimum": 0, "maximum": 9}),
    ] {
        let code = edited(SET, |action| change(&mut action["arguments"]["property"]));
        assert_eq!(code, "cloud_pack_template_key_invalid");
    }
}

#[test]
fn a_property_name_outside_its_pattern_is_refused() {
    let args = json!({"page_id": PAGE, "property": "Sta\u{7}tus", "option": "Done"});
    assert!(render(&action(SET), &args).is_err());
}
