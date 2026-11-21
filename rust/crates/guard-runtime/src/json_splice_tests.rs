use crate::hook_removal_prune::write_indented;
use crate::json_splice::{document, preserve};
use crate::pyjson::{self, PyVal};

const CLAUDE_SEED: &str = "{\n  \"theme\": \"dark\",\n  \"env\": {\"SYNTHETIC_FLAG\": \"1\"},\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\"matcher\": \"Bash\", \"hooks\": [{\"type\": \"command\", \"command\": \"echo user-owned-hook\"}]}\n    ]\n  }\n}\n";
const JSON_SEED: &str =
    "{\n  \"syntheticUserSetting\": \"keep-me\",\n  \"nested\": {\"value\": 1}\n}\n";

fn render(value: &PyVal) -> String {
    let mut out = Vec::new();
    write_indented(value, 0, &mut out).expect("renders");
    String::from_utf8(out).expect("utf-8")
}

fn value(text: &str) -> PyVal {
    pyjson::parse(text).expect("json")
}

fn entries(value: &mut PyVal) -> &mut Vec<(String, PyVal)> {
    match value {
        PyVal::Dict(entries) => entries,
        _ => panic!("not an object"),
    }
}

fn member<'a>(value: &'a mut PyVal, key: &str) -> &'a mut PyVal {
    entries(value)
        .iter_mut()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
        .expect("member")
}

fn list(value: &mut PyVal) -> &mut Vec<PyVal> {
    match value {
        PyVal::List(items) => items,
        _ => panic!("not a list"),
    }
}

fn guard_handler() -> PyVal {
    value(r#"{"type": "command", "command": "hol-guard hook # managed", "timeout": 30}"#)
}

/// Install then uninstall, each one a render spliced over the file on disk.
fn round_trip(seed: &str, install: impl Fn(&mut PyVal), uninstall: impl Fn(&mut PyVal)) -> String {
    let mut installed = value(seed);
    install(&mut installed);
    let installed_text = document(Some(seed), &render(&installed), "\n");
    assert_eq!(value(&installed_text), installed, "install keeps its value");
    let mut removed = value(&installed_text);
    uninstall(&mut removed);
    let removed_text = document(Some(&installed_text), &render(&removed), "\n");
    assert_eq!(value(&removed_text), removed, "uninstall keeps its value");
    removed_text
}

#[test]
fn claude_install_and_uninstall_give_back_the_seed_bytes() {
    let restored = round_trip(
        CLAUDE_SEED,
        |payload| {
            let hooks = member(payload, "hooks");
            let pre = list(member(hooks, "PreToolUse"));
            let user_group = &mut pre[0];
            list(member(user_group, "hooks")).push(guard_handler());
            pre.push(value(
                r#"{"matcher": "*", "hooks": [{"type": "command", "command": "g"}]}"#,
            ));
            entries(hooks).push(("PostToolUse".to_owned(), value(r#"[{"hooks": []}]"#)));
            entries(hooks).push(("SessionStart".to_owned(), value(r#"[{"hooks": []}]"#)));
        },
        |payload| {
            let hooks = member(payload, "hooks");
            entries(hooks).retain(|(key, _)| key == "PreToolUse");
            let pre = list(member(hooks, "PreToolUse"));
            pre.truncate(1);
            list(member(&mut pre[0], "hooks")).truncate(1);
        },
    );
    assert_eq!(restored, CLAUDE_SEED);
}

#[test]
fn added_top_level_keys_are_removed_with_their_whitespace() {
    let restored = round_trip(
        JSON_SEED,
        |payload| {
            entries(payload).push(("mcp".to_owned(), value("{}")));
            entries(payload).push(("plugins".to_owned(), value("{}")));
            entries(payload).push((
                "hooks".to_owned(),
                value(r#"{"enabled": true, "events": {"PreToolUse": [{"hooks": [{"command": "g"}]}]}}"#),
            ));
        },
        |payload| {
            entries(payload)
                .retain(|(key, _)| !matches!(key.as_str(), "mcp" | "plugins" | "hooks"));
        },
    );
    assert_eq!(restored, JSON_SEED);
}

#[test]
fn unchanged_members_keep_their_bytes_beside_a_change() {
    let original = "{\"a\":[1,2,  3],  \"b\" : {\"x\":true}}";
    let mut changed = value(original);
    *member(member(&mut changed, "b"), "x") = PyVal::Bool(false);
    let spliced = preserve(original, &render(&changed)).expect("splices");
    assert_eq!(spliced, "{\"a\":[1,2,  3],  \"b\" : {\"x\":false}}");
}

#[test]
fn a_new_member_in_an_empty_object_takes_the_render() {
    let original = "{}\n";
    let mut changed = value(original);
    entries(&mut changed).push(("hooks".to_owned(), value("{}")));
    let spliced = preserve(original, &render(&changed)).expect("splices");
    assert_eq!(spliced, "{\n  \"hooks\": {}\n}\n");
}

#[test]
fn an_emptied_object_closes_with_the_original_whitespace() {
    let original = "{\n  \"hooks\": {\"PreToolUse\": []}\n}\n";
    let mut changed = value(original);
    entries(&mut changed).clear();
    let spliced = preserve(original, &render(&changed)).expect("splices");
    assert_eq!(value(&spliced), changed);
}

#[test]
fn reordered_keys_fall_back_to_the_render_for_that_object() {
    let original = "{\"outer\": {\"a\": 1, \"b\": 2}, \"keep\": [1,2]}";
    let mut changed = value(original);
    entries(member(&mut changed, "outer")).reverse();
    let spliced = preserve(original, &render(&changed)).expect("splices");
    assert_eq!(value(&spliced), changed);
    assert!(spliced.ends_with("\"keep\": [1,2]}"));
}

#[test]
fn duplicate_keys_and_invalid_text_are_never_spliced() {
    let rendered = render(&value("{\"a\": 1}"));
    assert_eq!(preserve("{\"a\": 1, \"a\": 1}", &rendered), None);
    assert_eq!(preserve("not json", &rendered), None);
    assert_eq!(
        document(Some("not json"), &rendered, "\n"),
        format!("{rendered}\n")
    );
    assert_eq!(document(None, &rendered, ""), rendered);
}

#[test]
fn escaped_and_raw_text_compare_by_value() {
    let original = "{\"name\": \"caf\u{e9}\", \"n\": 1.50, \"x\": 1}";
    let mut changed = value(original);
    entries(&mut changed).retain(|(key, _)| key != "x");
    let spliced = preserve(original, &render(&changed)).expect("splices");
    assert_eq!(spliced, "{\"name\": \"caf\u{e9}\", \"n\": 1.50}");
}

#[test]
fn array_elements_removed_from_the_middle_take_their_lead() {
    let original = "[\n  1,\n  2,\n  3\n]";
    let mut changed = value(original);
    list(&mut changed).remove(1);
    let spliced = preserve(original, &render(&changed)).expect("splices");
    assert_eq!(spliced, "[\n  1,\n  3\n]");
}

#[test]
fn whitespace_inside_an_empty_object_survives_install_and_uninstall() {
    for seed in ["{ }\n", "{\t}", "[ ]"] {
        let restored = round_trip(
            seed,
            |payload| match payload {
                PyVal::Dict(entries) => entries.push((
                    "hooks".to_owned(),
                    value(r#"{"PreToolUse": [{"hooks": [{"command": "g"}]}]}"#),
                )),
                PyVal::List(items) => items.push(guard_handler()),
                _ => panic!("container"),
            },
            |payload| match payload {
                PyVal::Dict(entries) => entries.clear(),
                PyVal::List(items) => items.clear(),
                _ => panic!("container"),
            },
        );
        assert_eq!(restored, seed);
    }
}

#[test]
fn an_empty_object_without_inner_whitespace_takes_the_render_when_filled() {
    let restored = round_trip(
        "{}\n",
        |payload| entries(payload).push(("hooks".to_owned(), value("{}"))),
        |payload| entries(payload).clear(),
    );
    assert_eq!(restored, "{}\n");
}
