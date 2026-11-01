use super::prepare_payload;
use crate::hook_adapter_value::{OMap, OValue};

fn payload(entries: &[(&str, &str)]) -> OMap {
    let mut map = OMap::new();
    map.insert("hook_event_name", OValue::str("PreToolUse"));
    for (key, value) in entries {
        map.insert(key, OValue::str(*value));
    }
    map.insert("tool_input", OValue::Map(OMap::new()));
    map
}

fn names(prepared: &OMap) -> Vec<(&str, &str)> {
    ["tool_name", "toolName", "toolname", "tool"]
        .into_iter()
        .filter_map(|key| Some((key, prepared.get_str(key)?)))
        .collect()
}

#[test]
fn a_harness_spelling_of_the_same_tool_takes_the_canonical_name() {
    for harness in ["grok", "zcode"] {
        let prepared = prepare_payload(
            harness,
            &payload(&[("toolName", "run_terminal_command")]),
            None,
        )
        .unwrap();
        assert_eq!(
            names(&prepared),
            [("tool_name", "Bash"), ("toolName", "Bash")],
            "{harness}"
        );
    }
}

#[test]
fn every_spelling_that_names_the_tool_agrees_after_prepare() {
    let prepared = prepare_payload(
        "grok",
        &payload(&[
            ("tool_name", "run_terminal_command"),
            ("toolName", "Run_Terminal_Command"),
            ("tool", "Bash"),
        ]),
        None,
    )
    .unwrap();
    assert_eq!(
        names(&prepared),
        [
            ("tool_name", "Bash"),
            ("toolName", "Bash"),
            ("tool", "Bash")
        ]
    );
}

#[test]
fn a_spelling_that_names_another_tool_is_left_for_the_ambiguity_check() {
    for harness in ["grok", "zcode"] {
        let prepared = prepare_payload(
            harness,
            &payload(&[
                ("tool_name", "read_file"),
                ("toolName", "run_terminal_command"),
                ("tool", "write_file"),
            ]),
            None,
        )
        .unwrap();
        let tool = if harness == "grok" { "Edit" } else { "Write" };
        assert_eq!(
            names(&prepared),
            [
                ("tool_name", "Read"),
                ("toolName", "run_terminal_command"),
                ("tool", "write_file"),
            ],
            "{harness} must not rewrite a {tool} spelling as Read"
        );
    }
}

#[test]
fn a_qualified_mcp_name_and_its_spelling_both_become_the_mcp_tool() {
    let prepared = prepare_payload(
        "grok",
        &payload(&[
            ("tool_name", "lean-ctx__ctx_call"),
            ("toolName", "lean-ctx__ctx_call"),
        ]),
        None,
    )
    .unwrap();
    assert_eq!(
        names(&prepared),
        [("tool_name", "MCPTool"), ("toolName", "MCPTool")]
    );
    assert_eq!(
        prepared.get_str("original_tool_name"),
        Some("lean-ctx__ctx_call")
    );
}

#[test]
fn a_non_string_tool_value_is_left_alone() {
    let mut sent = payload(&[("toolName", "read_file")]);
    let mut nested = OMap::new();
    nested.insert("name", OValue::str("run_terminal_command"));
    sent.insert("tool", OValue::Map(nested.clone()));
    let prepared = prepare_payload("grok", &sent, None).unwrap();
    assert_eq!(prepared.get("tool"), Some(&OValue::Map(nested)));
    assert_eq!(prepared.get_str("toolName"), Some("Read"));
}

#[test]
fn a_devin_mcp_dispatch_names_the_call_it_carries_under_every_spelling() {
    let mut call = OMap::new();
    call.insert("server_name", OValue::str("s"));
    call.insert("tool_name", OValue::str("t"));
    call.insert("arguments", OValue::Map(OMap::new()));
    let mut sent = payload(&[
        ("tool_name", "mcp_call_tool"),
        ("toolName", "MCP_CALL_TOOL"),
    ]);
    sent.insert("tool_input", OValue::Map(call));
    let prepared = prepare_payload("devin", &sent, None).unwrap();
    assert_eq!(
        names(&prepared),
        [("tool_name", "mcp__s__t"), ("toolName", "mcp__s__t")]
    );
}

#[test]
fn a_kimi_prompt_joins_its_text_parts_and_keeps_anything_else() {
    fn part(key: &str, value: &str) -> OValue {
        let mut item = OMap::new();
        item.insert("role", OValue::str("user"));
        item.insert(key, OValue::str(value));
        OValue::Map(item)
    }
    fn with_prompt(prompt: OValue) -> OMap {
        let mut map = OMap::new();
        map.insert("hook_event_name", OValue::str("UserPromptSubmit"));
        map.insert("prompt", prompt);
        map
    }

    let parts = OValue::List(vec![part("text", "Hello"), part("text", "World")]);
    let prepared = prepare_payload("kimi", &with_prompt(parts.clone()), None).unwrap();
    assert_eq!(prepared.get("prompt"), Some(&OValue::str("Hello\nWorld")));

    let images = OValue::List(vec![part("image_url", "data:image/png;base64,AAAA")]);
    let prepared = prepare_payload("kimi", &with_prompt(images.clone()), None).unwrap();
    assert_eq!(prepared.get("prompt"), Some(&images));

    let plain = OValue::str("plain text");
    let prepared = prepare_payload("kimi", &with_prompt(plain.clone()), None).unwrap();
    assert_eq!(prepared.get("prompt"), Some(&plain));

    let prepared = prepare_payload("codex", &with_prompt(parts.clone()), None).unwrap();
    assert_eq!(prepared.get("prompt"), Some(&parts));
}
