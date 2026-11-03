use super::*;

const GUARD: &str = "/opt/guard/1.2.3/hol-guard-codex-hook --harness codex";
const UPGRADED: &str = "/opt/guard/1.2.4/hol-guard-codex-hook --harness codex";
const FOREIGN: &str = "/usr/bin/other-tool";
const CANONICAL: &str = "/home/user/.codex/config.toml";
const ALIAS: &str = "/alias/.codex/config.toml";

fn run(request: Value) -> Result<Value, String> {
    run_command(request.to_string().as_bytes())
        .map(|bytes| serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn hash(event: &str, matcher: Value, handler: Value) -> Value {
    run(json!({
        "schema": SCHEMA,
        "op": "hash",
        "event": event,
        "matcher": matcher,
        "handler": handler,
    }))
    .expect("hash answer")["hash"]
        .clone()
}

fn handler(command: &str) -> Value {
    json!({ "type": "command", "command": command, "timeout": 30 })
}

fn table(op: &str, events: Value, state: Value) -> Value {
    json!({
        "schema": SCHEMA,
        "op": op,
        "events": events,
        "state": state,
        "prefixes": [CANONICAL, ALIAS, CANONICAL],
        "guard_commands": [GUARD, UPGRADED],
    })
}

fn guard_events() -> Value {
    json!([
        ["PreToolUse", [{ "matcher": "Bash", "hooks": [handler(GUARD), { "type": "command", "command": FOREIGN }] }]],
        ["UserPromptSubmit", [{ "hooks": [handler(GUARD)] }]],
    ])
}

fn key(coordinate: &str) -> String {
    format!("{CANONICAL}:{coordinate}")
}

fn alias(coordinate: &str) -> String {
    format!("{ALIAS}:{coordinate}")
}

#[test]
fn the_hash_matches_the_one_codex_computes() {
    // Recorded from the Python port of Codex's `hook_hash`, which Codex's
    // own hash was checked against when that port was written.
    for (event, matcher, entry, expected) in [
        (
            "PreToolUse",
            json!("Bash"),
            handler(GUARD),
            "537124fb8c2e878d9af2d1ba42958a6056b9976231cfa4d7ebb2613483944418",
        ),
        (
            "UserPromptSubmit",
            json!("Bash"),
            handler("/opt/guard/hook"),
            "31cf7207a4ea5db645a167058ee99f4ed1c305442de3046f32addb60b88e3089",
        ),
        (
            "SessionEnd",
            Value::Null,
            json!({ "type": "command", "command": "/opt/guard/hook", "timeout": 99 }),
            "1fd9079929d9ad0cbd434053e9eb332387b79695a33c534e0c0dfab442d5d06a",
        ),
        (
            "SessionEnd",
            Value::Null,
            json!({ "type": "command", "command": "/opt/guard/hook" }),
            "d058b1768fecf30767a2e7b189d9fcc5b1bffed9563c6927ecc8d764a81e91c3",
        ),
        (
            "PostToolUse",
            json!("*"),
            json!({
                "type": "command",
                "command": "\u{e9} \u{1f} \"q\"",
                "statusMessage": "Checking",
                "async": true,
                "additionalContextLimit": 4000,
                "timeout": -5,
            }),
            "116ae5b40d7ed7424d6d557f8481e94cc26ff63e2d895689e1940734b53baa4a",
        ),
        (
            "Stop",
            Value::Null,
            json!({ "type": "command", "command": "x", "additionalContextLimit": 4000 }),
            "6f14477468be127a92604ce05b51030268ccd6077fa7a807515589cfcfc7fd17",
        ),
    ] {
        assert_eq!(
            hash(event, matcher, entry),
            json!(format!("sha256:{expected}")),
            "{event}"
        );
    }
}

#[test]
fn an_integer_wider_than_64_bits_keeps_its_exact_digits() {
    let request = format!(
        r#"{{"schema":"{SCHEMA}","op":"hash","event":"PostToolUse","matcher":"*","handler":{{"type":"command","command":"x","additionalContextLimit":2500,"timeout":123456789012345678901234567890}}}}"#
    );
    let answer: Value =
        serde_json::from_slice(&run_command(request.as_bytes()).expect("answer")).expect("JSON");
    assert_eq!(
        answer["hash"],
        "sha256:47ee2054a151720a61a2fbca28e28f6150d54fdcb036ae7f5926f6d5cad365f1"
    );
}

#[test]
fn handlers_codex_would_not_hash_have_no_hash() {
    for (event, entry) in [
        (
            "PreToolUse",
            json!({ "type": "command", "command": "x", "timeout": 5.0 }),
        ),
        (
            "PreToolUse",
            json!({ "type": "command", "command": "x", "timeout": true }),
        ),
        (
            "PreToolUse",
            json!({ "type": "command", "command": "x", "timeout": ["opaque"] }),
        ),
        ("PreToolUse", json!({ "type": "command", "command": "  " })),
        ("PreToolUse", json!({ "type": "prompt", "command": "x" })),
        ("Unknown", json!({ "type": "command", "command": "x" })),
    ] {
        assert_eq!(
            hash(event, json!("Bash"), entry.clone()),
            Value::Null,
            "{entry}"
        );
    }
}

#[test]
fn requests_are_validated() {
    for request in [
        json!({ "schema": "codex-hook-trust.v0", "op": "hash" }),
        json!({ "schema": SCHEMA, "op": "unknown" }),
        json!({ "schema": SCHEMA, "op": "stale", "events": [] }),
        json!({ "schema": SCHEMA, "op": "hash", "extra": true }),
    ] {
        assert_eq!(
            run(request.clone()).expect_err("refused"),
            "codex_hook_trust_request_invalid",
            "{request}"
        );
    }
}

#[test]
fn recording_trusts_only_guard_handlers_under_the_canonical_key() {
    let recorded =
        run(table("record", guard_events(), json!([]))).expect("record")["recorded"].clone();
    let pre_tool = hash("PreToolUse", json!("Bash"), handler(GUARD));
    let prompt = hash("UserPromptSubmit", Value::Null, handler(GUARD));
    assert_eq!(
        recorded,
        json!([
            [key("pre_tool_use:0:0"), null, pre_tool],
            [key("user_prompt_submit:0:0"), null, prompt],
        ])
    );
    let stale = run(table("stale", guard_events(), json!([]))).expect("stale")["stale"].clone();
    assert_eq!(
        stale,
        json!([key("pre_tool_use:0:0"), key("user_prompt_submit:0:0")])
    );
}

#[test]
fn trust_under_the_alias_alone_is_recorded_again_under_the_canonical_key() {
    let expected = hash("PreToolUse", json!("Bash"), handler(GUARD));
    let prompt = hash("UserPromptSubmit", Value::Null, handler(GUARD));
    let state = json!([
        [alias("pre_tool_use:0:0"), { "trusted_hash": expected, "note": 1 }],
        [key("user_prompt_submit:0:0"), { "trusted_hash": prompt }],
    ]);
    let stale = run(table("stale", guard_events(), state.clone())).expect("stale")["stale"].clone();
    assert_eq!(stale, json!([]));
    let recorded = run(table("record", guard_events(), state)).expect("record")["recorded"].clone();
    assert_eq!(
        recorded,
        json!([[key("pre_tool_use:0:0"), alias("pre_tool_use:0:0"), expected]])
    );
}

#[test]
fn a_hook_switched_off_keeps_that_choice_and_is_never_stale() {
    let state = json!([
        [alias("pre_tool_use:0:0"), { "enabled": false }],
        [key("user_prompt_submit:0:0"), { "trusted_hash": "sha256:old" }],
    ]);
    let recorded =
        run(table("record", guard_events(), state.clone())).expect("record")["recorded"].clone();
    assert_eq!(recorded.as_array().map(Vec::len), Some(1));
    assert_eq!(
        recorded[0][1],
        json!(key("user_prompt_submit:0:0")),
        "the existing entry is copied"
    );
    let stale = run(table("stale", guard_events(), state)).expect("stale")["stale"].clone();
    assert_eq!(stale, json!([key("user_prompt_submit:0:0")]));
}

#[test]
fn inactive_groups_and_handlers_are_left_alone() {
    let events = json!([
        ["PreToolUse", [{ "matcher": "Bash", "enabled": false, "hooks": [handler(GUARD)] }]],
        ["UserPromptSubmit", [{ "hooks": [{ "type": "command", "command": GUARD, "disabled": true }] }]],
        ["state", { "ignored": true }],
    ]);
    let recorded = run(table("record", events, json!([]))).expect("record")["recorded"].clone();
    assert_eq!(recorded, json!([]));
}

#[test]
fn a_foreign_hook_state_follows_its_handler_when_guard_groups_move() {
    let foreign =
        json!({ "matcher": "Bash", "hooks": [{ "type": "command", "command": FOREIGN }] });
    let guard = json!({ "matcher": "Bash", "hooks": [handler(GUARD)] });
    let mut request = table(
        "remap",
        json!([["PreToolUse", [foreign.clone(), guard.clone()]]]),
        json!([
            [key("pre_tool_use:1:0"), { "enabled": false }],
            ["/elsewhere/config.toml:pre_tool_use:0:0", { "enabled": false }],
        ]),
    );
    request["before_events"] = json!([["PreToolUse", [guard, foreign]]]);
    let state = run(request).expect("remap")["state"].clone();
    assert_eq!(
        state,
        json!([
            [
                "/elsewhere/config.toml:pre_tool_use:0:0",
                "/elsewhere/config.toml:pre_tool_use:0:0"
            ],
            [key("pre_tool_use:0:0"), key("pre_tool_use:1:0")],
        ])
    );
}

#[test]
fn an_upgraded_guard_handler_inherits_only_the_switched_off_choice() {
    let mut request = table(
        "remap",
        json!([["PreToolUse", [{ "matcher": "Bash", "hooks": [handler(UPGRADED)] }]]]),
        json!([[key("pre_tool_use:0:0"), { "enabled": false, "trusted_hash": "sha256:old" }]]),
    );
    request["before_events"] =
        json!([["PreToolUse", [{ "matcher": "Bash", "hooks": [handler(GUARD)] }]]]);
    let state = run(request.clone()).expect("remap")["state"].clone();
    assert_eq!(state, json!([[key("pre_tool_use:0:0"), null]]));

    request["state"] = json!([[key("pre_tool_use:0:0"), { "trusted_hash": "sha256:old" }]]);
    let state = run(request).expect("remap")["state"].clone();
    assert_eq!(state, json!([]), "stale trust is never carried over");
}

#[test]
fn no_state_means_nothing_to_remap() {
    let mut request = table("remap", guard_events(), json!([]));
    request["before_events"] = guard_events();
    assert_eq!(run(request).expect("remap")["state"], Value::Null);
}
