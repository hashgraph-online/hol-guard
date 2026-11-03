//! Replays `install_plan_vectors.json`, recorded from the original Python
//! install helpers, through the native kind. Every object in the vectors is
//! written as `{"o": [[key, value], ...]}` so key order survives; the answer's
//! build specs are evaluated here over those ordered objects, the way the
//! Python shim evaluates them over its own dicts.

use serde_json::{json, Map, Value};

use crate::opencode_install_plan::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/opencode/install_plan_vectors.json");
const SCHEMA: &str = "guard-opencode-install-plan-vectors.v1";
const RECORDED_CASES: usize = 22;
/// The recorder's stand-in for the workspace directory.
const WORKSPACE: &str = "nonexistent-guard/work";

/// The plain JSON of an ordered value.
fn plain(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut map = Map::new();
            for pair in object["o"].as_array().expect("ordered pairs") {
                map.insert(pair[0].as_str().expect("key").to_owned(), plain(&pair[1]));
            }
            Value::Object(map)
        }
        Value::Array(items) => Value::Array(items.iter().map(plain).collect()),
        other => other.clone(),
    }
}

/// The ordered value at `path` of the ordered request.
fn resolve(request: &Value, path: &Value) -> Value {
    let mut current = request.clone();
    for step in path.as_array().expect("path") {
        let next = match step {
            Value::String(key) => current["o"]
                .as_array()
                .expect("object step")
                .iter()
                .find(|pair| pair[0] == *key)
                .map(|pair| pair[1].clone())
                .expect("key present"),
            Value::Number(number) => {
                let index = usize::try_from(number.as_u64().expect("index")).expect("usize");
                current[index].clone()
            }
            _ => panic!("bad path step {step}"),
        };
        current = next;
    }
    current
}

/// Assign `key` with Python's dict order.
fn assign(pairs: &mut Vec<(String, Value)>, key: &str, item: Value) {
    match pairs.iter().position(|(name, _)| name == key) {
        Some(index) => pairs[index].1 = item,
        None => pairs.push((key.to_owned(), item)),
    }
}

fn ordered(pairs: Vec<(String, Value)>) -> Value {
    let list: Vec<Value> = pairs
        .into_iter()
        .map(|(key, item)| json!([key, item]))
        .collect();
    json!({ "o": list })
}

/// Evaluate one build spec into an ordered value.
fn build(request: &Value, spec: &Value) -> Value {
    let tag = spec[0].as_str().expect("spec tag");
    match tag {
        "value" => {
            assert!(!spec[1].is_object(), "a literal is never an object");
            spec[1].clone()
        }
        "ref" => resolve(request, &spec[1]),
        "object" => {
            let mut pairs: Vec<(String, Value)> = Vec::new();
            for pair in spec[1].as_array().expect("object pairs") {
                let key = pair[0].as_str().expect("object key");
                let item = build(request, &pair[1]);
                assign(&mut pairs, key, item);
            }
            ordered(pairs)
        }
        "merge" => {
            let mut pairs: Vec<(String, Value)> = Vec::new();
            for part in spec[1].as_array().expect("merge parts") {
                let built = build(request, part);
                for pair in built["o"].as_array().expect("merge part object") {
                    let key = pair[0].as_str().expect("merged key");
                    assign(&mut pairs, key, pair[1].clone());
                }
            }
            ordered(pairs)
        }
        "launch" => {
            let index = usize::try_from(spec[1].as_u64().expect("server")).expect("usize");
            let servers = resolve(request, &json!(["servers"]));
            let name = resolve(&servers[index], &json!(["name"]));
            let workspace = match spec[2].as_str().expect("launch kind") {
                "companion" => "",
                "override" => {
                    let enabled = resolve(request, &json!(["workspace"]));
                    if enabled == json!(true) {
                        WORKSPACE
                    } else {
                        ""
                    }
                }
                other => panic!("bad launch kind {other}"),
            };
            json!(["relay", "guard-cli", "opencode-mcp-proxy", name, workspace])
        }
        other => panic!("bad spec tag {other}"),
    }
}

/// The answer as the recorder wrote it.
fn evaluated(request: &Value, answer: &Value) -> Value {
    let mut pairs: Vec<(String, Value)> = Vec::new();
    assign(&mut pairs, "managed", answer["managed"].clone());
    assign(&mut pairs, "skipped", answer["skipped"].clone());
    for key in ["permission", "mcp", "overlay"] {
        assign(&mut pairs, key, build(request, &answer[key]));
    }
    ordered(pairs)
}

#[test]
fn replays_every_recorded_plan() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], SCHEMA);
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), RECORDED_CASES);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let request = &case["request"];
        let answer = dispatch(&plain(request)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let keys: Vec<&String> = answer.as_object().expect("answer").keys().collect();
        assert_eq!(
            keys,
            ["managed", "mcp", "overlay", "permission", "skipped"],
            "{name}"
        );
        assert_eq!(evaluated(request, &answer), case["expect"], "{name}");
    }
}

fn server(name: &str) -> Value {
    json!({
        "name": name,
        "source_scope": "global",
        "command": "node",
        "args": [],
        "env": {},
        "enabled": true,
        "proxy_environment": {},
        "source": null,
    })
}

fn request() -> Value {
    json!({
        "op": "plan",
        "workspace": false,
        "servers": [server("a")],
        "skipped": [],
        "artifacts": [],
        "workspace_servers": [],
        "permission": null,
        "mcp": {"x": {"command": ["y"]}},
        "mcp_keys": ["x"],
    })
}

#[test]
fn a_user_value_is_always_a_reference() {
    let mut sent = request();
    sent["permission"] = json!({"bash": {"git push": "ask"}, "*": "deny"});
    let answer = dispatch(&sent).expect("plan");
    let text = answer.to_string();
    assert!(!text.contains("git push"), "{text}");
    assert_eq!(
        answer["permission"][1][0],
        json!(["merge", [["ref", ["permission"]]]])
    );
    assert_eq!(
        answer["mcp"][1][0],
        json!(["x", ["merge", [["ref", ["mcp", "x"]]]]])
    );
}

#[test]
fn guard_launchers_carry_the_relay_tail() {
    let mut sent = request();
    sent["mcp"] = json!({
        "relay": {"command": ["hol-guard.EXE", "mcp-relay", "py", "-m", "codex_plugin_scanner.cli", "guard", "mcp-proxy"]},
        "relay-other": {"command": ["hol-guard", "mcp-relay", "py", "opencode-mcp-proxy"]},
        "plain": {"command": "C:\\bin\\current-hol-guard.cmd", "args": ["guard", "codex-mcp-proxy"]},
    });
    sent["mcp_keys"] = json!(["relay", "relay-other", "plain"]);
    let answer = dispatch(&sent).expect("plan");
    let kept: Vec<&str> = answer["mcp"][1]
        .as_array()
        .expect("pairs")
        .iter()
        .map(|pair| pair[0].as_str().expect("key"))
        .collect();
    assert_eq!(kept, ["relay-other", "a", "hol-guard::a"]);
}

#[test]
fn malformed_requests_are_refused() {
    let mut bad_op = request();
    bad_op["op"] = json!("apply");
    let mut extra = request();
    extra["extra"] = json!(true);
    let mut missing = request();
    missing.as_object_mut().expect("object").remove("mcp_keys");
    let mut wrong_keys = request();
    wrong_keys["mcp_keys"] = json!(["z"]);
    let mut repeated_keys = request();
    repeated_keys["mcp_keys"] = json!(["x", "x"]);
    let mut keys_without_object = request();
    keys_without_object["mcp"] = json!([]);
    let mut workspace = request();
    workspace["workspace"] = json!("yes");
    let mut skipped = request();
    skipped["skipped"] = json!([1]);
    let mut server_extra = request();
    server_extra["servers"][0]["extra"] = json!(1);
    let mut server_env = request();
    server_env["servers"][0]["env"] = json!({"A": 1});
    let mut server_source = request();
    server_source["servers"][0]["source"] = json!("x");
    let mut server_enabled = request();
    server_enabled["servers"][0]["enabled"] = json!(1);
    let mut server_args = request();
    server_args["servers"][0]["args"] = json!("a");
    for sent in [
        json!(null),
        bad_op,
        extra,
        missing,
        wrong_keys,
        repeated_keys,
        keys_without_object,
        workspace,
        skipped,
        server_extra,
        server_env,
        server_source,
        server_enabled,
        server_args,
    ] {
        assert_eq!(dispatch(&sent), Err(ERR_INVALID), "{sent}");
    }
}

/// Ported from `TestOpenCodePermissionRules` in `tests/test_opencode_adapter.py`:
/// an enabled managed server and its companion are kept on native ask, and the
/// user's permission keys and wildcard spelling come back by reference.
#[test]
fn permission_rules_match_the_retired_python_tests() {
    let mut sent = request();
    sent["permission"] = json!({"some_tool": "allow"});
    let answer = dispatch(&sent).expect("plan");
    let asks = json!([
        "object",
        [
            ["a_*", ["value", "ask"]],
            ["hol-guard::a_*", ["value", "ask"]]
        ]
    ]);
    assert_eq!(
        answer["permission"][1][0],
        json!(["merge", [["ref", ["permission"]]]])
    );
    assert_eq!(answer["permission"][1][1], asks);
    assert_eq!(answer["overlay"][1][1], json!(["permission", asks]));

    sent["permission"] = json!("allow");
    let answer = dispatch(&sent).expect("plan");
    assert_eq!(
        answer["permission"][1][0],
        json!(["object", [["*", ["ref", ["permission"]]]]])
    );
    for permission in [json!(null), json!(["allow"])] {
        sent["permission"] = permission;
        let answer = dispatch(&sent).expect("plan");
        assert_eq!(answer["permission"][1].as_array().expect("parts").len(), 2);
    }
}
