use super::*;
use serde_json::{json, Value};

#[test]
fn original_python_option_helpers_replay() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/shell-helper-python.v1.json"
    ))
    .unwrap();
    for (index, vector) in fixture["option_vectors"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut input = vector["input"].clone();
        input["command"] = json!("");
        let request = ShellHelpersRequest {
            schema: "guard-shell-helpers-request.v1".into(),
            request_id: "option-parity".into(),
            action: vector["action"].as_str().unwrap().into(),
            input,
            timeout_ms: 10_000,
        };
        let reply = resident_reply(&request);
        assert_eq!(reply["code"], json!("ok"));
        assert_eq!(
            &reply["result"], &vector["expected"],
            "original option vector {index}"
        );
    }
}

fn chunks(text: &str) -> Value {
    let chars: Vec<char> = text.chars().collect();
    json!(chars
        .chunks(131_072)
        .map(|part| part.iter().collect::<String>())
        .collect::<Vec<_>>())
}

fn resident_reply(request: &ShellHelpersRequest) -> Value {
    use base64::Engine;
    let mut material = serde_json::to_value(request).unwrap();
    let mut bytes = Vec::new();
    let mut digest = None;
    for _ in 0..256 {
        let frame =
            json!({"operation":"shell_helpers", "request":material,"deadline_budget_ms":10_000});
        let encoded = serde_json::to_vec(&frame).unwrap();
        let mut answer: Value = serde_json::from_slice(
            &crate::resident_ops::evaluate_resident_bytes(&encoded, None).unwrap(),
        )
        .unwrap();
        let result = &answer["result"];
        let Some(fragment) = result["fragment_b64"].as_str() else {
            assert!(bytes.is_empty());
            return answer;
        };
        assert_eq!(result["byte_offset"], json!(bytes.len()));
        if let Some(previous) = &digest {
            assert_eq!(previous, &result["result_sha256"]);
        }
        digest = Some(result["result_sha256"].clone());
        bytes.extend(
            base64::engine::general_purpose::STANDARD
                .decode(fragment)
                .unwrap(),
        );
        if result["next_offset"].is_null() {
            assert_eq!(result["total_bytes"], json!(bytes.len()));
            assert_eq!(
                result["result_sha256"],
                json!(guard_policy_snapshot::digest_bytes(&bytes))
            );
            answer["result"] = serde_json::from_slice(&bytes).unwrap();
            return answer;
        }
        material["input"]["result_offset"] = result["next_offset"].clone();
    }
    panic!("native result did not finish within the fragment limit");
}

#[cfg(unix)]
#[test]
fn trusted_absolute_env_wrapper_uses_native_observations() {
    let result = guard_command::shell_helpers::evaluate(
        "normalization",
        &json!({"command":"/usr/bin/env bash -lc 'echo value'"}),
    )
    .unwrap();
    assert_eq!(result["wrapper_chain"], json!(["env", "bash"]));
    assert_eq!(result["normalized_command"], json!("echo value"));
}

#[test]
fn original_python_shell_helpers_replay() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/shell-helper-python.v1.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let command = &vector["command"];
        for action in [
            "segments",
            "pipe_segments",
            "redirects",
            "pipes",
            "heredocs",
            "substitutions",
            "expanded_substitutions",
            "masked_bodies",
            "masked_complete",
            "normalization",
            "trace",
        ] {
            if vector["expected"].get(action).is_none() {
                continue;
            }
            let mut input = json!({"command_chunks":chunks(command.as_str().unwrap())});
            if action.starts_with("masked_") {
                let spans: Vec<Value> = vector["expected"]["heredocs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| {
                        json!([
                            h["operator_start"],
                            h["declaration_end"],
                            h["body_start"],
                            h["end"]
                        ])
                    })
                    .collect();
                input["spans_chunks"] = chunks(&serde_json::to_string(&spans).unwrap());
            }
            if action == "trace" {
                input["state"] = json!([null, 0, false]);
                input["index"] = json!(0);
            }
            if action == "heredocs" {
                input["offset"] = json!(0);
            }
            let mut request = ShellHelpersRequest {
                schema: "guard-shell-helpers-request.v1".into(),
                request_id: "parity".into(),
                action: if action == "heredocs" {
                    "heredocs_page"
                } else {
                    action
                }
                .into(),
                input,
                timeout_ms: 10_000,
            };
            let mut reply = resident_reply(&request);
            if action == "heredocs" {
                let mut rows = reply["result"]["items"].as_array().unwrap().clone();
                while !reply["result"]["next_offset"].is_null() {
                    request.input["offset"] = reply["result"]["next_offset"].clone();
                    reply = resident_reply(&request);
                    rows.extend(reply["result"]["items"].as_array().unwrap().iter().cloned());
                }
                reply["result"] = json!(rows);
            }
            if action == "trace" {
                let mut rows = reply["result"].as_array().unwrap().clone();
                while rows.last().is_some_and(|r| {
                    r[1].as_u64().unwrap() < command.as_str().unwrap().chars().count() as u64
                }) {
                    let last = rows.last().unwrap();
                    request.input["index"] = last[1].clone();
                    request.input["state"] = json!([last[2], last[3], last[4]]);
                    reply = resident_reply(&request);
                    let page = reply["result"].as_array().unwrap();
                    assert!(!page.is_empty());
                    rows.extend(page.iter().cloned());
                }
                reply["result"] = json!(rows);
            }
            assert_eq!(
                reply["result"], vector["expected"][action],
                "action={action}, command={command}"
            );
        }
    }
}

#[test]
fn original_python_interpreter_options_replay() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/shell-helper-python.v1.json"
    ))
    .unwrap();
    for vector in fixture["interpreter_vectors"].as_array().unwrap() {
        let request = ShellHelpersRequest {
            schema: "guard-shell-helpers-request.v1".into(),
            request_id: "interpreter-parity".into(),
            action: "interpreter_payload".into(),
            timeout_ms: 10_000,
            input: json!({"command":"", "parts":vector["parts"], "command_index":vector["command_index"]}),
        };
        let reply: Value = serde_json::from_slice(&evaluate(&request).unwrap()).unwrap();
        assert_eq!(reply["code"], json!("ok"));
        assert_eq!(
            reply["result"], vector["expected"],
            "parts={}",
            vector["parts"]
        );
    }
}

#[test]
fn input_rejections_are_bound_replies_and_large_results_are_bounded() {
    for (action, input, code) in [
        (
            "trace",
            json!({"command":"echo", "index":0,"state":["invalid",0,false]}),
            "shell_helpers_invalid_state",
        ),
        (
            "masked_bodies",
            json!({"command":"echo","heredocs":[{}]}),
            "shell_helpers_invalid",
        ),
    ] {
        let request = ShellHelpersRequest {
            schema: "guard-shell-helpers-request.v1".into(),
            request_id: "rejected-input".into(),
            action: action.into(),
            input,
            timeout_ms: 10_000,
        };
        let reply = resident_reply(&request);
        assert_eq!(reply["status"], json!("ok"));
        assert_eq!(reply["code"], json!(code));
        assert!(reply["result"].is_null());
        assert_eq!(reply["request_id"], json!(request.request_id));
    }
}

#[test]
fn request_binding_matches_python_ascii_and_unicode_canonical_hashes() {
    // Frozen hashlib/json.dumps outputs from the original Python transport.
    for (command, digest) in [
        (
            "echo value",
            "79a1fced92569b36164be981bafdd7850d280e06c384c86769c2597ec913cd02",
        ),
        (
            "echo $(printf 'é🙂')",
            "f82ec33cb2e9fa38483c39804c4d402eb5350d7529d141d853ba6c8872541ae8",
        ),
    ] {
        let request = ShellHelpersRequest {
            schema: "guard-shell-helpers-request.v1".into(),
            request_id: "binding".into(),
            action: "segments".into(),
            input: json!({"command":command}),
            timeout_ms: 10_000,
        };
        let reply: Value = serde_json::from_slice(&evaluate(&request).unwrap()).unwrap();
        assert_eq!(reply["request_sha256"], digest);
    }
}

#[test]
fn malformed_and_out_of_range_spans_are_rejected() {
    for input in [
        json!({"command":"echo","heredocs":[{}]}),
        json!({"command":"echo","heredocs":[{"delimiter":"EOF","body":"","operator_start":0,"declaration_end":1,"body_start":0,"body_end":5,"end":5,"quoted":false,"strip_tabs":false}]}),
    ] {
        assert!(guard_command::shell_helpers::evaluate("masked_bodies", &input).is_err());
    }
    assert!(guard_command::shell_helpers::evaluate(
        "trace",
        &json!({"command":"echo","index":0,"state":["invalid",0,false]})
    )
    .is_err());
    assert!(guard_command::shell_helpers::evaluate(
        "trace",
        &json!({"command":"(","index":0,"state":[null,u64::MAX,false]})
    )
    .is_err());
}
#[test]
fn paged_results_reuse_prepared_values_and_serialized_fragments() {
    let deadline = Instant::now() + Duration::from_secs(8);
    let input = json!({"command": "cat <<EOF\nvalue\nEOF\n"});
    let first = prepared_result("heredocs", &input, deadline).unwrap();
    let repeated = prepared_result("heredocs", &input, deadline).unwrap();
    assert!(std::sync::Arc::ptr_eq(&first, &repeated));
    let page_input = json!({"command": input["command"], "offset": 0});
    let page = prepared_result("heredocs_page", &page_input, deadline).unwrap();
    let same_page = prepared_result("heredocs_page", &page_input, deadline).unwrap();
    assert!(std::sync::Arc::ptr_eq(&page, &same_page));
    assert_eq!(
        page_result(&page, 0).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let large = json!({"command": "echo ".repeat(100_000), "heredocs": []});
    let masked = prepared_result("masked_bodies", &large, deadline).unwrap();
    assert_eq!(
        page_result(&masked, 0).unwrap()["result_sha256"],
        masked.digest
    );
    assert_eq!(
        page_result(&masked, 256 * 1024).unwrap()["result_sha256"],
        masked.digest
    );
}

#[test]
fn kubernetes_secret_read_source_replays_recorded_python() {
    use std::io::Read;
    let bytes = include_bytes!("../../guard-command/tests/fixtures/sfrs/kubernetes.json.gz");
    let mut body = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut body)
        .unwrap();
    let fixture: Value = serde_json::from_str(&body).unwrap();
    let mut replayed = 0;
    for case in fixture["cases"].as_array().unwrap() {
        if case["fn"] != json!("k_secret_read_source") {
            continue;
        }
        let Some(command) = case["args"][0].as_str() else {
            continue;
        };
        let request = ShellHelpersRequest {
            schema: "guard-shell-helpers-request.v1".into(),
            request_id: "kubernetes-parity".into(),
            action: "kubernetes_secret_read_source".into(),
            input: json!({"command": command}),
            timeout_ms: 10_000,
        };
        let reply = resident_reply(&request);
        assert_eq!(reply["code"], json!("ok"), "{command}");
        assert_eq!(reply["result"], case["result"], "{command}");
        replayed += 1;
    }
    assert!(replayed >= 500, "replayed {replayed}");
}
