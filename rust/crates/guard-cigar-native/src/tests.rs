use crate::broker_host::{is_hex64, outcome, Outcome};
use crate::frames::{read_line, serve, REQUEST_FAILED, SCHEMA};
use crate::graph;
use serde_json::{json, Value};

fn run_bridge(input: &str, stop_on: &str) -> Vec<Value> {
    let mut output = Vec::new();
    serve(&mut input.as_bytes(), &mut output, |request| {
        let op = request["op"].as_str().unwrap_or_default();
        let reply = match op {
            "echo" => Ok(request.clone()),
            _ => Err(REQUEST_FAILED),
        };
        (reply, op == stop_on)
    });
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap_or(Value::Null))
        .collect()
}

#[test]
fn bridge_replies_carry_the_schema_and_request_id() {
    let replies = run_bridge(
        "{\"schema\":\"guard-cigar-bridge.v1\",\"id\":7,\"request\":{\"op\":\"echo\"}}\n\
         {\"schema\":\"guard-cigar-bridge.v1\",\"id\":8,\"request\":{\"op\":\"nope\"}}\n",
        "",
    );
    assert_eq!(
        replies,
        vec![
            json!({"schema": SCHEMA, "id": 7, "ok": true, "result": {"op": "echo"}}),
            json!({"schema": SCHEMA, "id": 8, "ok": false, "error": REQUEST_FAILED}),
        ]
    );
}

#[test]
fn bridge_answers_unparseable_lines_with_id_zero_and_keeps_going() {
    let replies = run_bridge(
        "not json\n{\"schema\":\"guard-cigar-bridge.v1\",\"id\":2,\"request\":{\"op\":\"echo\"}}\n",
        "",
    );
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["id"], 0);
    assert_eq!(replies[0]["error"], REQUEST_FAILED);
    assert_eq!(replies[1]["id"], 2);
}

#[test]
fn bridge_stops_on_a_wrong_schema_a_bad_id_or_a_stop_request() {
    for input in [
        "{\"schema\":\"other\",\"id\":1,\"request\":{\"op\":\"echo\"}}\n",
        "{\"schema\":\"guard-cigar-bridge.v1\",\"id\":0,\"request\":{\"op\":\"echo\"}}\n",
        "{\"schema\":\"guard-cigar-bridge.v1\",\"id\":\"1\",\"request\":{\"op\":\"echo\"}}\n",
    ] {
        let follow =
            "{\"schema\":\"guard-cigar-bridge.v1\",\"id\":3,\"request\":{\"op\":\"echo\"}}\n";
        assert!(
            run_bridge(&format!("{input}{follow}"), "").is_empty(),
            "{input}"
        );
    }
    let stopped = run_bridge(
        "{\"schema\":\"guard-cigar-bridge.v1\",\"id\":1,\"request\":{\"op\":\"echo\"}}\n\
         {\"schema\":\"guard-cigar-bridge.v1\",\"id\":2,\"request\":{\"op\":\"echo\"}}\n",
        "echo",
    );
    assert_eq!(stopped.len(), 1);
}

#[test]
fn line_reader_refuses_oversized_and_unterminated_lines() {
    assert_eq!(read_line(&mut &b"abc\n"[..], 4), Some(b"abc\n".to_vec()));
    assert_eq!(read_line(&mut &b"abcd\n"[..], 4), None);
    assert_eq!(read_line(&mut &b"abc"[..], 4), None);
    assert_eq!(read_line(&mut &b""[..], 4), None);
}

#[test]
fn graph_replies_pass_only_documented_error_codes() {
    assert_eq!(
        graph::decode(&json!({"id": 4, "ok": true, "result": {"a": 1}}), 4),
        Ok(json!({"a": 1}))
    );
    assert_eq!(
        graph::decode(&json!({"id": 4, "ok": false, "error": "Integrity"}), 4),
        Err(Some("Integrity"))
    );
    for reply in [
        json!({"id": 4, "ok": false, "error": "SomethingElse"}),
        json!({"id": 5, "ok": true, "result": 1}),
        json!({"id": 4, "ok": "yes", "result": 1}),
        json!({"id": 4, "ok": true}),
    ] {
        assert_eq!(graph::decode(&reply, 4), Err(None), "{reply}");
    }
}

#[test]
fn the_compiled_worker_accepts_the_graph_hello_this_host_checks() {
    let input = b"{\"id\":1,\"command\":{\"op\":\"init\",\"domain\":\"t\",\"limits\":{}}}\n";
    let mut output = Vec::new();
    assert!(cigar_context::worker::serve(&mut &input[..], &mut output).is_ok());
    let reply: Value = serde_json::from_slice(&output).unwrap_or(Value::Null);
    let hello = graph::decode(&reply, 1);
    assert!(hello.is_ok(), "{reply}");
    let features = hello.ok().and_then(|hello| graph::hello_features(&hello));
    assert!(features.is_some_and(|features| features.iter().any(|item| item == "context_views.v1")));
}

fn broker_reply(outcome: Value) -> Value {
    json!({
        "protocol": crate::BROKER_PROTOCOL,
        "id": 1,
        "outcome": outcome,
        "timing": {"queue_us": 3, "service_us": 9},
    })
}

#[test]
fn broker_replies_must_have_exactly_the_documented_members() {
    let done = outcome(&broker_reply(json!({"status": "ok", "result": [1]})), 1);
    assert!(matches!(done, Some(Outcome::Done(result)) if result == json!([1])));
    let failed = outcome(
        &broker_reply(json!({"status": "error", "error": "Stale", "dispatched": true})),
        1,
    );
    assert!(matches!(failed, Some(Outcome::Failed("Stale"))));
    let mut extra = broker_reply(json!({"status": "ok", "result": 1}));
    extra["more"] = json!(1);
    let mut slow = broker_reply(json!({"status": "ok", "result": 1}));
    slow["timing"]["queue_us"] = json!(9_007_199_254_740_992_u64);
    for reply in [
        extra,
        slow,
        broker_reply(json!({"status": "ok", "result": 1, "x": 1})),
        broker_reply(json!({"status": "error", "error": "Unknown", "dispatched": true})),
        broker_reply(json!({"status": "error", "error": "Stale"})),
    ] {
        assert!(outcome(&reply, 1).is_none(), "{reply}");
    }
    assert!(outcome(&broker_reply(json!({"status": "ok", "result": 1})), 2).is_none());
}

#[test]
fn secrets_and_epochs_are_lowercase_64_hex() {
    assert!(is_hex64(&json!("a".repeat(64))));
    assert!(!is_hex64(&json!("A".repeat(64))));
    assert!(!is_hex64(&json!("a".repeat(63))));
    assert!(!is_hex64(&json!(5)));
}

#[test]
fn modes_are_recognised_only_by_their_exact_first_argument() {
    let args = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>()
    };
    assert!(crate::is_command(&args(&[crate::BRIDGE_COMMAND])));
    assert!(crate::is_command(&args(&[
        crate::WORKER_COMMAND,
        "--broker"
    ])));
    assert!(!crate::is_command(&args(&[
        "status",
        crate::BRIDGE_COMMAND
    ])));
    assert!(!crate::is_command(&[]));
    assert_eq!(crate::main(&args(&[crate::BRIDGE_COMMAND, "extra"])), 2);
}
