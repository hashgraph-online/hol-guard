use super::*;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_relay/inline_approval_vectors.json");

fn fixture() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn reply(name: &str) -> Reply {
    serde_json::from_value(Value::String(name.to_owned())).unwrap()
}

#[test]
fn the_relay_classifies_every_reply_the_proxy_classifies() {
    let fixture = fixture();
    for vector in fixture["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let classified = Reply::classify(&vector["response"]);
        assert_eq!(
            classified,
            reply(vector["reply"].as_str().unwrap()),
            "{name}"
        );
        // `_inline_approval_kind`, which the route reads; a denial and an
        // invalid answer reach it alike.
        assert_eq!(
            serde_json::to_value(classified.contract()).unwrap(),
            vector["kind"],
            "{name}"
        );
    }
}

#[test]
fn only_a_denial_and_an_invalid_answer_name_a_block() {
    let fixture = fixture();
    for block in fixture["blocks"].as_array().unwrap() {
        let source = block["decision_source"].as_str().unwrap();
        let classified = reply(block["reply"].as_str().unwrap());
        assert_eq!(classified.block_source(), Some(source));
        assert_eq!(
            block_message(
                source,
                fixture["prompt"]["tool"].as_str().unwrap(),
                fixture["prompt"]["server"].as_str().unwrap(),
            ),
            block["reason"].as_str().unwrap()
        );
    }
    assert_eq!(Reply::Allow.block_source(), None);
    assert_eq!(Reply::Fallthrough.block_source(), None);
}

#[test]
fn the_prompt_carries_the_params_the_proxy_sends() {
    let fixture = fixture();
    let spec = &fixture["prompt"];
    assert_eq!(
        prompt(
            spec["server"].as_str().unwrap(),
            spec["tool"].as_str().unwrap(),
            spec["summary"].as_str().unwrap(),
        ),
        spec["request"]["params"]
    );
}

#[test]
fn an_unanswered_prompt_leaves_the_call_to_the_approval_queue() {
    // `_request_inline_approval` answers a timeout and a closed client stream
    // with a cancel, which is neither a denial nor an invalid answer.
    for unanswered in [
        json!({"result": {"action": "cancel", "reason": "timeout"}}),
        json!({}),
    ] {
        assert_eq!(Reply::classify(&unanswered), Reply::Fallthrough);
    }
}
