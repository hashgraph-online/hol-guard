use super::*;

fn answer(text: &str) -> Value {
    dispatch(&json!({ "text": text })).expect("a well-formed request")
}

#[test]
fn a_config_reads_in_document_order() {
    let reply =
        answer("model = \"x\"\n[features]\nhooks = true\n[[hooks.Stop]]\nmatcher = \"*\"\n");
    assert_eq!(
        reply["payload"],
        json!(r#"{"model":"x","features":{"hooks":true},"hooks":{"Stop":[{"matcher":"*"}]}}"#)
    );
    assert_eq!(reply["tokens"], json!({}));
}

#[test]
fn values_json_cannot_carry_cross_as_shared_tokens() {
    let reply = answer(
        "a = 1979-05-27T07:32:00Z\nb = 1979-05-27\nc = 07:32:00.5\nd = inf\ne = nan\nf = 1979-05-27T07:32:00Z\n",
    );
    let payload = reply["payload"].as_str().expect("payload text");
    let tokens = reply["tokens"].as_object().expect("token map");
    assert_eq!(tokens.len(), 5);
    let meanings: Vec<&Value> = tokens.values().collect();
    assert!(
        meanings.contains(&&json!({ "type": "datetime", "value": "1979-05-27T07:32:00+00:00" }))
    );
    assert!(meanings.contains(&&json!({ "type": "date", "value": "1979-05-27" })));
    assert!(meanings.contains(&&json!({ "type": "time", "value": "07:32:00.500000" })));
    assert!(meanings.contains(&&json!({ "type": "float", "value": "inf" })));
    assert!(meanings.contains(&&json!({ "type": "float", "value": "nan" })));
    let parsed: Value = serde_json::from_str(payload).expect("payload JSON");
    assert_eq!(parsed["a"], parsed["f"]);
}

#[test]
fn a_string_shaped_like_a_token_stays_a_string() {
    let reply = answer("a = 1979-05-27\n");
    let token = reply["tokens"]
        .as_object()
        .and_then(|tokens| tokens.keys().next().cloned())
        .expect("one token");
    let second = answer(&format!("a = 1979-05-27\nb = \"{token}\"\n"));
    let parsed: Value =
        serde_json::from_str(second["payload"].as_str().expect("payload")).expect("JSON");
    assert_eq!(parsed["b"], json!(token));
    let tokens = second["tokens"].as_object().expect("token map");
    assert!(!tokens.contains_key(&token));
    assert!(tokens
        .keys()
        .all(|key| !token.starts_with(key.rsplit_once('-').unwrap().0)));
}

#[test]
fn refusals_name_why_tomllib_refused() {
    assert_eq!(
        answer("[features]\nhooks = false\n[hooks]\nStop = []\nStop = []\n"),
        json!({ "error": "duplicate_key" })
    );
    assert_eq!(answer("[hooks\n"), json!({ "error": "malformed" }));
}

#[test]
fn malformed_requests_are_refused() {
    assert_eq!(dispatch(&json!({})), Err(ERR_INVALID));
    assert_eq!(dispatch(&json!({ "text": 1 })), Err(ERR_INVALID));
    assert_eq!(dispatch(&json!({ "text": "", "x": 1 })), Err(ERR_INVALID));
}
