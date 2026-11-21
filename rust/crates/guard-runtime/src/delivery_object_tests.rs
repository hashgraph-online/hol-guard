use super::stored_zip::tests::build;
use super::*;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn an_unknown_operation_is_a_hard_error() {
    for input in [
        json!({"kind": "object"}),
        json!({"kind": "object", "operation": "other"}),
        json!({"kind": "object", "operation": 3}),
    ] {
        assert_eq!(
            evaluate(&input).unwrap_err(),
            "delivery object request invalid"
        );
    }
}

#[test]
fn a_rejection_is_a_normal_reply_with_its_message() {
    let target = json!({"tag": "x", "asset": "object-1.json"});
    let reply = evaluate(&json!({"operation": "asset", "profile": "release", "target": target}));
    assert_eq!(
        reply.unwrap(),
        json!({"rejected": "release object location invalid"})
    );
    let reply = evaluate(&json!({"operation": "verify", "data": "!", "sha256": "", "length": 0}));
    assert_eq!(
        reply.unwrap(),
        json!({"rejected": "delivery object request invalid"})
    );
}

#[test]
fn fetched_bytes_must_have_the_asked_length_and_digest() {
    let data = b"{\"a\":1}";
    let encoded = STANDARD.encode(data);
    let ask = |sha: &str, length: usize| {
        evaluate(&json!({
            "operation": "verify",
            "data": encoded,
            "sha256": sha,
            "length": length,
        }))
        .unwrap()
    };
    assert_eq!(ask(&digest(data), data.len()), json!({"verified": true}));
    let rejected = json!({"rejected": "fetched delivery object integrity invalid"});
    assert_eq!(ask(&digest(b"other"), data.len()), rejected);
    assert_eq!(ask(&digest(data), data.len() + 1), rejected);
    assert_eq!(ask(&digest(data).to_uppercase(), data.len()), rejected);
}

#[test]
fn operations_reach_their_handlers() {
    let dir = tempfile::tempdir().unwrap();
    let data = b"{\"b\":2}";
    let name = format!("object-{}.json", digest(data));
    let path = dir.path().join("objects-000001.zip");
    std::fs::write(&path, build(&[(&name, data)])).unwrap();
    let reply = evaluate(&json!({
        "operation": "member",
        "path": path.to_str().unwrap(),
        "asset": "objects-000001.zip",
        "name": name,
        "length": data.len(),
    }))
    .unwrap();
    assert_eq!(reply["data"], STANDARD.encode(data));
    let sha = digest(data);
    std::fs::write(dir.path().join(format!("{sha}.json")), data).unwrap();
    let reply = evaluate(&json!({
        "operation": "expand",
        "mode": "pack",
        "directory": dir.path().to_str().unwrap(),
        "reference": {
            "sha256": sha,
            "length": data.len(),
            "expanded_length": data.len(),
            "kind": "data",
        },
    }))
    .unwrap();
    assert_eq!(reply["data"], STANDARD.encode(data));
}

#[test]
fn the_pack_lifecycle_protocol_routes_object_requests() {
    let reply = crate::pack_lifecycle::evaluate(&json!({"kind": "object", "operation": "nope"}));
    assert_eq!(reply.unwrap_err(), "delivery object request invalid");
}
