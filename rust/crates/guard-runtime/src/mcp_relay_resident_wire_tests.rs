//! The child frame and the decide request come from one Python rewrite.

use serde_json::Value;

use super::tests::{facts, no_prompt};
use super::*;

#[test]
fn the_child_frame_and_the_request_share_one_python_rewrite() {
    let facts = facts();
    let catalog = RelayCatalog::default();
    let host = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call",
        "params":{"name":"read","arguments":{"b":1.00,"a":[-0,1e5,"2.50"]}}}"#;
    let message: Value = serde_json::from_str(host).unwrap();
    let order = ["b".to_owned(), "a".to_owned()];
    let (frame, request, expected) =
        prepare(&facts, &message, Some(&order), &catalog, &no_prompt()).unwrap();
    assert_eq!(expected, catalog.snapshot());
    assert_eq!(
        serde_json::to_string(&frame).unwrap(),
        r#"{"id":4,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"a":[0,100000.0,"2.50"],"b":1.0},"name":"read"}}"#
    );
    assert_eq!(request["params"], frame["params"]);
    assert_eq!(
        serde_json::to_string(&request["arguments"]).unwrap(),
        r#"{"entries":[["b",1.0],["a",[0,100000.0,"2.50"]]],"format":"mapping"}"#
    );
}

#[test]
fn a_frame_the_proxy_would_not_relay_unchanged_is_not_sent() {
    let facts = facts();
    let catalog = RelayCatalog::default();
    for host in [
        // The host correlates by the id it sent; the proxy would send 1.5.
        r#"{"jsonrpc":"2.0","id":1.50,"method":"tools/call","params":{"name":"read"}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read","arguments":{"a":1e400}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read","_meta":{"t":-1e999}}}"#,
    ] {
        let message: Value = serde_json::from_str(host).unwrap();
        assert!(
            prepare(&facts, &message, None, &catalog, &no_prompt()).is_none(),
            "{host}"
        );
    }
}
