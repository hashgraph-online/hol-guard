use serde_json::json;

use super::prepare_with;

#[test]
fn a_record_without_a_stamp_is_handed_back_whole_for_the_retry() {
    let record = json!({"kind": "mcp_tool_call", "remember": true});
    let (composed, retry) = prepare_with("/guard", vec![(7, record.clone())], || None);
    assert!(composed.is_empty());
    assert_eq!(retry, vec![(7, record)]);
}

#[test]
fn a_record_no_receipt_composes_from_is_dropped_rather_than_retried() {
    // A relayed block whose action names no block event: `compose` returns
    // nothing for it now and would return nothing on any later page either.
    let mut record = crate::mcp_relay_receipt::tests::record("block", "policy-block", "block");
    record["policy_action"] = json!("allow");
    let (composed, retry) = prepare_with("/guard", vec![(7, record)], super::Stamp::fresh);
    assert!(composed.is_empty());
    assert!(retry.is_empty());
}
