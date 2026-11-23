use serde_json::json;

use super::prepare_with;

#[test]
fn a_record_without_a_stamp_is_handed_back_whole_for_the_retry() {
    let record = json!({"kind": "mcp_tool_call", "remember": true});
    let (composed, retry) = prepare_with("/guard", vec![(7, record.clone())], || None);
    assert!(composed.is_empty());
    assert_eq!(retry, vec![(7, record)]);
}
