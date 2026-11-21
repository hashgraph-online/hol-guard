//! Pending notices that accompany a native relay receipt.

use serde_json::Value;

const NOTICE_FIELDS: [&str; 7] = [
    "request_id",
    "harness",
    "workspace",
    "approval_url",
    "artifact_name",
    "risk_headline",
    "trigger_summary",
];

fn request_id(notice: &Value) -> Option<&str> {
    notice["request_id"]
        .as_str()
        .filter(|id| !id.trim().is_empty())
}

/// Check the record's shape. The notifier reads the message and link from
/// the stored request, so a damaged notice can still name a recoverable row.
pub(super) fn valid(notices: &Value, limit: usize, expected: Option<&str>) -> bool {
    notices.as_array().is_some_and(|notices| {
        notices.len() <= limit
            && notices.iter().all(|notice| {
                notice.as_object().is_some_and(|fields| {
                    fields.len() == NOTICE_FIELDS.len()
                        && NOTICE_FIELDS.iter().all(|key| fields.contains_key(*key))
                }) && request_id(notice)
                    .is_some_and(|id| expected.is_none_or(|expected| expected == id))
            })
    })
}

/// Called after receipt storage for a record whose notice shape was checked
/// by the receipt composer. OS notification I/O stays off the drain thread.
pub(super) fn schedule(guard_home: &str, record: &Value) {
    let requests = ["approval", "observed"]
        .into_iter()
        .filter_map(|key| record[key]["notices"].as_array())
        .flatten()
        .filter_map(request_id)
        .map(str::to_owned);
    crate::hook_direct_evidence::notice::raise_stored_approvals(guard_home, "mcp-relay", requests);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard_store_cmd_vectors_tests::temp_home;
    use crate::guard_store_tool_call_evidence_tests::{build_database, count, vectors};
    use serde_json::json;

    #[test]
    fn a_pending_notice_no_longer_keeps_an_ask_receipt_out_of_the_resident() {
        let home = temp_home("relay-notice-receipt");
        let (receipts, inventory) = vectors();
        build_database(&home.join("guard.db"), &receipts, &inventory);
        let mut record =
            crate::mcp_relay_receipt::tests::record("block", "approval-center-pending", "review");
        record["approval"] = json!({
            "request_id": "req-1",
            "workspace": null,
            "approval_center_url": "http://127.0.0.1:4781",
            "review_url": "http://127.0.0.1:4781/requests/req-1",
            "notices": [{
                "request_id": "req-1", "harness": "codex",
                "workspace": null, "approval_url": null,
                "artifact_name": "example tool", "risk_headline": null,
                "trigger_summary": null
            }]
        });
        assert!(crate::mcp_relay_receipt::is_plain(&record));
        assert!(!valid(&record["approval"]["notices"], 1, Some("different")));
        assert!(crate::mcp_relay_receipt::write(home.to_str().unwrap(), vec![record]).is_empty());
        assert_eq!(count(&home, "runtime_receipts"), 1);
        let _ = std::fs::remove_dir_all(&home);
    }
}
