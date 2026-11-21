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

/// The requests on a record whose notice shape the receipt composer checked.
pub(super) fn request_ids(record: &Value) -> impl Iterator<Item = &str> {
    ["approval", "observed"]
        .into_iter()
        .filter_map(|key| record[key]["notices"].as_array())
        .flatten()
        .filter_map(request_id)
}

/// OS notification I/O stays off the drain thread.
pub(super) fn schedule(guard_home: &str, requests: Vec<String>) {
    crate::hook_direct_evidence::notice::raise_stored_approvals(
        guard_home,
        "mcp-relay",
        requests.into_iter(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard_store_approval_reads::tests::seed;
    use crate::guard_store_cmd_vectors_tests::temp_home;
    use crate::guard_store_tool_call_evidence_tests::count;
    use crate::hook_direct_evidence::notice::notify_stored_for_test;
    use serde_json::json;

    #[test]
    fn the_writer_recovers_one_notice_from_the_stored_request_after_the_receipt() {
        const ID: &str = "relay-notice-recovery-fixture";
        const URL: &str = "http://127.0.0.1:4781/requests/relay-notice-recovery-fixture";
        let home = temp_home("relay-notice-receipt");
        let path = home.join("guard.db");
        let fixture: Value = serde_json::from_str(include_str!(
            "../testdata/guard_store/approval_metadata_vectors.json"
        ))
        .unwrap();
        let mut row = fixture["scenarios"][0]["rows"][0].clone();
        row["request_id"] = json!(ID);
        row["workspace"] = Value::Null;
        row["approval_url"] = json!(URL);
        row["risk_headline"] = json!("Checks package metadata");
        seed(&path, &fixture, &json!({"rows":[row]}));
        let mut record =
            crate::mcp_relay_receipt::tests::record("block", "approval-center-pending", "review");
        record["approval"] = json!({
            "request_id": ID,
            "workspace": null,
            "approval_center_url": "http://127.0.0.1:4781",
            "review_url": URL,
            "notices": [{
                "request_id": ID, "harness": "codex",
                "workspace": null, "approval_url": null,
                "artifact_name": "example tool", "risk_headline": null,
                "trigger_summary": null
            }]
        });
        assert!(crate::mcp_relay_receipt::is_plain(&record));
        assert!(!valid(&record["approval"]["notices"], 1, Some("different")));
        let mut sent = 0;
        let before = count(&home, "runtime_receipts");
        for attempt in 1..=2 {
            let unwritten = crate::mcp_relay_receipt::write_with_notices(
                home.to_str().unwrap(),
                vec![record.clone()],
                |guard_home, requests| {
                    assert_eq!(count(&home, "runtime_receipts"), before + attempt);
                    assert_eq!(requests, [ID]);
                    for request in requests {
                        notify_stored_for_test(
                            guard_home,
                            "mcp-relay",
                            request,
                            |id, _, text, url| {
                                assert_eq!(id, ID);
                                assert_eq!(text, "Codex wants approval: Checks package metadata");
                                assert_eq!(url, URL);
                                sent += 1;
                                true
                            },
                        );
                    }
                },
            );
            assert!(unwritten.is_empty());
        }
        assert_eq!(sent, 1);
        let notified_at: Option<String> = rusqlite::Connection::open(&path)
            .unwrap()
            .query_row(
                "select desktop_notified_at from approval_requests where request_id = ?",
                [ID],
                |row| row.get(0),
            )
            .unwrap();
        assert!(notified_at.is_some());
        let _ = std::fs::remove_dir_all(&home);
    }
}
