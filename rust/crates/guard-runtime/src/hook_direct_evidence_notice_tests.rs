use serde_json::json;

use super::{message, pending};

#[test]
fn a_connector_notice_reads_as_the_daemon_writes_it() {
    assert_eq!(
        message("claude-code", "Example CLI", true),
        "Claude Code is waiting on a connector Guard has not set up yet: Example CLI"
    );
    assert_eq!(
        message("codex", "Example CLI", false),
        "Codex wants approval: Example CLI"
    );
}

#[test]
fn a_long_notice_is_cut_as_the_daemon_cuts_it() {
    let shown = message("codex", &"x".repeat(400), true);
    assert_eq!(shown.chars().count(), 180);
    assert!(shown.ends_with("..."));
}

#[test]
fn a_record_names_its_notice_until_the_drain_raises_it() {
    let notice = json!({"request_id": "req-1", "connector_name": "Example CLI"});
    let record = json!({"connector_setup_notice": notice});
    assert_eq!(
        pending(&record),
        Some(("req-1".to_owned(), "Example CLI".to_owned()))
    );
    let raised = json!({"connector_setup_notice": notice, "connector_notice_raised": true});
    assert_eq!(pending(&raised), None);
    for unnamed in [
        json!({}),
        json!({"connector_setup_notice": {"request_id": "", "connector_name": "Example CLI"}}),
        json!({"connector_setup_notice": {"request_id": "req-1"}}),
    ] {
        assert_eq!(pending(&unnamed), None);
    }
}
