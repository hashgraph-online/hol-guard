use serde_json::{json, Value};

use super::{approval_notice, approval_notices, message, pending, raise_approvals, Shown};

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

fn notice(fields: Value) -> Value {
    let mut notice = json!({
        "request_id": "req-1",
        "harness": "codex",
        "workspace": "/work",
        "approval_url": "http://127.0.0.1:1/approvals/req-1",
        "artifact_name": "example-server",
        "risk_headline": null,
        "trigger_summary": null,
    });
    for (key, value) in fields.as_object().into_iter().flatten() {
        notice[key] = value.clone();
    }
    notice
}

fn subject(notice: &Value) -> Option<String> {
    approval_notice(notice).map(|shown| shown.subject)
}

#[test]
fn an_asked_call_names_its_notice_as_the_daemon_reads_it() {
    assert_eq!(
        approval_notice(&notice(json!({}))),
        Some(Shown {
            request_id: "req-1".to_owned(),
            harness: "codex".to_owned(),
            workspace: Some("/work".to_owned()),
            approval_url: "http://127.0.0.1:1/approvals/req-1".to_owned(),
            subject: "example-server".to_owned(),
            connector: false,
        })
    );
    let headline = notice(json!({"risk_headline": "Deletes files", "trigger_summary": "rm"}));
    let summary = notice(json!({"risk_headline": "", "trigger_summary": "rm", "workspace": null}));
    assert_eq!(subject(&headline).as_deref(), Some("Deletes files"));
    assert_eq!(subject(&summary).as_deref(), Some("rm"));
}

#[test]
fn a_notice_the_daemon_could_not_read_is_left() {
    for unreadable in [
        notice(json!({"request_id": ""})),
        notice(json!({"approval_url": null})),
        notice(json!({"workspace": 1})),
        json!("req-1"),
    ] {
        assert_eq!(approval_notice(&unreadable), None);
    }
}

#[test]
fn a_call_raises_all_its_notices_in_order_or_none() {
    let second = notice(json!({"request_id": "req-2", "artifact_name": "other-server"}));
    let shown = approval_notices(&[notice(json!({})), second]).expect("both notices read");
    let ids: Vec<_> = shown
        .iter()
        .map(|shown| shown.request_id.as_str())
        .collect();
    assert_eq!(ids, ["req-1", "req-2"]);
    // One unreadable notice leaves the whole call's notices to the daemon, so
    // none is raised here and none is dropped from its record.
    let mixed = [notice(json!({})), notice(json!({"approval_url": null}))];
    assert_eq!(approval_notices(&mixed), None);
    assert!(!raise_approvals("/nonexistent-guard-home", "test", &mixed));
    assert_eq!(approval_notices(&[]), Some(Vec::new()));
}
