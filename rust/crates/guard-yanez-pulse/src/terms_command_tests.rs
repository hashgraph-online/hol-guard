//! The command row the YID app shows for a single paused action.

use serde_json::Value;

use super::*;

const KEY: [u8; 32] = [7; 32];

fn binding() -> ActionBinding<'static> {
    ActionBinding {
        purpose: "approval_decision",
        action: "allow",
        scope: "artifact",
        subject: "approval-request:r1",
        session_nonce: "session",
        session_binding: "signals",
        request_nonce: "nonce-0123456789abcdef",
        factor_generation: 1,
    }
}

fn row<'a>(terms: &'a Value, label: &str) -> Option<&'a Value> {
    terms["details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["label"] == label)
}

fn with_command(command: &str) -> ActionSummary {
    ActionSummary {
        programs: Some("rm".into()),
        agent: Some("Codex".into()),
        command: Some(command.into()),
        ..ActionSummary::default()
    }
}

#[test]
fn the_command_shows_right_after_the_program() {
    let terms =
        build_terms_with_summary(&KEY, &binding(), &with_command("rm -rf ~/build")).unwrap();
    let labels: Vec<&str> = terms["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["label"].as_str().unwrap())
        .collect();
    assert_eq!(
        labels,
        ["Request", "Program", "Command", "Agent", "Match code"]
    );
    let command = row(&terms, "Command").unwrap();
    assert_eq!(command["value"], "rm -rf ~/build");
    assert_eq!(command["emphasized"], true);
    // The headline the notification shows stays the short program summary.
    let headline = terms["summary"].as_str().unwrap();
    assert!(!headline.contains("~/build"), "{headline}");
}

#[test]
fn a_long_command_is_cut_at_its_own_limit() {
    let long = format!("echo {}", "x".repeat(1000));
    let terms = build_terms_with_summary(&KEY, &binding(), &with_command(&long)).unwrap();
    let shown = row(&terms, "Command").unwrap()["value"].as_str().unwrap();
    assert_eq!(shown.chars().count(), MAX_COMMAND_CHARS);
    assert!(shown.ends_with('…'));
    assert!(MAX_COMMAND_CHARS > MAX_SUMMARY_VALUE_CHARS);
}

#[test]
fn a_command_is_one_line_without_hidden_characters() {
    assert_eq!(
        command_value("git push\n  origin\tmain\u{7}").as_deref(),
        Some("git push origin main")
    );
    assert_eq!(
        command_value("rm\u{202E}fdp.exe").as_deref(),
        Some("rm fdp.exe")
    );
    assert_eq!(command_value(" \n\t\u{200B}"), None);
    let terms = build_terms_with_summary(&KEY, &binding(), &with_command("\n\t")).unwrap();
    assert!(row(&terms, "Command").is_none());
}

#[test]
fn a_batch_never_shows_a_command() {
    let batch = ActionSummary {
        action_count: Some(3),
        ..with_command("rm -rf ~/build")
    };
    let terms = build_terms_with_summary(&KEY, &binding(), &batch).unwrap();
    assert!(row(&terms, "Command").is_none());
    assert!(row(&terms, "Programs").is_some());
}

#[test]
fn the_command_row_is_dropped_before_the_size_limit_refuses_the_request() {
    // Every other row is already at its longest; the command no longer fits.
    let crowded = ActionSummary {
        agent: Some("a".repeat(500)),
        request_type: Some("b".repeat(500)),
        risk_level: Some("c".repeat(500)),
        reason: Some("\u{1F600}".repeat(500)),
        programs: Some("\u{1F600}".repeat(500)),
        decision: Some("\u{1F600}".repeat(500)),
        command: Some("\u{1F600}".repeat(500)),
        action_count: None,
    };
    let terms = build_terms_with_summary(&KEY, &binding(), &crowded).unwrap();
    assert!(serde_json::to_vec(&terms).unwrap().len() <= MAX_TERMS_BYTES);
    assert!(
        row(&terms, "Command").is_none(),
        "the command should be left out"
    );
    assert!(row(&terms, "Match code").is_some());
}
