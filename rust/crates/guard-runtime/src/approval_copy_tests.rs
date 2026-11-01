use serde_json::{json, Value};

use super::*;

const URL: &str = "http://127.0.0.1:5474/requests/req-1";

fn context(label: &str) -> String {
    format!(
        "Open HOL Guard to approve or keep this blocked: {URL}. \
         After you choose, retry the same {label} action."
    )
}

fn localize(args: Value) -> Value {
    let mut args = args;
    args["review_url"] = json!(URL);
    dispatch(&args).unwrap()
}

#[test]
fn context_names_the_harness_or_a_package_install() {
    let cases = [
        ("codex", "Codex"),
        ("claude-code", "Claude Code"),
        ("omp", "Oh My Pi"),
        ("guard-cli", "package install"),
        ("pnpm", "package install"),
        ("brew", "package install"),
        ("hermes", "the harness"),
        ("Codex", "the harness"),
    ];
    for (harness, label) in cases {
        let result = localize(json!({"harness": harness}));
        assert_eq!(result["review_context"], context(label), "{harness}");
        assert_eq!(result["decisions"], json!([]));
        assert_eq!(result["user_copy_message"], Value::Null);
    }
}

#[test]
fn decisions_route_their_messages_and_retry_copy_to_the_center() {
    let ctx = context("Codex");
    let decisions = json!([
        {"harness_message": "Blocked a risky install", "action": "block"},
        {"harness_message": "   ", "action": " ask ", "retry_instruction": "Run hol-guard connect first"},
        {"action": "allow", "retry_instruction": "Retry later."},
        {"action": "ask", "retry_instruction": "Retry later."},
        null,
    ]);
    let result = localize(json!({"harness": "codex", "decisions": decisions}));
    assert_eq!(
        result["decisions"],
        json!([
            {
                "harness_message": format!("Blocked a risky install. {ctx}"),
                "retry_instruction": ctx,
            },
            {"retry_instruction": format!("Run hol-guard connect first. {ctx}")},
            {},
            {"retry_instruction": ctx},
            null,
        ])
    );
}

#[test]
fn routed_message_drops_inbox_links_and_stale_center_copy() {
    let ctx = context("Codex");
    let cases = [
        (
            "Held for review (https://hol.org/guard/inbox/). Review this request in HOL Guard, then retry.",
            format!("Held for review. {ctx}"),
        ),
        (
            "Held. See <HTTPS:/guard/inbox;view?x#y>, then https://hol.org/guard/inboxes.",
            format!("Held. See then https://hol.org/guard/inboxes. {ctx}"),
        ),
        (
            "Held. open HOL Guard to approve or keep this blocked: http://old. After you choose, retry the same Cursor action. Then wait",
            format!("Held. Then wait. {ctx}"),
        ),
        (
            "Held. Open HOL Guard to approve or keep this blocked: http://old.",
            format!("Held. {ctx}"),
        ),
        (
            "Held.\n\tReview evidence: .",
            format!("Held. {ctx}"),
        ),
        ("https://hol.org/guard/inbox", ctx.clone()),
        ("Review evidence:", ctx.clone()),
        (
            "Kept ftp://hol.org/guard/inbox",
            format!("Kept ftp://hol.org/guard/inbox. {ctx}"),
        ),
        // `urlparse` raised on the unbalanced bracket and lost the whole
        // rewrite; the token is now kept like any other non-inbox link.
        (
            "Kept http://[::1/guard/inbox",
            format!("Kept http://[::1/guard/inbox. {ctx}"),
        ),
    ];
    for (message, expected) in cases {
        assert_eq!(routed_message(message, &ctx), expected, "{message}");
    }
}

#[test]
fn case_folding_indexes_follow_python_slicing() {
    // 'İ' lowers to two code points, so Python's lowered index lands one
    // character later in the original text.
    assert_eq!(
        strip_legacy_sentence("İ Open HOL Guard to approve or keep this blocked: x"),
        "İ O"
    );
    // The Kelvin sign lowers to `k`, so it still matches the sentence.
    assert_eq!(
        strip_legacy_sentence("A open hol guard to approve or \u{212a}eep this blocked: x"),
        "A"
    );
    assert_eq!(strip_review_evidence_tail("İ Review evidence:"), "İ");
    assert_eq!(strip_review_evidence_tail(" Hold. "), "Hold.");
    assert_eq!(strip_review_evidence_tail("Hold. Review evidence: ."), "Hold.");
    assert_eq!(strip_review_evidence_tail("Hold. review EVIDENCE:"), "Hold.");
}

#[test]
fn user_copy_message_is_routed_when_present() {
    let ctx = context("package install");
    let result = localize(json!({
        "harness": "npm",
        "user_copy_message": " Package held. Review evidence: . ",
    }));
    assert_eq!(result["user_copy_message"], format!("Package held. {ctx}"));
    let blank = localize(json!({"harness": "npm", "user_copy_message": " "}));
    assert_eq!(blank["user_copy_message"], Value::Null);
}

#[test]
fn invalid_arguments_are_refused() {
    for args in [
        json!({"review_url": URL}),
        json!({"harness": "codex"}),
        json!({"harness": "codex", "review_url": URL, "decisions": {}}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
