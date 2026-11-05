use serde_json::{json, Value};

use super::*;

const REQUEST_ID: &str = "req-1";

fn payload() -> Value {
    json!({
        "_ephemeral_signed_approval_url": null,
        "approval_request_ids": [REQUEST_ID],
        "approval_resume": null,
        "primary_approval_url": null,
        "request": {"command": ["bun", "install", "-g", "@openai/codex"]},
        "supply_chain": null,
        "supply_chain_evaluation": {
            "user_copy": {
                "harness_message": "Guard paused this install. Wait for approval; do not retry.",
                "next_step": "Approve it in HOL Guard.",
                "dashboard_url": "http://127.0.0.1:5474/requests/req-1",
            },
        },
        "verdict": {"action": "review", "reason": " New package version. "},
    })
}

fn run(payload: Value, from_agent: bool) -> Value {
    dispatch(&json!({"payload": payload, "from_agent": from_agent, "emphasis": false}))
        .expect("guidance")
}

fn lines(answer: &Value) -> Vec<&str> {
    answer["guidance"]
        .as_array()
        .expect("guidance lines")
        .iter()
        .map(|line| line.as_str().expect("line"))
        .collect()
}

#[test]
fn a_person_gets_the_commands_that_approve_the_install() {
    let mut payload = payload();
    payload["supply_chain"] = json!({"status": "synced", "bundle": {}});
    let answer = run(payload, false);
    assert_eq!(answer["title"], "Approve this install");
    assert_eq!(
        lines(&answer),
        vec![
            "Approve in the browser: http://127.0.0.1:5474/requests/req-1",
            "Approve once:   hol-guard approvals approve req-1",
            "Always allow:   hol-guard approvals approve req-1 --remember",
            "Or decide in the approval center: hol-guard approvals",
            "Then run it again: bun install -g @openai/codex",
            "Sign in to Guard Cloud for package intelligence and phone approvals: hol-guard connect",
        ]
    );
    assert_eq!(answer["request_ids"], json!([REQUEST_ID]));
}

#[test]
fn an_agent_gets_the_harness_guidance() {
    let answer = run(payload(), true);
    assert_eq!(answer["title"], "Guard guidance");
    assert_eq!(
        lines(&answer),
        vec![
            "Guard paused this install. Wait for approval; do not retry.",
            "Next step: Approve it in HOL Guard.",
            "Review: http://127.0.0.1:5474/requests/req-1",
        ]
    );
}

#[test]
fn steps_need_exactly_one_request_under_review() {
    let mut two = payload();
    two["approval_request_ids"] = json!(["a", "b"]);
    assert_eq!(run(two, false)["title"], "Guard guidance");
    let mut blocked = payload();
    blocked["verdict"]["action"] = json!("block");
    assert_eq!(run(blocked, false)["title"], "Guard guidance");
    let mut reapproval = payload();
    reapproval["verdict"]["action"] = json!("require-reapproval");
    assert_eq!(run(reapproval, false)["title"], "Approve this install");
}

#[test]
fn a_connected_workspace_is_not_asked_to_sign_in() {
    let mut payload = payload();
    payload["supply_chain"] = json!({"bundle": {"workspace_id": "w"}});
    let answer = run(payload, false);
    assert!(!lines(&answer)
        .iter()
        .any(|line| line.contains("hol-guard connect")));
}

#[test]
fn request_ids_fall_back_to_the_resume_request() {
    let mut payload = payload();
    payload["approval_request_ids"] = json!(["", 7]);
    payload["approval_resume"] = json!({"request_id": "resume-1"});
    assert_eq!(
        run(payload.clone(), false)["request_ids"],
        json!(["resume-1"])
    );
    payload["approval_resume"] = json!({"request_id": ""});
    assert_eq!(run(payload, false)["request_ids"], json!([]));
}

#[test]
fn prompt_names_the_install_and_its_reason() {
    let answer = run(payload(), false);
    assert_eq!(
        answer["prompt"],
        "\nHOL Guard paused this install before it ran.\n  bun install -g @openai/codex\n  New package version.\n\n  y  Allow once\n  a  Always allow this exact install (Guard asks again if the package changes)\n  n  Keep it blocked\n\nAllow this install? [y/a/N] "
    );
    let bold = dispatch(&json!({"payload": payload(), "from_agent": false, "emphasis": true}))
        .expect("guidance");
    assert!(bold["prompt"]
        .as_str()
        .expect("prompt")
        .starts_with("\n\u{1b}[1mHOL Guard paused this install before it ran.\u{1b}[0m\n"));
}

#[test]
fn request_text_cannot_restyle_the_prompt() {
    let mut payload = payload();
    payload["request"] = json!({"command": ["bun", "add", "pkg\u{1b}[2Jcleared"]});
    payload["verdict"]["reason"] = json!("bad\u{7}reason");
    let prompt = run(payload, false)["prompt"]
        .as_str()
        .expect("prompt")
        .to_owned();
    assert!(!prompt.contains('\u{1b}'));
    assert!(prompt.contains("bun add 'pkg?[2Jcleared'"));
    assert!(prompt.contains("bad?reason"));
}

#[test]
fn retry_line_is_quoted_and_names_the_manager_the_shim_wraps() {
    let mut payload = payload();
    payload["request"] = json!({"command": ["/opt/real/bin/bun", "add", "left-pad; rm -rf ~", 3]});
    assert_eq!(
        command_text(payload.as_object().expect("payload")),
        "bun add 'left-pad; rm -rf ~'"
    );
    payload["request"] = json!({"command": ["/opt/real/bin/", "add"]});
    assert_eq!(
        command_text(payload.as_object().expect("payload")),
        "/opt/real/bin/ add"
    );
    payload["request"] = json!({"command": "  npm i x  "});
    assert_eq!(
        command_text(payload.as_object().expect("payload")),
        "npm i x"
    );
    payload["request"] = json!({"command": [1]});
    assert_eq!(command_text(payload.as_object().expect("payload")), "");
}

#[test]
fn signed_url_wins_and_an_explicitly_absent_dashboard_url_is_dropped() {
    let mut signed = payload();
    signed["_ephemeral_signed_approval_url"] = json!(" https://hol.org/a?sig=1 ");
    assert_eq!(
        lines(&run(signed, true)).last().copied(),
        Some("Review: https://hol.org/a?sig=1")
    );
    let mut absent = payload();
    absent["supply_chain_evaluation"]["user_copy"]["dashboard_url"] = Value::Null;
    assert!(!lines(&run(absent.clone(), true))
        .iter()
        .any(|line| line.starts_with("Review: ")));
    absent["primary_approval_url"] = json!("http://127.0.0.1:5474/x");
    assert_eq!(
        lines(&run(absent, true)).last().copied(),
        Some("Review: http://127.0.0.1:5474/x")
    );
}

#[test]
fn a_link_already_in_the_message_is_not_repeated() {
    let mut payload = payload();
    payload["supply_chain_evaluation"]["user_copy"] = json!({
        "harness_message": "Approve at http://127.0.0.1:5474/requests/req-1.",
        "next_step": "Approve at",
        "dashboard_url": "http://127.0.0.1:5474/requests/req-1",
    });
    assert_eq!(
        lines(&run(payload.clone(), true)),
        vec!["Approve at http://127.0.0.1:5474/requests/req-1."]
    );
    payload["supply_chain"] = json!({"bundle": {"workspace_id": "w"}});
    assert_eq!(
        lines(&run(payload, false))[0],
        "Approve in the browser: http://127.0.0.1:5474/requests/req-1"
    );
}

#[test]
fn approval_link_prefers_the_review_line() {
    let guidance = vec![
        "See https://docs.example/x).".to_owned(),
        "Review: https://hol.org/r]".to_owned(),
    ];
    assert_eq!(approval_link(&guidance), "https://hol.org/r");
    assert_eq!(approval_link(&guidance[..1]), "https://docs.example/x");
    assert_eq!(approval_link(&["no link".to_owned()]), "");
}

#[test]
fn request_shape_is_exact() {
    let mut payload = payload();
    assert!(dispatch(&json!({"payload": payload, "from_agent": false})).is_err());
    assert!(dispatch(&json!({"payload": payload, "from_agent": 1, "emphasis": false})).is_err());
    payload["extra"] = json!(1);
    assert_eq!(
        dispatch(&json!({"payload": payload, "from_agent": false, "emphasis": false})),
        Err(ERR_INVALID)
    );
    payload.as_object_mut().expect("payload").remove("extra");
    payload.as_object_mut().expect("payload").remove("verdict");
    assert_eq!(
        dispatch(&json!({"payload": payload, "from_agent": false, "emphasis": false})),
        Err(ERR_INVALID)
    );
}
