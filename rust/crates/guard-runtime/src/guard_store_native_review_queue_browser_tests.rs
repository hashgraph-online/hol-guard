//! BP-T072: a stored browser row's hook reply names the site and the wait and
//! keeps its approval link, shared profiles included.

use serde_json::{json, Value};

use super::tests::{args, delegate};

const URL: &str = "http://127.0.0.1:4781/requests/req1";

fn browser_reply(profile: &str) -> Value {
    json!({
        "request_id": "req1",
        "row": {
            "request_id": "req1",
            "approval_url": URL,
            "browser_card": {
                "site": {
                    "origin": "https://shop.example",
                    "first_visit_in_task": false,
                    "left_granted_site": false,
                },
                "profile_line": profile,
            },
        },
    })
}

#[test]
fn a_shared_profile_browser_hold_still_names_the_link() {
    for profile in ["shared", "remote-debugging", "unknown", "dedicated"] {
        let reply = delegate(&args(json!({"respond": {"paused_review": {}}})))
            .unwrap()
            .with_response(browser_reply(profile), "/nonexistent/hol-guard");
        let text = reply["response"].to_string();
        assert!(
            text.contains("on `https://shop.example`"),
            "{profile}: {text}"
        );
        assert!(
            text.contains("do not retry the action in a loop"),
            "{profile}: {text}"
        );
        assert!(text.contains(URL), "{profile}: {text}");
    }
}
