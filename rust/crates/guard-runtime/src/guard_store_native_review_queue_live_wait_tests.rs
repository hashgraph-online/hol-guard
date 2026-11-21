//! Which silent queue writes keep a waiting Codex hook's live-wait facts.

use serde_json::{json, Value};

use super::{args, delegate};

#[test]
fn a_silent_block_that_links_its_approval_keeps_the_codex_wait() {
    let facts = json!({"process": {"pid": 1}, "timeout_seconds": 90, "workspace": null});
    let delegated = delegate(&args(json!({
        "silent": true,
        "respond": {"silent_review_block": {"ask": false, "home_dir": "/home/u"}},
        "codex_live_wait_facts": facts,
    })))
    .unwrap();
    assert_eq!(
        delegated.method,
        "add_silent_native_review_approval_request"
    );
    assert_eq!(
        delegated.args[crate::codex_live_wait_build::FACTS_KEY],
        facts
    );
}

#[test]
fn a_silent_block_that_cannot_link_its_approval_holds_no_wait() {
    // Approving a row bound to neither the retry nor an exact-action Always
    // cannot let the agent run the action, so the block names no link and no
    // bridge waits on it.
    let mut call = args(json!({
        "silent": true,
        "respond": {"silent_review_block": {"ask": false, "home_dir": "/home/u"}},
        "codex_live_wait_facts": {"process": {"pid": 1}, "timeout_seconds": 90},
    }));
    call["review"]["review_binding"] = Value::Null;
    let delegated = delegate(&call).unwrap();
    assert!(!delegated
        .args
        .contains_key(crate::codex_live_wait_build::FACTS_KEY));
}
