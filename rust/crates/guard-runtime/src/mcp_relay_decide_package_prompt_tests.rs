//! When a package call is prompted inline, and how the forward an approval
//! led to is recorded.

use guard_command::effect_decision::GuardAction;
use serde_json::json;

use super::*;
use crate::mcp_tool_policy_decision::Current;

fn decision(source: &str) -> Decision {
    Decision::plain(Current {
        action: GuardAction::RequireReapproval,
        source: source.to_owned(),
        signals: vec!["Opens an external site.".to_owned()],
        summary: "browser navigation".to_owned(),
        risk_categories: vec!["browser_navigation".to_owned()],
    })
}

#[test]
fn a_package_call_is_prompted_where_a_plain_call_would_be() {
    let prompts = |mode: &str, harness: &str, inline: bool, decision: &Decision| {
        Call {
            catalog_state: "complete",
            mode,
            tool_name: "run",
            harness,
            inline_available: inline,
        }
        .prompts(decision)
    };
    let reviewed = decision("policy");
    for mode in ["observe", "enforce"] {
        // The client's inline elicitation runs before the package lane would
        // observe or queue the call.
        assert!(prompts(mode, "codex", true, &reviewed), "{mode}");
        // Without one the route falls through to the leg the lane takes.
        assert!(!prompts(mode, "codex", false, &reviewed), "{mode}");
        // The opencode proxy never elicits inline. Its native prompt raises
        // nothing, and the package handler it leads to composes the lane from
        // a fresh tool authority, so the lane answers the call either way.
        assert!(
            !prompts(mode, ask::OPENCODE, false, &decision("approval-gate")),
            "{mode}"
        );
        assert!(
            !prompts(mode, ask::OPENCODE, true, &decision("approval-gate")),
            "{mode}"
        );
        assert!(!prompts(mode, ask::OPENCODE, true, &reviewed), "{mode}");
    }
    // An executable decision, a terminal one or a saved block never prompts.
    let mut allowed = decision("policy");
    allowed.action = GuardAction::Allow;
    assert!(!prompts("observe", "codex", true, &allowed));
    let mut blocked = decision("policy");
    blocked.action = GuardAction::Block;
    assert!(!prompts("observe", "codex", true, &blocked));
    let mut saved = decision("policy");
    saved.saved_action = Some(GuardAction::Block);
    assert!(!prompts("observe", "codex", true, &saved));
}

#[test]
fn an_approved_forward_is_recorded_as_the_proxy_records_it() {
    let remembered = Remembered {
        remember: true,
        signals: vec!["Installs a package.".to_owned()],
        risk_categories: vec!["package_install".to_owned()],
        generation: Some(1),
    };
    let mut record = json!({
        "decision_source": "policy-allow",
        "package": {"signals": ["Lane signal."]},
    });
    mark_forward(&remembered, &mut record);
    assert_eq!(record["decision_source"], INLINE_SOURCE);
    assert_eq!(record["package"]["signals"], json!(["Installs a package."]));
    assert_eq!(
        record["package"]["risk_categories"],
        json!(["package_install"])
    );
    assert_eq!(record["remember"], json!(true));
    // A provider action whose calls are each reviewed saves no allow, and a
    // decision with no signals keeps the lane's own.
    let quiet = Remembered {
        remember: false,
        signals: Vec::new(),
        risk_categories: Vec::new(),
        generation: None,
    };
    let mut record = json!({
        "decision_source": "policy-allow",
        "package": {"signals": ["Lane signal."]},
    });
    mark_forward(&quiet, &mut record);
    assert_eq!(record["decision_source"], INLINE_SOURCE);
    assert_eq!(record["package"]["signals"], json!(["Lane signal."]));
    assert_eq!(record["package"]["risk_categories"], json!([]));
    assert!(record.get("remember").is_none());
}
