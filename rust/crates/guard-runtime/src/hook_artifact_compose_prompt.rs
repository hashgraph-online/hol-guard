//! The prompt-request reason query of `HookArtifactCompose`. Pure: the
//! caller passes the classes the prompt was read as, and the reason it gets
//! back is the wording before any harness applies its own.

use guard_contracts::PromptRequestReasonQueryV1;
use serde_json::{json, Value};

/// The class that makes a prompt a hard block rather than a flagged request.
const GUARD_BYPASS_INTENT: &str = "guard_bypass_intent";
/// The class that names a prompt as asking for local secrets.
const SECRET_READ: &str = "secret_read";
/// Actions that stop a prompt outright rather than flag it.
const PROMPT_STOP_ACTIONS: [&str; 2] = ["block", "sandbox-required"];

/// What a flagged prompt request tells the user. The harness wording is
/// applied later; this is the reason itself.
pub(crate) fn prompt_request_reason(query: &PromptRequestReasonQueryV1) -> Value {
    let has = |class: &str| query.prompt_classes.iter().any(|item| item == class);
    let bypass_intent = has(GUARD_BYPASS_INTENT);
    let secret_read = has(SECRET_READ);
    if query.harness.as_deref() == Some("codex") && secret_read {
        let credential_file = query
            .prompt_summary
            .as_deref()
            .is_some_and(|summary| summary.contains("credential-looking local file"));
        let opened = if credential_file {
            "a credential-looking local file"
        } else {
            "a sensitive local file"
        };
        return json!({
            "reason": format!(
                "HOL Guard stopped this Codex prompt before Codex could open {opened}. Codex does not \
                 expose native approval prompts for Read-tool file reads, so Guard blocks this request \
                 at prompt time."
            )
        });
    }
    let stopped = query
        .policy_action
        .as_deref()
        .is_some_and(|action| PROMPT_STOP_ACTIONS.contains(&action));
    if stopped && !bypass_intent {
        return json!({
            "reason": "HOL Guard blocked this prompt because it requests guarded local secret access."
        });
    }
    if bypass_intent {
        return json!({
            "reason": "HOL Guard blocked this prompt because it asks to bypass or disable Guard."
        });
    }
    if secret_read {
        return json!({
            "reason": "HOL Guard flagged this prompt because it asks for direct local secret access and is \
                       protecting your local secrets. If that is intentional, continue and Guard will ask \
                       again on the actual tool call."
        });
    }
    json!({
        "reason": "HOL Guard flagged this prompt as higher risk. Continue only if you expect the next tool \
                   call to need explicit approval."
    })
}
