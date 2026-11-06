//! Why the relay answered a `tools/call` with "no native decision".
//!
//! The host only sees the fail-closed block, so the relay names the cause on
//! its stderr: the resident's defer code, or the relay-side reason the call
//! never reached a decision. The line carries a fixed-shape code and nothing
//! from the call, which keeps the deferral rate measurable before the relay is
//! advertised.

use std::io::Write;

use serde_json::Value;

/// The relay could not build session facts for its launch.
pub(super) const FACTS_UNAVAILABLE: &str = "mcp_relay_facts_unavailable";
/// The call cannot be sent as the proxy would see it.
pub(super) const REQUEST_UNSENDABLE: &str = "mcp_relay_request_unsendable";
/// No live resident answered within the decision deadline.
pub(super) const RESIDENT_UNREACHABLE: &str = "mcp_relay_resident_unreachable";
/// The resident answered with something other than a decision.
pub(super) const REPLY_INVALID: &str = "mcp_relay_reply_invalid";
/// The resident asked for the package evaluation and the relay has none: the
/// call carries no intent this process reads, its environment is not one the
/// proxy could send, or the evaluation itself did not settle on a verdict.
pub(super) const PACKAGE_UNEVALUATED: &str = "mcp_relay_package_unevaluated";
/// The decide carrying the evaluation asked for one again, which is no
/// decision: the evaluation is performed once per call.
pub(super) const PACKAGE_UNDECIDED: &str = "mcp_relay_package_undecided";
/// The stderr prefix a deferral line starts with.
pub(super) const DEFER_LINE_PREFIX: &str = "hol-guard mcp-relay: no native decision: ";
const MAX_CODE_BYTES: usize = 64;

/// The resident's defer code, when `output` is a well-formed deferral.
pub(super) fn defer_code(output: &[u8]) -> Option<String> {
    let result: Value = serde_json::from_slice(output).ok()?;
    if result.get("schema")?.as_str()? != super::RESULT_SCHEMA
        || result.get("outcome")?.as_str()? != "defer"
    {
        return None;
    }
    let reason = result.get("reason")?.as_str()?;
    is_code(reason).then(|| reason.to_owned())
}

/// The cause of a reply that was not a forward or a block.
pub(super) fn reply_cause(output: Option<&[u8]>) -> String {
    match output {
        None => RESIDENT_UNREACHABLE.to_owned(),
        Some(bytes) => defer_code(bytes).unwrap_or_else(|| REPLY_INVALID.to_owned()),
    }
}

/// `[a-z0-9_]{1,64}`: a code never carries call content.
pub(super) fn is_code(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_CODE_BYTES
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The stderr line for one undecided call.
pub(super) fn defer_line(cause: &str) -> String {
    let code = if is_code(cause) { cause } else { REPLY_INVALID };
    format!("{DEFER_LINE_PREFIX}{code}\n")
}

/// Name the cause on stderr; a closed stderr never affects the answer.
pub(super) fn note(cause: &str) {
    let _ = std::io::stderr().write_all(defer_line(cause).as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bytes(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn a_resident_deferral_names_its_code() {
        let defer = json!({"schema": super::super::RESULT_SCHEMA, "outcome": "defer", "reason": "mcp_relay_policy_need"});
        assert_eq!(
            defer_code(&bytes(defer.clone())).as_deref(),
            Some("mcp_relay_policy_need")
        );
        assert_eq!(reply_cause(Some(&bytes(defer))), "mcp_relay_policy_need");
    }

    #[test]
    fn anything_else_is_unreachable_or_invalid() {
        assert_eq!(reply_cause(None), RESIDENT_UNREACHABLE);
        for other in [
            json!({"schema": super::super::RESULT_SCHEMA, "outcome": "defer"}),
            json!({"schema": super::super::RESULT_SCHEMA, "outcome": "defer", "reason": "Has Spaces"}),
            json!({"schema": super::super::RESULT_SCHEMA, "outcome": "defer", "reason": "x".repeat(65)}),
            json!({"schema": "other", "outcome": "defer", "reason": "mcp_relay_policy_need"}),
            json!({"schema": super::super::RESULT_SCHEMA, "outcome": "forward", "ticket": "e:1"}),
        ] {
            assert_eq!(reply_cause(Some(&bytes(other))), REPLY_INVALID);
        }
        assert_eq!(reply_cause(Some(b"not json")), REPLY_INVALID);
    }

    #[test]
    fn a_defer_line_carries_only_a_code() {
        assert_eq!(
            defer_line(REQUEST_UNSENDABLE),
            format!("{DEFER_LINE_PREFIX}mcp_relay_request_unsendable\n")
        );
        assert_eq!(
            defer_line("secret value\nforged"),
            format!("{DEFER_LINE_PREFIX}{REPLY_INVALID}\n")
        );
        assert!(is_code(FACTS_UNAVAILABLE));
    }
}
