//! Project a local Claude hook without sorting its answers.

use guard_contracts::HOOK_AUTHORITY_STATE_MAX_BYTES;
use serde_json::{json, Value};

use super::{python_lower, python_strip};
use crate::bounded_hook_bridge_render::member;
use crate::pyjson::{self, PyVal};

pub(crate) fn project_hook_question(raw: &str) -> Option<Value> {
    // A nested JSON string must meet the same structural limits as the outer
    // resident frame before the order-preserving reader sees it.
    let _ = crate::strict_json::parse(raw.as_bytes()).ok()?;
    let raw = pyjson::parse(raw).ok()?;
    let fields = raw.as_dict()?;
    let field = |key| member(fields, key);
    let Some(PyVal::Str(event)) = field("event") else {
        return None;
    };
    let Some(PyVal::Str(tool_name)) = field("tool_name") else {
        return None;
    };
    if event != "PostToolUse" || python_lower(python_strip(tool_name)) != "askuserquestion" {
        return None;
    }

    let raw_response = field("tool_response");
    let mut response = raw_response.map_or(Some(Value::Null), PyVal::to_json)?;
    let mut ordered_answers = Value::Null;
    if let Some(PyVal::Dict(answers)) = raw_response
        .and_then(PyVal::as_dict)
        .and_then(|fields| member(fields, "answers"))
    {
        let pairs = answers
            .iter()
            .map(|(question, answer)| Some(json!([question, answer.to_json()?])))
            .collect::<Option<Vec<_>>>()?;
        ordered_answers = Value::Array(pairs);
        response.as_object_mut()?.remove("answers");
    }
    let projection = json!({
        "event": event,
        "tool_name": tool_name,
        "tool_input": field("tool_input").map_or(Some(Value::Null), PyVal::to_json)?,
        "tool_response": response,
        "response_answers": ordered_answers,
    });
    (serde_json::to_vec(&projection).ok()?.len() <= HOOK_AUTHORITY_STATE_MAX_BYTES)
        .then_some(projection)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_keep_hook_order_before_they_are_compared() {
        let output = project_hook_question(
            r#"{"event":"PostToolUse","tool_name":" AskUserQuestion ",
                "tool_response":{"answers":{"z prompt":{"label":"Keep blocked"},
                    "a prompt":"Allow once"},"status":"complete"}}"#,
        )
        .expect("question");
        assert_eq!(
            output["response_answers"],
            json!([["z prompt", {"label": "Keep blocked"}], ["a prompt", "Allow once"]])
        );
        assert_eq!(output["tool_response"], json!({"status":"complete"}));
        assert!(output["tool_input"].is_null());
    }

    #[test]
    fn filters_other_events_and_leaves_non_object_answers_on_the_response() {
        assert!(
            project_hook_question(r#"{"event":"PreToolUse","tool_name":"AskUserQuestion"}"#)
                .is_none()
        );
        assert!(project_hook_question(r#"{"event":"PostToolUse","tool_name":"Bash"}"#).is_none());
        let output = project_hook_question(
            r#"{"event":"PostToolUse","tool_name":"AskUserQuestion","tool_response":{"answers":["Keep blocked"]}}"#,
        )
        .expect("question");
        assert!(output["response_answers"].is_null());
        assert_eq!(output["tool_response"], json!({"answers":["Keep blocked"]}));
    }

    #[test]
    fn rejects_a_repeated_key_in_the_embedded_hook() {
        assert!(project_hook_question(
            r#"{"event":"PostToolUse","tool_name":"Bash","tool_name":"AskUserQuestion"}"#,
        )
        .is_none());
    }
}
