//! `HookRender` - resident op that renders a harness response for a verdict
//! the daemon adjusted after the edge decision.
//!
//! Pure: the caller ships the adjusted verdict (and the queued approval for a
//! review), the resident returns the exact harness JSON. Rendering itself
//! lives in `guard_command::hook_responses`, shared with the edge decision.

use guard_command::hook_responses::cli_documents::{cli_document, cli_response, CliOutcome};
use guard_command::hook_responses::{pre_tool, pre_tool_review, recording_only_pre_tool, Object};
use guard_contracts::{
    HookRenderRequestV1, HookRenderResultV1, HOOK_RENDER_MAX_BYTES, HOOK_RENDER_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_hook_render_request(
    request: &HookRenderRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, HOOK_RENDER_MAX_BYTES)
        .map_err(|_| "native_hook_render_too_large".to_owned())?;
    let (status, code, payload) = match render(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::encode_response(&HookRenderResultV1 {
        schema: HOOK_RENDER_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn object_of(value: Option<&Value>) -> Option<&Object> {
    value.and_then(Value::as_object)
}

fn cli_payload(outcome: CliOutcome) -> Value {
    match outcome {
        CliOutcome::Silent => json!({ "outcome": "silent" }),
        CliOutcome::Fallback => json!({ "outcome": "fallback" }),
        CliOutcome::Document(document) => {
            json!({ "outcome": "document", "response": Value::Object(document) })
        }
    }
}

fn render(request: &HookRenderRequestV1) -> Result<Value, &'static str> {
    let harness = request.harness.as_str();
    if matches!(request.kind.as_str(), "cli_response" | "cli_document") {
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        return Ok(if request.kind == "cli_response" {
            cli_payload(
                cli_response(harness, params).map_or(CliOutcome::Silent, CliOutcome::Document),
            )
        } else {
            cli_payload(cli_document(harness, params))
        });
    }
    render_edge(request).map(|response| json!({ "response": Value::Object(response) }))
}

fn render_edge(request: &HookRenderRequestV1) -> Result<Object, &'static str> {
    let harness = request.harness.as_str();
    match request.kind.as_str() {
        "pre_tool" => {
            let verdict =
                object_of(request.verdict.as_ref()).ok_or("native_hook_render_invalid")?;
            Ok(pre_tool(harness, verdict))
        }
        "pre_tool_review" => {
            let verdict =
                object_of(request.verdict.as_ref()).ok_or("native_hook_render_invalid")?;
            Ok(pre_tool_review(
                harness,
                verdict,
                object_of(request.approval.as_ref()),
                request.linked_reason.as_deref(),
            ))
        }
        "recording_only_pre_tool" => Ok(recording_only_pre_tool(
            harness,
            request
                .reason_code
                .as_deref()
                .ok_or("native_hook_render_invalid")?,
            request
                .reason
                .as_deref()
                .ok_or("native_hook_render_invalid")?,
        )),
        _ => Err("native_hook_render_invalid"),
    }
}

#[cfg(test)]
#[path = "hook_render_op_tests.rs"]
mod tests;
