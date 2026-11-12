//! `HookRender` - resident op that renders a harness response for a verdict
//! the daemon adjusted after the edge decision.
//!
//! Pure: the caller ships the adjusted verdict (and the queued approval for a
//! review), the resident returns the exact harness JSON. Rendering itself
//! lives in `guard_command::hook_responses`, shared with the edge decision.
//!
//! The op also answers the named-string questions the CLI hook path asks
//! before it has a verdict - the approval copy a Claude prompt shows, and the
//! artifact id an event is filed under - so no rule that decides what a user
//! sees or which override applies is evaluated outside the runtime.

use std::path::Path;

use crate::hook_cli_claude_text::claude_approval_copy;
use crate::hook_cli_emit::{
    cli_hook_emit_document, cli_hook_emit_printed_document, PrintedDocument,
};
use guard_command::hook_responses::cli_documents::{
    cli_document, cli_response, copilot_hook_response, CliOutcome,
};
use guard_command::hook_responses::{
    hermes, muse, pre_tool, pre_tool_review, recording_only_pre_tool, Object,
};
use guard_contracts::{
    artifact_id_from_event, cursor_after_shell_observed, cursor_observer_event_for_payload,
    evaluation_has_terminal_policy_action, hook_render_max_bytes, HookRenderRequestV1,
    HookRenderResultV1, HOOK_RENDER_RESULT_SCHEMA, MAX_NATIVE_RESPONSE_BYTES,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_hook_render_request(
    request: &HookRenderRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, hook_render_max_bytes(&request.kind))
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

/// What a `cli_hook_emit` document may take up. A caller reads the answer
/// over the resident stream, which refuses anything past
/// `MAX_NATIVE_RESPONSE_BYTES`, so the rest of the result - its schema,
/// request id and digest - has to fit alongside the document.
const CLI_EMIT_DOCUMENT_BUDGET_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 128 * 1024;

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
    if request.kind == "claude_approval_copy" {
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let which = params
            .get("which")
            .and_then(Value::as_str)
            .ok_or("native_hook_render_invalid")?;
        let payload = object_of(params.get("payload"))
            .cloned()
            .unwrap_or_default();
        let notice = object_of(params.get("notice")).cloned();
        let reason = params.get("reason").and_then(Value::as_str).unwrap_or("");
        let value = claude_approval_copy(which, &payload, notice.as_ref(), reason)
            .ok_or("native_hook_render_invalid")?;
        let mut document = Object::new();
        document.insert("value".into(), value);
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if request.kind == "artifact_id" {
        // The artifact an event belongs to is what a configured action
        // override is keyed on, so the resident names it rather than reading a
        // name Python derived. Only the payload fields the rule reads travel.
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let canonical_harness = params
            .get("canonical_harness")
            .and_then(Value::as_str)
            .ok_or("native_hook_render_invalid")?;
        let payload = object_of(params.get("payload"))
            .cloned()
            .unwrap_or_default();
        let mut document = Object::new();
        document.insert(
            "value".into(),
            Value::String(artifact_id_from_event(harness, canonical_harness, &payload)),
        );
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if request.kind == "terminal_policy_action" {
        // Whether an approval could still change the outcome is a verdict about
        // the verdict: a block or sandbox-required answer is not a question to
        // put to a user. The resident reads its own evaluation rather than
        // letting the caller re-rank the actions it just returned.
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let evaluation = object_of(params.get("evaluation")).ok_or("native_hook_render_invalid")?;
        let mut document = Object::new();
        document.insert(
            "value".into(),
            Value::Bool(evaluation_has_terminal_policy_action(evaluation)),
        );
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if request.kind == "cursor_observer_event" {
        // The event names a field of the message an after-observer proof is
        // computed over, and the side that issues a proof and the side that
        // checks it both derive it from the same harness-supplied payload.
        // One answer keeps them from drifting apart.
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let payload = object_of(params.get("payload")).ok_or("native_hook_render_invalid")?;
        let mut document = Object::new();
        document.insert(
            "value".into(),
            Value::String(cursor_observer_event_for_payload(payload).to_string()),
        );
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if request.kind == "cursor_after_shell_observed" {
        // Reading a before-event as an after-report would turn a pending
        // approval into a durable allowance for a command nobody watched
        // finish, so the resident reads the payload rather than trusting the
        // caller's account of what the harness reported.
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let payload = object_of(params.get("payload")).ok_or("native_hook_render_invalid")?;
        let mut document = Object::new();
        document.insert(
            "value".into(),
            Value::Bool(cursor_after_shell_observed(payload)),
        );
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if request.kind == "cursor_shell_route" {
        // Whether Cursor's probe moves into the sandbox, and whether a shell
        // call is the sink command a probe wrote, is the resident's reading
        // on the daemon path as on the direct lane.
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let mut document = Object::new();
        document.insert(
            "value".into(),
            crate::hook_direct::cursor::daemon_answer(params)?.unwrap_or(Value::Null),
        );
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if request.kind == "hermes_bridge" {
        // A daemon reply reaches Hermes as a decision object plus an exit
        // status. Reading that reply is a verdict about a verdict, so the
        // resident reads it and names the status rather than letting the
        // forwarding side decide what the answer meant.
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let response = object_of(params.get("response")).ok_or("native_hook_render_invalid")?;
        let (stdout_document, exit_code) = hermes::bridge_response(response);
        let mut document = Object::new();
        document.insert("document".into(), Value::Object(stdout_document));
        document.insert("exit_code".into(), json!(exit_code));
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if request.kind == "muse_bridge" {
        // Muse reads an allow as empty stdout: an explicit allow without an
        // updated input is rejected outright. The document is therefore
        // optional, and a null one is the silence Muse takes as permission.
        // Which answers earn that silence is a verdict about a verdict, so
        // the resident names it rather than the hook that prints it.
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let response = object_of(params.get("response")).ok_or("native_hook_render_invalid")?;
        let event_name = params
            .get("event_name")
            .and_then(Value::as_str)
            .ok_or("native_hook_render_invalid")?;
        let (stdout_document, exit_code) = muse::bridge_response(response, event_name);
        let mut document = Object::new();
        document.insert(
            "document".into(),
            stdout_document.map_or(Value::Null, Value::Object),
        );
        document.insert("exit_code".into(), json!(exit_code));
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if request.kind == "cli_hook_emit" {
        // The `hol-guard hook` command prints the daemon's answer and exits
        // with the status that answer means to the harness. Reading which
        // verdict the answer gave is the resident's call, not the printer's.
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        let event_name = params
            .get("event_name")
            .and_then(Value::as_str)
            .ok_or("native_hook_render_invalid")?;
        let response_json = params
            .get("response_json")
            .and_then(Value::as_str)
            .ok_or("native_hook_render_invalid")?;
        // The store the caller's command names. Optional on the wire: a
        // caller that sends none gets the recovery line for the default
        // home, which is what every caller printed before this key existed.
        let guard_home = params.get("guard_home").and_then(Value::as_str);
        // The Python bounded bridge prints the harness's own output for
        // every harness it launches, not only the ones `hol-guard hook`
        // reshapes. Absent means the `hol-guard hook` reading.
        let bridge = params
            .get("bridge")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // A caller that prints the document the resident renders asks for it
        // with `document`, naming its own home so the paths it shortens are
        // the caller's. Absent means the policy action alone, which is all a
        // caller that printed its own document read.
        let printed = params
            .get("document")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            .then(|| PrintedDocument {
                home_dir: params.get("home_dir").and_then(Value::as_str),
            });
        let document = match printed {
            Some(printed) => cli_hook_emit_printed_document(
                harness,
                event_name,
                response_json,
                guard_home.map(Path::new),
                bridge,
                &printed,
            ),
            None => cli_hook_emit_document(
                harness,
                event_name,
                response_json,
                guard_home.map(Path::new),
                bridge,
            ),
        }
        .ok_or("native_hook_render_unrenderable")?;
        // An answer may be four times the size of a response, and the
        // printed document is larger again than the answer it renders: it
        // is indented, written as ASCII and escaped a second time as a JSON
        // string. A document the caller could never be handed is named here
        // instead of being dropped unexplained when the stream reads it.
        if serde_json::to_vec(&document).map_or(usize::MAX, |bytes| bytes.len())
            > CLI_EMIT_DOCUMENT_BUDGET_BYTES
        {
            return Err("native_hook_render_document_too_large");
        }
        return Ok(cli_payload(CliOutcome::Document(document)));
    }
    if matches!(
        request.kind.as_str(),
        "cli_response" | "cli_document" | "copilot_hook_response"
    ) {
        let params = object_of(request.cli.as_ref()).ok_or("native_hook_render_invalid")?;
        return Ok(match request.kind.as_str() {
            "cli_response" => cli_payload(
                cli_response(harness, params).map_or(CliOutcome::Silent, CliOutcome::Document),
            ),
            "copilot_hook_response" => {
                cli_payload(CliOutcome::Document(copilot_hook_response(params)))
            }
            _ => cli_payload(cli_document(harness, params)),
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
