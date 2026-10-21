//! Production entry for the sensitive-request classifiers.
//!
//! The resident answers each `secret_file_requests` query here over plain
//! JSON. Python sends the tool call and its own observations; it never sends
//! a verdict. A canonical command and native evaluation are bound only when
//! the resident reparses the same raw text to the identity both claim.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::benign_request_api::{
    is_benign_native_file_read, is_benign_tool_action, ovalue_from_json, ToolActionControls,
};
use crate::codex_output_env::Ctx;
use crate::command_evaluation::CommandDecisionFloor;
use crate::command_model::{parse_shell_command, CanonicalCommand};
use crate::compound_artifact::compound_artifact;
use crate::hook_adapter_value::OValue;
use crate::sfrs_dispatcher::{extract_sensitive_tool_action_request, ExtractInputs};
use crate::sfrs_dispatcher_request::{NativeEvaluationView, ToolActionRequestMatch};
use crate::sfrs_gh_actions_read::is_nonexecuting_github_actions_read_workflow;
use crate::sfrs_gh_ephemeral_body::gh_pr_create_uses_safe_ephemeral_body;
use crate::sfrs_read_only_filters::read_only_lookup_target_is_safe;
use crate::sfrs_requests::{
    build_file_read_request_artifact, build_file_write_request_artifact, classify_sensitive_path,
    command_list_candidate_texts, extract_sensitive_file_read_request,
    extract_sensitive_file_read_request_from_action, extract_sensitive_file_write_request,
    FileReadRequest, FileWriteRequest, SensitivePath,
};
use crate::unmodeled_shell_artifact::unmodeled_shell_artifact;
use crate::CommandModelRequestV1;

#[cfg(all(test, unix))]
#[path = "sensitive_request_tests.rs"]
mod tests;

/// The queries [`evaluate`] answers.
pub const QUERIES: &[&str] = &[
    "tool_action",
    "file_read",
    "file_read_artifact",
    "file_read_from_action",
    "file_read_from_action_artifact",
    "file_write",
    "file_write_artifact",
    "classify_path",
    "command_list_candidate_texts",
    "benign_file_read",
    "benign_tool_action",
    "read_only_lookup_target_is_safe",
    "benign_github_shell",
    "unmodeled_shell_artifact",
    "compound_artifact",
];

/// Answer one query. `controls` is the extension-control snapshot the
/// resident derived, `None` when none was active.
///
/// # Errors
///
/// `Err` is a wire error code for an unknown query or malformed input. A
/// classifier `ValueError` is an `Ok` reply carrying `{"error": message}`.
pub fn evaluate(
    query: &str,
    input: &Value,
    ctx: &Ctx,
    controls: Option<&ToolActionControls>,
) -> Result<Value, &'static str> {
    if !input.is_object() {
        return Err(INVALID);
    }
    let cwd = path_field(input, "cwd")?;
    let home = path_field(input, "home_dir")?;
    let (cwd, home) = (cwd.as_deref(), home.as_deref());
    let field = |key: &str| field(input, key);
    match query {
        "tool_action" => tool_action(input, cwd, home, ctx, controls),
        "file_read" => Ok(read_wire(extract_sensitive_file_read_request(
            &ovalue_from_json(field("tool_name")),
            &ovalue_from_json(field("arguments")),
            cwd,
            home,
        ))),
        "file_read_artifact" => {
            let naming = ArtifactNaming::from_input(input)?;
            let found = extract_sensitive_file_read_request(
                &ovalue_from_json(field("tool_name")),
                &ovalue_from_json(field("arguments")),
                cwd,
                home,
            );
            Ok(naming.read_reply(found))
        }
        "file_read_from_action" => {
            let action = ovalue_from_json(field("action"));
            let found = action.as_map().and_then(|action| {
                extract_sensitive_file_read_request_from_action(action, cwd, home)
            });
            Ok(read_wire(found))
        }
        "file_read_from_action_artifact" => {
            let naming = ArtifactNaming::from_input(input)?;
            let action = ovalue_from_json(field("action"));
            let found = action.as_map().and_then(|action| {
                extract_sensitive_file_read_request_from_action(action, cwd, home)
            });
            Ok(naming.read_reply(found))
        }
        "file_write" => {
            let protected = protected_paths(field("protected_paths"))?;
            let found = extract_sensitive_file_write_request(
                &ovalue_from_json(field("tool_name")),
                &ovalue_from_json(field("arguments")),
                cwd,
                home,
                &protected,
            );
            Ok(found.map_or(Value::Null, |found| write_wire(&found)))
        }
        "file_write_artifact" => {
            let naming = ArtifactNaming::from_input(input)?;
            let protected = protected_paths(field("protected_paths"))?;
            let found = extract_sensitive_file_write_request(
                &ovalue_from_json(field("tool_name")),
                &ovalue_from_json(field("arguments")),
                cwd,
                home,
                &protected,
            );
            Ok(naming.write_reply(found))
        }
        "classify_path" => {
            let path = field("path").as_str().ok_or(INVALID)?;
            Ok(classify_sensitive_path(path, cwd, home)
                .map_or(Value::Null, |found| path_wire(&found)))
        }
        "command_list_candidate_texts" => {
            let OValue::List(values) = ovalue_from_json(field("values")) else {
                return Err(INVALID);
            };
            let preserve = field("preserve_items").as_bool().ok_or(INVALID)?;
            Ok(json!(command_list_candidate_texts(&values, preserve)))
        }
        "benign_file_read" => Ok(json!(is_benign_native_file_read(
            field("tool_name"),
            field("arguments"),
            cwd,
            home,
            ctx,
        ))),
        "benign_tool_action" => Ok(json!(is_benign_tool_action(
            field("tool_name"),
            field("arguments"),
            cwd,
            home,
            ctx,
            controls,
        ))),
        "read_only_lookup_target_is_safe" => {
            let target = field("target").as_str().ok_or(INVALID)?;
            let allow_dirs = field("allow_dirs").as_bool().ok_or(INVALID)?;
            Ok(json!(read_only_lookup_target_is_safe(
                target, allow_dirs, home
            )))
        }
        // A read-only Actions workflow or a static ephemeral PR body needs no
        // unmodeled-shell review.
        "benign_github_shell" => {
            let command = field("command_text").as_str().ok_or(INVALID)?;
            Ok(json!(
                is_nonexecuting_github_actions_read_workflow(command, None, ctx)
                    || gh_pr_create_uses_safe_ephemeral_body(command, ctx)
            ))
        }
        "unmodeled_shell_artifact" => unmodeled_shell_artifact(input, ctx),
        "compound_artifact" => compound_artifact(input, cwd, home, ctx),
        _ => Err("native_sensitive_request_query_unknown"),
    }
}

const INVALID: &str = "native_sensitive_request_input_invalid";

static NULL: Value = Value::Null;

fn field<'a>(input: &'a Value, key: &str) -> &'a Value {
    input.get(key).unwrap_or(&NULL)
}

fn path_field(input: &Value, key: &str) -> Result<Option<PathBuf>, &'static str> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !text.contains('\0') => Ok(Some(PathBuf::from(text))),
        Some(_) => Err(INVALID),
    }
}

fn protected_paths(value: &Value) -> Result<Vec<(String, String)>, &'static str> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Object(map) => map
            .iter()
            .map(|(path, label)| Ok((path.clone(), label.as_str().ok_or(INVALID)?.to_owned())))
            .collect(),
        _ => Err(INVALID),
    }
}

const DIALECTS: &[&str] = &["posix", "powershell", "cmd", "argv", "unknown"];
const TRANSPORTS: &[&str] = &["shell_string", "argv", "embedded_script"];
const MAX_PROVENANCE_BYTES: usize = 128;

/// One parse setting of the claim: absent means the Python default, and a
/// present value must be one the parser knows.
fn claim_setting<'a>(
    claim: &'a Value,
    key: &str,
    default: &'a str,
    allowed: Option<&[&str]>,
) -> Result<&'a str, &'static str> {
    let value = match claim.get(key) {
        None | Some(Value::Null) => return Ok(default),
        Some(value) => value.as_str().ok_or(INVALID)?,
    };
    let known = allowed.map_or(
        !value.is_empty() && value.len() <= MAX_PROVENANCE_BYTES,
        |allowed| allowed.contains(&value),
    );
    known.then_some(value).ok_or(INVALID)
}

/// The caller's canonical command, rebuilt here with the caller's parse
/// settings, with the claimed identity it bound under. It binds only when
/// that identity agrees with the resident's own parse.
fn bound_canonical(
    input: &Value,
    cwd: Option<&Path>,
    home: Option<&Path>,
) -> Result<Option<(CanonicalCommand, String)>, &'static str> {
    let claim = match input.get("canonical") {
        None | Some(Value::Null) => return Ok(None),
        Some(claim) => claim,
    };
    let raw_text = claim["raw_text"].as_str().ok_or(INVALID)?;
    let identity = claim["security_identity"].as_str().ok_or(INVALID)?;
    if raw_text.trim().is_empty() {
        return Err(INVALID);
    }
    let dialect = claim_setting(claim, "dialect", "posix", Some(DIALECTS))?;
    let transport = claim_setting(claim, "transport", "shell_string", Some(TRANSPORTS))?;
    let provenance = claim_setting(claim, "extraction_provenance", "guard-shell", None)?;
    let command = parse_shell_command(raw_text, cwd, home, dialect, transport, provenance, true);
    if command.security_identity() == identity {
        return Ok(Some((command, identity.to_owned())));
    }
    // Native evaluation stores this parse with redirects and embedded
    // commands removed. Accept that identity, then classify the full parse
    // so a nested executor stays visible.
    let mut native_evaluation =
        parse_shell_command(raw_text, cwd, home, dialect, transport, provenance, true);
    native_evaluation.redirects.clear();
    native_evaluation.embedded_commands.clear();
    if native_evaluation.security_identity() == identity
        || native_model_identity(raw_text, dialect, transport, provenance).as_deref()
            == Some(identity)
    {
        return Ok(Some((command, identity.to_owned())));
    }
    Err("native_sensitive_request_canonical_unbound")
}

/// The identity the native command model gives `raw_text`. Native evaluation
/// stores this model, which keeps no segments for input it cannot prove (an
/// unsupported redirect, for one), so its identity differs from the full parse.
fn native_model_identity(
    raw_text: &str,
    dialect: &str,
    transport: &str,
    provenance: &str,
) -> Option<String> {
    let request = CommandModelRequestV1 {
        command: raw_text.to_owned(),
        dialect: dialect.to_owned(),
        transport: transport.to_owned(),
        extraction_provenance: provenance.to_owned(),
    };
    crate::parse_command(&request)
        .ok()
        .map(|model| model.security_identity)
}

fn text_list(value: &Value) -> Result<Vec<String>, &'static str> {
    value
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(INVALID))
        .collect()
}

fn optional_text(value: &Value) -> Result<Option<String>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        _ => Err(INVALID),
    }
}

fn floor(value: &Value) -> Result<CommandDecisionFloor, &'static str> {
    match value.as_str() {
        Some("allow") => Ok(CommandDecisionFloor::Allow),
        Some("monitor") => Ok(CommandDecisionFloor::Monitor),
        Some("review") => Ok(CommandDecisionFloor::Review),
        Some("block") => Ok(CommandDecisionFloor::Block),
        _ => Err(INVALID),
    }
}

/// The evaluation fields the classifier reads. `security_identity` is the
/// evaluated command's identity: the classifier applies the evaluation only
/// where it equals the bound canonical command's, as the legacy code did.
fn evaluation_view(input: &Value) -> Result<Option<NativeEvaluationView>, &'static str> {
    let view = match input.get("evaluation") {
        None | Some(Value::Null) => return Ok(None),
        Some(view) => view,
    };
    let identity = view["security_identity"].as_str().ok_or(INVALID)?;
    Ok(Some(NativeEvaluationView {
        security_identity: identity.to_owned(),
        minimum_action: floor(&view["minimum_action"])?,
        match_default_modes: text_list(&view["match_default_modes"])?,
        reason_codes: text_list(&view["reason_codes"])?,
        explicitly_enabled_permission_ids: text_list(&view["explicitly_enabled_permission_ids"])?,
        controlling_action_class: optional_text(&view["controlling_action_class"])?,
        controlling_reason: optional_text(&view["controlling_reason"])?,
    }))
}

fn tool_action(
    input: &Value,
    cwd: Option<&Path>,
    home: Option<&Path>,
    ctx: &Ctx,
    controls: Option<&ToolActionControls>,
) -> Result<Value, &'static str> {
    let bound = bound_canonical(input, cwd, home)?;
    let mut view = evaluation_view(input)?;
    // An evaluation of the accepted claim applies to the full parse that
    // replaced it; any other identity still fails the classifier's check.
    // A claim that bound through a reduced identity did not see the segments
    // that were dropped, so that evaluation cannot short-circuit as benign.
    if let (Some((command, claimed)), Some(view)) = (&bound, view.as_mut()) {
        if &view.security_identity == claimed {
            let full_identity = command.security_identity();
            let reduced = claimed != &full_identity;
            view.security_identity = full_identity;
            if reduced {
                view.reason_codes
                    .retain(|code| code != "native.explicit-benign");
                let allow_floor_only = view.minimum_action == CommandDecisionFloor::Allow
                    && !view.match_default_modes.is_empty()
                    && view
                        .match_default_modes
                        .iter()
                        .all(|mode| mode == "disabled");
                if allow_floor_only {
                    view.match_default_modes.clear();
                }
            }
        }
    }
    let canonical = bound.map(|(command, _)| command);
    let tool = ovalue_from_json(field(input, "tool_name"));
    let arguments = field(input, "arguments");
    let inputs = ExtractInputs {
        cwd,
        home_dir: home,
        canonical_command: canonical.as_ref(),
        native_evaluation: view.as_ref(),
        controls,
        ctx,
    };
    match extract_sensitive_tool_action_request(&tool, arguments, &inputs) {
        Ok(None) => Ok(json!({"match": null})),
        Ok(Some(found)) => Ok(json!({"match": tool_action_wire(&found)?})),
        Err(error) => Ok(json!({"error": error.0})),
    }
}

/// The match with its canonical command's `raw_text`, which `to_dict` omits.
fn tool_action_wire(found: &ToolActionRequestMatch) -> Result<Value, &'static str> {
    let mut wire = serde_json::to_value(found).map_err(|_| INVALID)?;
    if let (Some(command), Some(slot)) =
        (&found.canonical_command, wire.get_mut("canonical_command"))
    {
        if let Some(fields) = slot.as_object_mut() {
            fields.insert("raw_text".to_owned(), json!(command.raw_text));
            let Some(embedded) = fields
                .get_mut("embedded_commands")
                .and_then(Value::as_array_mut)
            else {
                return Err(INVALID);
            };
            if embedded.len() != command.embedded_commands.len() {
                return Err(INVALID);
            }
            for (slot, embedded_command) in embedded.iter_mut().zip(&command.embedded_commands) {
                let Some(object) = slot.as_object_mut() else {
                    return Err(INVALID);
                };
                object.insert("text".to_owned(), json!(embedded_command.text));
            }
        }
    }
    Ok(wire)
}

/// The naming a request artifact carries beyond the request itself: which
/// harness asked, which policy file the resulting review cites, and whether
/// the review is scoped to the project or to the account.
///
/// Python supplies these three because they describe the call site, not the
/// request; everything the artifact says *about* the request — its id, its
/// name and its metadata — is derived here, so one implementation decides
/// what a sensitive-request artifact is called and what it is keyed under.
struct ArtifactNaming {
    harness: String,
    config_path: String,
    source_scope: String,
}

impl ArtifactNaming {
    fn from_input(input: &Value) -> Result<Self, &'static str> {
        let text = |key: &str| {
            input
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(INVALID)
        };
        Ok(Self {
            harness: text("harness")?.to_owned(),
            config_path: text("config_path")?.to_owned(),
            source_scope: text("source_scope")?.to_owned(),
        })
    }

    /// The match and its artifact together. They travel in one reply because
    /// the caller needs both and a second round trip would let the request the
    /// artifact describes differ from the request the caller then acts on.
    fn read_reply(&self, found: Option<FileReadRequest>) -> Value {
        let artifact = found.as_ref().map(|found| {
            build_file_read_request_artifact(
                &self.harness,
                found,
                &self.config_path,
                &self.source_scope,
            )
        });
        json!({
            "match": read_wire(found),
            "artifact": artifact,
        })
    }

    fn write_reply(&self, found: Option<FileWriteRequest>) -> Value {
        let artifact = found.as_ref().map(|found| {
            build_file_write_request_artifact(
                &self.harness,
                found,
                &self.config_path,
                &self.source_scope,
            )
        });
        json!({
            "match": found.as_ref().map_or(Value::Null, write_wire),
            "artifact": artifact,
        })
    }
}

fn path_wire(found: &SensitivePath) -> Value {
    json!({
        "family": found.family,
        "path": found.path,
        "reason": found.reason,
        "requested_path": found.requested_path,
        "sensitivity": found.sensitivity,
    })
}

fn read_wire(found: Option<FileReadRequest>) -> Value {
    found.map_or(Value::Null, |found| {
        json!({
            "tool_name": found.tool_name,
            "normalized_tool_name": found.normalized_tool_name,
            "path_match": path_wire(&found.path_match),
        })
    })
}

fn write_wire(found: &FileWriteRequest) -> Value {
    json!({
        "tool_name": found.tool_name,
        "normalized_tool_name": found.normalized_tool_name,
        "normalized_path": found.normalized_path,
        "path_class": found.path_class,
        "reason": found.reason,
        "action_class": found.action_class,
    })
}
