//! Request-bound access to the existing rich parser and its model helpers.
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use base64ct::{Base64, Encoding};
use guard_command::{command_model, rich_command_model_api as model_api};
use guard_contracts::write_canonical_json_with_limit;
use guard_policy_snapshot::digest_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const REQUEST_SCHEMA: &str = "guard-rich-command-model-request.v1";
const RESULT_SCHEMA: &str = "guard-rich-command-model-result.v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RichCommandModelRequest {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub action: String,
    pub args: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParseArgs {
    command: Option<String>,
    #[serde(default)]
    command_chunks: Option<Vec<String>>,
    #[serde(default)]
    command_gzip_chunks: Option<Vec<String>>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    home_dir: Option<String>,
    #[serde(default = "posix")]
    dialect: String,
    #[serde(default = "shell_string")]
    transport: String,
    #[serde(default = "provenance")]
    extraction_provenance: String,
    #[serde(default = "yes")]
    normalize_wrappers: bool,
}
fn posix() -> String {
    "posix".into()
}
fn shell_string() -> String {
    "shell_string".into()
}
fn provenance() -> String {
    "guard-shell".into()
}
fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextArgs {
    command: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableArgs {
    value: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokensArgs {
    tokens: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SudoArgs {
    tokens: Vec<String>,
    index: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvArgs {
    tokens: Vec<String>,
    inherited_environment: Option<BTreeMap<String, String>>,
    cwd: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentArgs {
    command: String,
    source_offset: usize,
    redirects: Vec<model_api::CommandRedirect>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeredocInput {
    delimiter: String,
    body: String,
    operator_start: usize,
    declaration_end: usize,
    body_start: usize,
    body_end: usize,
    end: usize,
    quoted: bool,
    strip_tabs: bool,
}
impl From<HeredocInput> for model_api::ShellHeredoc {
    fn from(h: HeredocInput) -> Self {
        Self {
            delimiter: h.delimiter,
            body: h.body,
            operator_start: h.operator_start,
            declaration_end: h.declaration_end,
            body_start: h.body_start,
            body_end: h.body_end,
            end: h.end,
            quoted: h.quoted,
            strip_tabs: h.strip_tabs,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectArgs {
    command: String,
    heredocs: Vec<HeredocInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityArgs {
    normalized_text: String,
    dialect: String,
    transport: String,
    wrapper_chain: Vec<String>,
    segments: Vec<model_api::IdentitySegment>,
    redirects: Vec<model_api::CommandRedirect>,
    embedded_commands: Vec<model_api::EmbeddedCommand>,
}

fn decode<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T, String> {
    serde_json::from_value(args.clone())
        .map_err(|_| "native_rich_command_model_invalid_args".into())
}

pub(crate) fn result(action: &str, args: &Value) -> Result<Value, String> {
    match action {
        "parse" => {
            let a: ParseArgs = decode(args)?;
            let command = match (a.command, a.command_chunks, a.command_gzip_chunks) {
                (Some(command), None, None) => command,
                (None, Some(chunks), None) if !chunks.is_empty() => chunks.concat(),
                (None, None, Some(chunks)) if !chunks.is_empty() => {
                    let bytes = Base64::decode_vec(&chunks.concat())
                        .map_err(|_| "native_rich_command_model_invalid_args")?;
                    let mut text = String::new();
                    flate2::read::GzDecoder::new(bytes.as_slice())
                        .take(8 * 1024 * 1024 + 1)
                        .read_to_string(&mut text)
                        .map_err(|_| "native_rich_command_model_invalid_args")?;
                    if text.len() > 8 * 1024 * 1024 {
                        return Err("native_rich_command_model_bounds".into());
                    }
                    text
                }
                _ => return Err("native_rich_command_model_invalid_args".into()),
            };
            if command.trim().is_empty() {
                return Err("Command text cannot be empty".into());
            }
            let model = command_model::parse_shell_command(
                &command,
                a.cwd.as_deref().map(Path::new),
                a.home_dir.as_deref().map(Path::new),
                &a.dialect,
                &a.transport,
                &a.extraction_provenance,
                a.normalize_wrappers,
            );
            let mut value = model.to_dict();
            value["raw_text"] = json!(model.raw_text);
            if model.confidence == "uncertain"
                && model.raw_text == model.normalized_text
                && serde_json::to_vec(&value)
                    .map_err(|_| "native_rich_command_model_invalid_result")?
                    .len()
                    > 1024 * 1024
            {
                let text = command.trim();
                let start = text.as_ptr() as usize - command.as_ptr() as usize;
                value["raw_text"] = json!("");
                value["normalized_text"] = json!("");
                value["source_text_span"] = json!({"start": start, "end": start + text.len()});
            }
            for (value, command) in value["embedded_commands"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .zip(&model.embedded_commands)
            {
                value["text"] = json!(command.text);
            }
            Ok(value)
        }
        "tokens" | "windows_tokens" => {
            let a: TextArgs = decode(args)?;
            let (tokens, exact) = if action == "windows_tokens" {
                model_api::windows_shell_tokens(&a.command)
            } else {
                model_api::shell_tokens(&a.command)
            };
            Ok(json!([tokens, exact]))
        }
        "executable" => {
            let a: ExecutableArgs = decode(args)?;
            Ok(json!(model_api::executable_name(a.value.as_deref())))
        }
        "leading_environment" => {
            let a: TokensArgs = decode(args)?;
            let (names, index, wrappers) = model_api::leading_environment(&a.tokens);
            Ok(json!([names, index, wrappers]))
        }
        "sudo_options" => {
            let a: SudoArgs = decode(args)?;
            Ok(json!(model_api::after_sudo_options(&a.tokens, a.index)))
        }
        "segment_tokens" => {
            let a: SegmentArgs = decode(args)?;
            Ok(json!(model_api::shell_tokens_without_redirects(
                &a.command,
                a.source_offset,
                &a.redirects
            )))
        }
        "redirects" => {
            let a: RedirectArgs = decode(args)?;
            let heredocs: Vec<_> = a.heredocs.into_iter().map(Into::into).collect();
            Ok(
                serde_json::to_value(model_api::extract_command_redirects(&a.command, &heredocs))
                    .map_err(|_| "native_rich_command_model_invalid_result")?,
            )
        }
        "identity" => {
            let a: IdentityArgs = decode(args)?;
            Ok(json!(model_api::build_command_security_identity(
                &a.normalized_text,
                &a.dialect,
                &a.transport,
                &a.wrapper_chain,
                &a.segments,
                &a.redirects,
                &a.embedded_commands
            )))
        }
        "env" => {
            let a: EnvArgs = decode(args)?;
            let e = model_api::parse_env_wrapper(
                &a.tokens,
                a.inherited_environment.as_ref(),
                a.cwd.as_deref().map(Path::new),
            );
            Ok(json!({
                "complete": e.complete, "error": e.error, "original_tokens": e.original_tokens,
                "expanded_tokens": e.expanded_tokens,
                "option_effects": { "ignore_environment": e.option_effects.ignore_environment,
                    "unset_names": e.option_effects.unset_names, "chdir": e.option_effects.chdir,
                    "search_path": e.option_effects.search_path, "verbose": e.option_effects.verbose,
                    "null_output": e.option_effects.null_output },
                "environment_delta": { "clear": e.environment_delta.clear,
                    "unset_names": e.environment_delta.unset_names, "assignments": e.environment_delta.assignments },
                "effective_environment": e.effective_environment,
                "effective_cwd": e.effective_cwd, "command_index": e.command_index,
                "executable_argv": e.executable_argv,
                "split_expansions": e.split_expansions.iter().map(|s| json!({
                    "payload": s.payload, "source_index": s.source_index, "tokens": s.tokens
                })).collect::<Vec<_>>()
            }))
        }
        _ => Err("native_rich_command_model_invalid_action".into()),
    }
}

pub(crate) fn evaluate(request: &RichCommandModelRequest) -> Result<Vec<u8>, String> {
    if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
    {
        return Err("native_rich_command_model_invalid_request".into());
    }
    let value =
        serde_json::to_value(request).map_err(|_| "native_rich_command_model_invalid_request")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(
        &value,
        &mut bytes,
        2 * 1024 * 1024,
        "native_rich_command_model_bounds",
    )?;
    let digest = digest_bytes(&bytes);
    let (status, value, error) = match result(&request.action, &request.args) {
        Ok(value) => ("ok", value, None),
        Err(error) => ("invalid_input", Value::Null, Some(error)),
    };
    crate::encode_response(
        &json!({ "schema": RESULT_SCHEMA, "request_id": request.request_id,
        "request_sha256": digest, "status": status, "result": value, "error": error }),
    )
}

#[cfg(test)]
#[path = "rich_command_model_vectors_tests.rs"]
mod tests;
