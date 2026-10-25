//! `LocalCliHelpParse` - wire contract for the resident op that reads the
//! first-level commands out of a local CLI's `--help` output.
//!
//! Guard probes an unlisted CLI with `--help` in Python, where the process
//! isolation lives, and hands the text here for the parse. The text is
//! whatever a third-party program printed, so nothing in it is trusted: the
//! op only reports the command names it recognizes.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const LOCAL_CLI_HELP_PARSE_REQUEST_SCHEMA: &str = "guard-local-cli-help-parse-request.v1";
/// Schema discriminator for the result.
pub const LOCAL_CLI_HELP_PARSE_RESULT_SCHEMA: &str = "guard-local-cli-help-parse-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const LOCAL_CLI_HELP_PARSE_FEATURE: &str = "local-cli-help-parse-v1";
/// Largest canonical request serialization the op will accept. Python bounds
/// the probed output at 8 KiB; this leaves room for the envelope around it.
pub const LOCAL_CLI_HELP_PARSE_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalCliHelpParseRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The `--help` output to read, exactly as the program printed it.
    pub text: String,
    /// The command every discovered command hangs from, when there is one.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// The program and parent command path, for example `["wrangler", "d1"]`.
    #[serde(default)]
    pub invocation: Vec<String>,
}

/// One command read out of help text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalCliHelpCommandV1 {
    pub command_id: String,
    pub name: String,
    pub usage: String,
    pub description: String,
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalCliHelpParseResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_local_cli_help_parse_*` failure codes.
    pub code: String,
    /// `{"commands": [...]}`, in the order the help text named them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}
