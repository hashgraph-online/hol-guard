//! `package_command_redaction` — the command text Guard stores for a reviewed
//! package manager launch.
//!
//! Every argv token goes through `guard_command::redacted_command_tokens`
//! (package-source credentials first, then key-shaped assignments, then the
//! text rules), and the tokens are joined the way `shlex.join` joins them, so
//! the receipt, the event and the review card all carry the one spelling the
//! resident produced.
//!
//! `{"command": [token, ...]}` answers `{"text": "..."}`.

use serde_json::{json, Value};

use guard_command::redacted_command_tokens::redacted_command_tokens;

use crate::runner_authority_op::KindResult;

const ERR_INVALID: &str = "native_package_command_redaction_invalid";
/// The most argv tokens one launch may carry; a package command is far shorter.
const MAX_TOKENS: usize = 4096;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    if fields.len() != 1 {
        return Err(ERR_INVALID);
    }
    let tokens = fields
        .get("command")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    if tokens.len() > MAX_TOKENS {
        return Err(ERR_INVALID);
    }
    let command = tokens
        .iter()
        .map(|token| token.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()
        .ok_or(ERR_INVALID)?;
    let text = crate::mcp_proxy_shlex::join(&redacted_command_tokens(&command));
    Ok(json!({ "text": text }))
}

#[cfg(test)]
#[path = "package_command_redaction_tests.rs"]
mod tests;
