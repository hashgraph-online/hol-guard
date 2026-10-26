//! `InventoryUrlRedaction` — resident op that redacts an inventory export's
//! URLs, header names, endpoint host classes, command strings and paths.
//!
//! Python held a second copy of this grammar: how a URL is rebuilt from its
//! host and port alone so userinfo cannot survive, which query names are
//! sensitive enough to lose their values, which header names are, and which
//! hosts count as loopback or private. `guard_command::inventory_redaction`
//! already owned all of it, pinned against CPython by the parity corpus in
//! `rust/crates/guard-command/testdata/inventory_url_parity.json`, so the
//! caller now sends the strings and reads the answers.
//!
//! The command and path tasks remove the same duplication one layer out: the
//! four substitutions that redact an exported command string, and the
//! home-then-workspace-then-file-name labelling an exported path gets.
//! `inventory_path_redaction` already owned both, pinned against CPython by
//! `rust/crates/guard-command/testdata/inventory_path_parity.json`.

use std::path::Path;

use guard_command::inventory_path_redaction::{redact_command_value, redact_known_path};
use guard_command::inventory_redaction::{classify_endpoint_host, redact_headers, redact_url};
use guard_contracts::{
    InventoryUrlAnswerV1, InventoryUrlRedactionRequestV1, InventoryUrlRedactionResultV1,
    InventoryUrlTaskV1, INVENTORY_URL_REDACTION_MAX_REQUEST_BYTES,
    INVENTORY_URL_REDACTION_MAX_TASKS, INVENTORY_URL_REDACTION_REQUEST_SCHEMA,
    INVENTORY_URL_REDACTION_RESULT_SCHEMA,
};

use crate::package_authority_op::request_digest_with_limit;

fn answer(task: &InventoryUrlTaskV1) -> InventoryUrlAnswerV1 {
    match task {
        InventoryUrlTaskV1::RedactUrl { value } => InventoryUrlAnswerV1::RedactUrl {
            value: redact_url(value),
        },
        InventoryUrlTaskV1::RedactHeaders { header_names } => InventoryUrlAnswerV1::RedactHeaders {
            headers: redact_headers(header_names),
        },
        InventoryUrlTaskV1::ClassifyEndpointHost { value } => {
            InventoryUrlAnswerV1::ClassifyEndpointHost {
                host_class: classify_endpoint_host(value.as_deref()).to_owned(),
            }
        }
        InventoryUrlTaskV1::RedactCommandValue {
            value,
            home_dir,
            workspace_dir,
            cwd,
        } => InventoryUrlAnswerV1::RedactCommandValue {
            value: redact_command_value(
                value,
                Path::new(home_dir),
                workspace_dir.as_deref().map(Path::new),
                Path::new(cwd),
            ),
        },
        InventoryUrlTaskV1::RedactKnownPath {
            value,
            home_dir,
            workspace_dir,
            cwd,
        } => InventoryUrlAnswerV1::RedactKnownPath {
            value: redact_known_path(
                value,
                Path::new(home_dir),
                workspace_dir.as_deref().map(Path::new),
                Path::new(cwd),
            ),
        },
    }
}

pub(crate) fn evaluate_inventory_url_redaction(
    request: &InventoryUrlRedactionRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest_with_limit(request, INVENTORY_URL_REDACTION_MAX_REQUEST_BYTES)?;
    if request.schema != INVENTORY_URL_REDACTION_REQUEST_SCHEMA {
        return Err("native_inventory_url_redaction_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() || request.tasks.len() > INVENTORY_URL_REDACTION_MAX_TASKS {
        return Err("native_inventory_url_redaction_invalid".to_owned());
    }
    crate::encode_response(&InventoryUrlRedactionResultV1 {
        schema: INVENTORY_URL_REDACTION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        answers: request.tasks.iter().map(answer).collect(),
    })
}

#[cfg(test)]
#[path = "inventory_url_redaction_op_tests.rs"]
mod tests;
