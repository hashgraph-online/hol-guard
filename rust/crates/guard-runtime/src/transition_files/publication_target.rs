//! The config a Codex hook publication starts from, ported from the
//! snapshot at the top of `CodexHarnessAdapter._write_authenticated_hook_config_owned`.
//!
//! A pending publication must be recovered first. The config, when present,
//! must be an admitted single-link regular file holding UTF-8, and its
//! identity must not move while its bytes are read. Request fields: `home`,
//! `config` and `package_roots`. Answer: `{"before": base64 or null,
//! "identity": [5 ints] or null, "key_present": bool}`.

use std::path::PathBuf;

use serde_json::{json, Value};

use super::publication::{path_present, Call};
use super::publication_generation::package_roots;
use super::publication_io::{encode, rollback_identity};
use super::{Fault, Step};
use crate::codex_hook_file_integrity_op;
use crate::codex_hook_key;

const PENDING: &str =
    "Codex hook publication must be recovered before preparing another generation.";

pub(super) fn target(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    if path_present(&Call::record_path(&home)) {
        return Err(Fault::Integrity(
            "codex_hook_publication_pending".to_owned(),
            PENDING.to_owned(),
        ));
    }
    let config = call.path("config")?;
    let key_present = path_present(&codex_hook_key::key_path(&home));
    if path_present(&config) {
        let roots: Vec<PathBuf> = package_roots(call.args)?
            .iter()
            .map(PathBuf::from)
            .collect();
        codex_hook_file_integrity_op::admit(&config, "config_target", false, &roots).map_err(
            |reason| {
                let message = codex_hook_file_integrity_op::message(&reason);
                Fault::Integrity(reason, message)
            },
        )?;
    }
    let first = rollback_identity(&config)
        .map_err(|_| invalid("Codex configuration must be a single-link regular file."))?;
    let data = call.snapshot(&config)?;
    if data
        .as_deref()
        .is_some_and(|bytes| std::str::from_utf8(bytes).is_err())
    {
        return Err(invalid("Codex configuration is not valid UTF-8."));
    }
    let second = rollback_identity(&config).map_err(|_| {
        invalid("Codex configuration became an invalid target during its snapshot.")
    })?;
    if first != second {
        return Err(invalid("Codex configuration changed during its snapshot."));
    }
    Ok(json!({
        "before": encode(data.as_deref())?,
        "identity": first,
        "key_present": key_present,
    }))
}

fn invalid(message: &str) -> Fault {
    Fault::Integrity(
        "codex_hook_config_invalid".to_owned(),
        format!("codex_hook_config_invalid: {message}"),
    )
}
