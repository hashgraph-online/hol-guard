//! The CIGAR engine selection. Guard runs only the engine compiled into its
//! own executable, offered as the reserved installation `builtin`; any other
//! saved id names a retired engine and is refused.
use guard_context_assistance::{
    BundleApproval, InterpreterFacts, RuntimeSelection, VerifiedRuntime,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use super::policy_store_persistence::{is_lower_hex, persist_private_bytes, read_private_json};
#[path = "context_assistance_lifecycle_files.rs"]
mod lifecycle;
#[path = "context_assistance_picked_folders.rs"]
pub(crate) mod picked;
#[path = "context_assistance_switch_store.rs"]
pub(crate) mod switching;
pub(crate) fn lifecycle_job_count(home: &Path) -> Result<usize, String> {
    Ok(switching::jobs::list(home)?.len())
}
pub(crate) fn selection_lease(home: &Path) -> Result<fs::File, String> {
    lifecycle::lease(home)
}
#[path = "context_assistance_installation_builtin.rs"]
mod builtin;
use super::policy_store_validation::validate_private_directory;
pub(crate) use builtin::BUILTIN_ID;

const PREFIX: &str = "native_context_assistance";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Installation {
    schema: String,
    pub(crate) runtime_id: String,
    pub(crate) qualification: String,
    source_revision: String,
    pub(crate) selection: RuntimeSelection,
    pub(crate) approval: BundleApproval,
    interpreter: InterpreterFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification_job_id: Option<String>,
}

fn error(suffix: &str) -> String {
    format!("{PREFIX}_{suffix}")
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_:-".contains(&c))
}
fn record_name(id: &str) -> String {
    format!("{:x}.json", Sha256::digest(id.as_bytes()))
}

/// Loads the selected engine. Only the built-in engine runs; a saved id of
/// the retired downloaded engine is migrated at startup, never started.
pub(crate) fn load(home: &Path, runtime_id: &str) -> Result<Installation, String> {
    if runtime_id == BUILTIN_ID {
        return builtin::installation(home);
    }
    if !valid_id(runtime_id) {
        return Err(error("runtime_not_selected"));
    }
    Err(error("runtime_retired"))
}

/// A stored opt-in may reference only the built-in engine.
pub(crate) fn validate_selection(home: &Path, runtime_id: &str) -> Result<(), String> {
    load(home, runtime_id).map(|_| ())
}

pub(crate) fn list(_home: &Path) -> Result<Vec<Value>, String> {
    Ok(vec![builtin::choice()])
}

/// The identity a switch pointer records for an installation. The layout is
/// unchanged from earlier releases so stored pointers still compare equal.
fn context(record: &Installation, home: &Path) -> Result<String, String> {
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let mut value = json!({"schema":"guard-cigar-installation-context.v1","guard_home":home,
        "record_schema":record.schema,"runtime_id":record.runtime_id,"qualification":record.qualification,
        "source_revision":record.source_revision,"selection":record.selection,"approval":record.approval,
        "interpreter":record.interpreter,"managed_slot":record.managed_slot});
    if let Some(job_id) = &record.verification_job_id {
        value["verification_job_id"] = json!(job_id);
    }
    let bytes = guard_policy_snapshot::canonical_json_bytes(&value)
        .map_err(|_| error("installation_invalid"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl Installation {
    pub(crate) fn start_cancellable(
        &self,
        home: &Path,
        _config: &guard_context_assistance::ContextAssistanceConfig,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<VerifiedRuntime, String> {
        if self.schema != builtin::BUILTIN_SCHEMA {
            return Err(error("runtime_retired"));
        }
        builtin::start(home, self, cancel)
    }
}
