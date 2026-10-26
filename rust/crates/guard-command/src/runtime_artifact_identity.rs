//! Rust port of the two runtime artifact identities built in
//! `cli/commands_support_runtime_artifacts.py`: the merged prompt request
//! (`_merged_prompt_runtime_artifact` :128) and the data-flow exfiltration
//! request (`_runtime_data_flow_artifact` :465).
//!
//! Both ids are keys a saved approval is stored under, so each has exactly one
//! derivation and it lives here. The data-flow payload is encoded the way
//! Python encoded it — `json.dumps(payload, sort_keys=True)` with the *default*
//! separators `(", ", ": ")`, not the compact canonical codec — so shortening
//! the separators would change every stored id.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::package_intent_common::write_spaced_sorted_json;

/// Python truncates the merged prompt digest to 24 hex characters (:128).
const PROMPT_MULTI_DIGEST_CHARS: usize = 24;

/// `_merged_prompt_runtime_artifact` (:107, :128). The identity material is the
/// sorted member ids joined with `|`, so the same set of prompt signals yields
/// the same id whatever order they were collected in.
pub fn prompt_multi_artifact_id(harness: &str, member_artifact_ids: &[String]) -> String {
    let mut sorted: Vec<&str> = member_artifact_ids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let identity = sorted.join("|");
    let digest = hex::encode(Sha256::digest(identity.as_bytes()));
    format!(
        "{harness}:session:prompt:multi:{}",
        &digest[..PROMPT_MULTI_DIGEST_CHARS]
    )
}

/// `_runtime_data_flow_artifact` (:463-475). `signal_ids` keeps the order the
/// detector produced: Python hashed the tuple as a JSON array, so reordering
/// the signals is a different request and a different id.
pub fn data_flow_artifact_id(
    harness: &str,
    source_scope: &str,
    command_text: &str,
    signal_ids: &[String],
) -> String {
    let mut payload = Map::new();
    payload.insert("command_text".to_owned(), json!(command_text));
    payload.insert(
        "signal_ids".to_owned(),
        Value::Array(signal_ids.iter().map(|id| json!(id)).collect()),
    );
    payload.insert("source_scope".to_owned(), json!(source_scope));
    let mut encoded = String::new();
    write_spaced_sorted_json(&Value::Object(payload), &mut encoded);
    let fingerprint = hex::encode(Sha256::digest(encoded.as_bytes()));
    format!("{harness}:{source_scope}:data-flow:{fingerprint}")
}
