//! `command_model.py` `CanonicalCommand.security_identity` + the `operation_ref`
//!/`segment_ref` derivation `evaluate_command` needs.
//!
//! The native path builds `CanonicalCommand` via `_canonical_command_from_native`
//! with `redirects=()`/`embedded_commands=()` — the resident matcher never emits
//! them. `security_identity` therefore reduces to `command-security-v2:` +
//! sha256 of the canonical JSON payload over the executable structure alone,
//! which `CanonicalCommandV1` already carries. This module ports
//! `build_command_security_identity` for the empty-redirect/embedded case and
//! mirrors `CanonicalCommand.to_dict` for the `evaluate_command` payload.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{CanonicalCommandV1, CommandSegmentV1};

/// `build_command_security_identity` (command_structure.py:71) for the native
/// path — `redirects=()`/`embedded_commands=()` — over a `CanonicalCommandV1`.
///
/// Payload keys are emitted in Python's insertion order; `sort_keys=True` in
/// `json.dumps` reorders them anyway, so we build a sorted `Map`. The canonical
/// JSON codec matches CPython `json.dumps(..., sort_keys=True,
/// separators=(",", ":"), ensure_ascii=True)` byte-for-byte.
pub fn command_security_identity(command: &CanonicalCommandV1) -> String {
    let segments: Vec<Value> = command
        .segments
        .iter()
        .map(|segment| {
            json!({
                "tokens": segment.tokens,
                "environment_names": segment.environment_names,
                "wrapper_chain": segment.wrapper_chain,
                "execution_context": segment.execution_context,
                "pipeline_index": segment.pipeline_index,
            })
        })
        .collect();
    let payload = json!({
        "version": 2,
        "normalized_text": command.normalized_text,
        "dialect": command.dialect,
        "transport": command.transport,
        "wrapper_chain": command.wrapper_chain,
        "segments": segments,
        "redirects": Vec::<Value>::new(),
        "embedded": Vec::<Value>::new(),
    });
    let mut out = Vec::new();
    // Payload is all strings/ints/arrays — always CPython-encodable.
    let _ = guard_contracts::write_canonical_json(&payload, &mut out);
    format!("command-security-v2:{:x}", Sha256::digest(&out))
}

/// `CanonicalCommand` — the Python command-model projection `evaluate_command`
/// reads, reconstructed over a `CanonicalCommandV1` plus its derived
/// `security_identity`. Only the fields the composition + factor producers
/// consume are surfaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCommand {
    pub normalized_text: String,
    pub dialect: String,
    pub transport: String,
    pub extraction_provenance: String,
    pub wrapper_chain: Vec<String>,
    pub segments: Vec<CommandSegmentV1>,
    pub security_identity: String,
    pub confidence: String,
    pub uncertainty_reason: Option<String>,
    pub path_overridden: bool,
}

impl CanonicalCommand {
    /// Project a `CanonicalCommandV1` into the evaluation-facing model.
    ///
    /// `security_identity`: the wire carries Python's authoritative digest
    /// (embedded-command `text` and redirect spans are not on the public model,
    /// so the identity cannot be re-derived). An empty `security_identity`
    /// means the pure-native path — recompute it over the empty
    /// redirect/embedded projection (`build_command_security_identity` for the
    /// `redirects=()`/`embedded_commands=()` case).
    pub fn from_v1(command: &CanonicalCommandV1) -> Self {
        Self {
            normalized_text: command.normalized_text.clone(),
            dialect: command.dialect.clone(),
            transport: command.transport.clone(),
            extraction_provenance: command.extraction_provenance.clone(),
            wrapper_chain: command.wrapper_chain.clone(),
            segments: command.segments.clone(),
            security_identity: if command.security_identity.is_empty() {
                command_security_identity(command)
            } else {
                command.security_identity.clone()
            },
            confidence: command.confidence.clone(),
            uncertainty_reason: command.uncertainty_reason.clone(),
            path_overridden: command.path_overridden,
        }
    }

    /// `operation_ref` base: `operation:{security_identity.rsplit(':',1)[-1]}`.
    pub fn operation_ref(&self) -> String {
        format!(
            "operation:{}",
            self.security_identity.rsplit(':').next().unwrap_or("")
        )
    }

    /// `command.confidence == "exact"` gate.
    pub fn is_exact(&self) -> bool {
        self.confidence == "exact"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandSegmentV1, CommandSpanV1};

    /// Python oracle:
    ///   build_command_security_identity(normalized_text="git status",
    ///     dialect="posix", transport="shell_string", wrapper_chain=("sudo",),
    ///     segments=[{tokens:(git,status), environment_names:(), wrapper_chain:(sudo,),
    ///               execution_context:"direct", pipeline_index:0}],
    ///     redirects=(), embedded_commands=())
    ///   = command-security-v2:cab29dbc2f4ad49d3ff99dec64b8fafa71a6c4ea261c2cd78ff7d732577212e4
    #[test]
    fn security_identity_matches_python_oracle() {
        let command = CanonicalCommandV1 {
            exact_raw_text: true,
            normalized_text: "git status".to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
            wrapper_chain: vec!["sudo".to_owned()],
            segments: vec![CommandSegmentV1 {
                text: "git status".to_owned(),
                tokens: vec!["git".to_owned(), "status".to_owned()],
                executable: Some("git".to_owned()),
                arguments: vec!["status".to_owned()],
                environment_names: vec![],
                wrapper_chain: vec!["sudo".to_owned()],
                path_overridden: false,
                execution_context: "direct".to_owned(),
                pipeline_index: 0,
                span: CommandSpanV1 {
                    source: "normalized".to_owned(),
                    start: 0,
                    end: 10,
                },
            }],
            confidence: "exact".to_owned(),
            uncertainty_reason: None,
            path_overridden: false,
            parser_profile: "posix".to_owned(),
            security_identity: String::new(),
        };
        assert_eq!(
            command_security_identity(&command),
            "command-security-v2:cab29dbc2f4ad49d3ff99dec64b8fafa71a6c4ea261c2cd78ff7d732577212e4"
        );
    }
}
