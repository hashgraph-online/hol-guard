//! Native readiness: one typed answer to "can the runtime give a verdict now?"
//!
//! `guard/contracts/native-readiness.v1.json` declares the seven states, the
//! reason code that leads to each, and the recovery commands. This module owns
//! the mapping: callers in Python only read the payload it builds. Only
//! `ready` carries a verdict. Every other state is `not_evaluated`, and a
//! reason code the contract does not name falls to the contract's default
//! state (`unavailable`), never to `ready`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::{json, Value};

const CONTRACT_TEXT: &str =
    include_str!("../../../../src/codex_plugin_scanner/guard/contracts/native-readiness.v1.json");
const CONTRACT_SCHEMA: &str = "hol-guard.native-readiness.v1";
/// The payload schema each projection carries.
pub(crate) const PAYLOAD_SCHEMA: &str = "hol-guard.native-readiness.v1";

/// Every readiness state, in the order the contract lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReadinessState {
    Ready,
    Starting,
    Overloaded,
    Unavailable,
    Incompatible,
    Unauthenticated,
    Failed,
}

impl ReadinessState {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 7] = [
        Self::Ready,
        Self::Starting,
        Self::Overloaded,
        Self::Unavailable,
        Self::Incompatible,
        Self::Unauthenticated,
        Self::Failed,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Starting => "starting",
            Self::Overloaded => "overloaded",
            Self::Unavailable => "unavailable",
            Self::Incompatible => "incompatible",
            Self::Unauthenticated => "unauthenticated",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateEntry {
    verdict: String,
    retry: bool,
    summary: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema: String,
    states: BTreeMap<String, StateEntry>,
    default_state: ReadinessState,
    reasons: BTreeMap<String, ReadinessState>,
    recovery_commands: Vec<String>,
}

fn contract() -> &'static Contract {
    static CONTRACT: OnceLock<Contract> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        let parsed: Contract =
            serde_json::from_str(CONTRACT_TEXT).expect("bundled native readiness contract");
        assert_eq!(
            parsed.schema, CONTRACT_SCHEMA,
            "native readiness contract schema"
        );
        parsed
    })
}

fn entry(state: ReadinessState) -> &'static StateEntry {
    contract()
        .states
        .get(state.as_str())
        .expect("every readiness state is declared")
}

/// The state a reason code leads to. An unknown code is the default state.
pub(crate) fn state_for_reason(reason: &str) -> ReadinessState {
    let contract = contract();
    contract
        .reasons
        .get(reason)
        .copied()
        .unwrap_or(contract.default_state)
}

/// The readiness payload for one reason code. Holds no command, path or
/// content: only the state, the code and what to do next.
pub(crate) fn readiness_payload(reason: &str) -> Value {
    let state = state_for_reason(reason);
    let declared = entry(state);
    let ready = state == ReadinessState::Ready;
    let known = contract().reasons.contains_key(reason);
    json!({
        "schema": PAYLOAD_SCHEMA,
        "state": state.as_str(),
        "reason_code": if known { reason } else { "native_reason_unrecognized" },
        "verdict": declared.verdict,
        "safe_verdict": ready,
        "retry": declared.retry,
        "summary": declared.summary,
        "recovery_commands": if ready { Vec::new() } else { contract().recovery_commands.clone() },
    })
}

#[cfg(test)]
#[path = "native_readiness_tests.rs"]
mod tests;
