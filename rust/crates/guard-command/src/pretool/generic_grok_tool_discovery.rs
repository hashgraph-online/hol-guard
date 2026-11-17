//! Grok's `search_tool`: a keyword search over the integration (MCP) tools
//! the session has configured. It lists tool names and descriptions so the
//! model can pick one for `use_tool`; it reads no file, runs nothing and
//! calls no tool. Its name contains `search`, so without this proof it was
//! typed as a file read with no path and every lookup stopped for review.
//!
//! Calling a tool it finds goes through `use_tool`, which keeps its own
//! review.

use super::extract::GenericSignals;
use super::result::{generic_action, generic_result};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::Value;

/// The longest query this proof admits. Grok's own queries are a few words.
const MAX_QUERY_BYTES: usize = 4_096;

pub(super) fn evaluate(
    harness: &str,
    event: &str,
    payload: &Value,
    signals: &GenericSignals,
) -> Option<PreToolResultV1> {
    if harness != "grok"
        || event != "PreToolUse"
        || signals.tool_name.as_deref() != Some("search_tool")
        || signals.mirrored_input_unproven
        || signals.command.is_some()
        || signals.package_present
    {
        return None;
    }
    let input = super::omp::strict_tool_input(payload)?;
    let query = input.get("query")?.as_str()?;
    let shaped = !query.trim().is_empty()
        && query.len() <= MAX_QUERY_BYTES
        && input.iter().all(|(key, value)| match key.as_str() {
            "query" => true,
            "limit" => value.as_u64().is_some_and(|limit| limit <= 1_000),
            _ => false,
        });
    shaped.then(|| {
        generic_result(
            generic_action(
                harness,
                event,
                PreToolActionTypeV1::Harness,
                PreToolOperationV1::Read,
                true,
                false,
            ),
            "allow",
            "native_grok_tool_discovery",
            "The Rust authority found a Grok search of its configured integration tools: it lists tool names and descriptions and reads no file, runs nothing and calls no tool.",
        )
    })
}

#[cfg(test)]
#[path = "generic_grok_tool_discovery_tests.rs"]
mod tests;
