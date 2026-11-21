//! Which of the non-consuming policy lookups answers an artifact hook.
//!
//! A hook may read a saved decision for the artifact itself, for the exact
//! command, and for the memory artifact. None of those reads consumes a
//! one-shot approval, so the composition is a pure selection, and it is the
//! same selection the MCP tool lane already makes: the most restrictive
//! decision wins, the first lookup that had to ignore local integrity carries
//! that, and lookups that disagree about the approval authority revision
//! carry no revision at all.

use guard_contracts::PolicyLookupSelectQueryV1;
use serde_json::Value;

use crate::mcp_tool_policy_lookup::most_restrictive;

pub(crate) fn policy_lookup_select(query: &PolicyLookupSelectQueryV1) -> Result<Value, String> {
    most_restrictive(&query.lookups)
        .ok_or_else(|| "at least one policy lookup is required".to_owned())
}
