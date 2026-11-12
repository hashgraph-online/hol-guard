//! The Guard configuration a relayed package call is evaluated under.
//!
//! The policy view a package authority request binds is hydrated from the
//! configuration fields, in `package_config_mirror`. A relay has no loaded
//! config: it has the harness view the publisher bound, which is
//! `_tool_call_configuration` of `config_for_harness` plus the managed-policy
//! and sandbox fields the approval hash binds. Those are exactly the fields the
//! view reads, so the relay hands them over as they were bound.

use super::view::HarnessView;
use crate::package_config_mirror::{self, ArtifactIdentity};
use guard_command::package_intent_common::GuardArtifact;
use serde_json::Value;

/// A bound view whose configuration fields this cannot read.
const CONFIG_INVALID: &str = "mcp_relay_package_config_invalid";

/// The hydrated policy view a package request's approval hash is bound to.
pub(super) fn config_policy(
    view: &HarnessView,
    artifact: &GuardArtifact,
) -> Result<Value, &'static str> {
    package_config_mirror::config_policy(
        &view.config,
        &view.hash_config,
        &ArtifactIdentity {
            artifact_id: &artifact.artifact_id,
            publisher: artifact.publisher.as_deref(),
            harness: &artifact.harness,
        },
    )
    .ok_or(CONFIG_INVALID)
}

/// `GuardConfig.sandbox_analysis`, which the approval hash binds beside the
/// policy view.
pub(super) fn sandbox_analysis(view: &HarnessView) -> Result<String, &'static str> {
    view.hash_config
        .get("sandbox_analysis")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(CONFIG_INVALID)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_config_tests.rs"]
mod tests;
