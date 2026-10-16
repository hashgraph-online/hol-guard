//! Purpose-separated platform anchor; private-file backing exists only in tests.
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Anchor {
    pub(super) schema: String,
    pub(super) version: u16,
    pub(super) root: String,
    pub(super) last_time_ms: u64,
    pub(super) replay_index:
        super::super::super::super::workspace_review_claim_index::ClaimIndexAnchor,
}

fn invalid() -> String {
    "native_business_budget_anchor_invalid".into()
}

#[cfg(not(test))]
fn account(base: &Path) -> Result<String, String> {
    Ok(format!(
        "{}:business-budget-v1",
        super::super::super::super::approval_enrollment::account_for_state_base(base)?
    ))
}

pub(super) fn load(base: &Path) -> Result<Option<Anchor>, String> {
    #[cfg(test)]
    let bytes = {
        let root = crate::resident_state::private_root_for_state_base(base)?;
        super::super::super::super::policy_store_persistence::read_private_json(
            &base.join("business-budget-anchor.test.json"),
            2048,
            "business_budget_anchor",
            &root,
        )?
        .map(|(_, bytes)| bytes)
    };
    #[cfg(not(test))]
    let bytes =
        super::super::super::super::approval_enrollment::read_platform_secret_for_workspace_review(
            base,
            &account(base)?,
            2048,
        )?
        .map(String::into_bytes);
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let value: Anchor = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if value.schema != "guard.business-budget-anchor.v1"
        || value.version != 1
        || !super::super::super::super::workspace_review_claim_index::valid_digest(&value.root)
        || value.last_time_ms == 0
        || !(value.replay_index.validate()
            || (value.replay_index.claim_count == 0 && value.replay_index.root == value.root))
    {
        return Err(invalid());
    }
    Ok(Some(value))
}

pub(super) fn store(
    base: &Path,
    root_digest: String,
    time_ms: u64,
    replay_index: super::super::super::super::workspace_review_claim_index::ClaimIndexAnchor,
) -> Result<(), String> {
    let value = Anchor {
        schema: "guard.business-budget-anchor.v1".into(),
        version: 1,
        root: root_digest,
        last_time_ms: time_ms,
        replay_index,
    };
    let bytes = guard_policy_snapshot::canonical_json_bytes(
        &serde_json::to_value(value).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    #[cfg(test)]
    {
        let root = crate::resident_state::private_root_for_state_base(base)?;
        super::super::super::super::policy_store_persistence::persist_private_bytes(
            &base.join("business-budget-anchor.test.json"),
            &bytes,
            2048,
            "business_budget_anchor",
            &root,
        )
    }
    #[cfg(not(test))]
    {
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        super::super::super::super::approval_enrollment::write_platform_secret_for_workspace_review(
            base,
            &account(base)?,
            text,
            2048,
        )
    }
}
