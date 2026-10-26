//! Declared cumulative limits. This contract does not implement reservations.

use crate::{business_match::BusinessPolicyMatchV1, SnapshotError};
use guard_contracts::MAX_BUSINESS_WIRE_COUNT;
use serde::{Deserialize, Serialize};

pub const BUSINESS_BUDGET_SCHEMA: &str = "guard.business-budget.v1";
pub const BUSINESS_BUDGET_MAX_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusinessBudgetScopeV1 {
    Workflow,
    Account,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BusinessBudgetV1 {
    pub schema: String,
    pub version: u16,
    pub id: String,
    pub scope: BusinessBudgetScopeV1,
    #[serde(rename = "match")]
    pub selector: BusinessPolicyMatchV1,
    pub window_ms: u64,
    pub maximum_actions: u64,
    pub maximum_recipients: u64,
    pub maximum_records: u64,
    pub maximum_bytes: u64,
}

impl BusinessBudgetV1 {
    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.schema != BUSINESS_BUDGET_SCHEMA
            || self.version != 1
            || !super::business_policy::valid_id(&self.id)
            || self.selector.validate().is_err()
            // Per-request volume thresholds would let chunked actions fall
            // outside a cumulative budget. Every matching chunk must count.
            || self.selector.min_recipient_count.is_some()
            || self.selector.min_record_count.is_some()
            || self.selector.min_byte_count.is_some()
            || self.window_ms == 0
            || self.window_ms > BUSINESS_BUDGET_MAX_WINDOW_MS
            || [
                self.maximum_actions,
                self.maximum_recipients,
                self.maximum_records,
                self.maximum_bytes,
            ]
            .iter()
            .any(|value| *value > MAX_BUSINESS_WIRE_COUNT)
        {
            return Err(SnapshotError::Policy);
        }
        // Zero is a deliberate zero allowance, never an unlimited sentinel.
        Ok(())
    }
}

#[cfg(test)]
#[path = "business_budget_tests.rs"]
mod tests;
