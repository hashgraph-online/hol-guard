//! Strict business rules carried by an authenticated native snapshot.
//! This binding does not authenticate action facts or activate a provider pack.

use crate::{
    business_match::BusinessPolicyMatchV1, SnapshotError, POLICY_SNAPSHOT_MAX_MAP_ENTRIES,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const BUSINESS_POLICY_BINDING_SCHEMA: &str = "guard.native-business-policy.v1";

pub(super) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn present_budgets<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<crate::business_budget::BusinessBudgetV1>>, D::Error> {
    Vec::<crate::business_budget::BusinessBudgetV1>::deserialize(d).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BusinessPolicyRuleV1 {
    pub id: String,
    pub action: String,
    #[serde(rename = "match")]
    pub selector: BusinessPolicyMatchV1,
    #[serde(
        default,
        deserialize_with = "present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BusinessPolicyBindingV1 {
    pub schema: String,
    pub version: u16,
    pub default_action: String,
    pub rules: Vec<BusinessPolicyRuleV1>,
    #[serde(
        default,
        deserialize_with = "present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub source_document_digest: Option<String>,
    #[serde(
        default,
        deserialize_with = "present_budgets",
        skip_serializing_if = "Option::is_none"
    )]
    pub budgets: Option<Vec<crate::business_budget::BusinessBudgetV1>>,
}

impl BusinessPolicyBindingV1 {
    pub fn validate(&self) -> Result<(), SnapshotError> {
        let mut ids = BTreeSet::new();
        if self.schema != BUSINESS_POLICY_BINDING_SCHEMA
            || self.version != 1
            || !super::validate_action(&self.default_action)
            || self.rules.len() > POLICY_SNAPSHOT_MAX_MAP_ENTRIES
            || self
                .source_document_digest
                .as_deref()
                .is_some_and(|digest| !super::valid_hex(digest, 64))
        {
            return Err(SnapshotError::Policy);
        }
        for rule in &self.rules {
            if !valid_id(&rule.id)
                || !ids.insert(&rule.id)
                || !super::validate_action(&rule.action)
                || rule.selector.validate().is_err()
                || rule.expires_at.as_deref().is_some_and(|expiry| {
                    guard_contracts::canonical_policy_timestamp_nanos(expiry).is_none()
                })
            {
                return Err(SnapshotError::Policy);
            }
        }
        if let Some(budgets) = &self.budgets {
            let mut budget_ids = BTreeSet::new();
            if budgets.is_empty() || budgets.len() > POLICY_SNAPSHOT_MAX_MAP_ENTRIES {
                return Err(SnapshotError::Policy);
            }
            for budget in budgets {
                budget.validate()?;
                if !budget_ids.insert(&budget.id) {
                    return Err(SnapshotError::Policy);
                }
            }
        }
        Ok(())
    }
}

fn present_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Null cannot discard an expiry or the complete-document identity.
    String::deserialize(d).map(Some)
}

// An explicit null must not silently remove an installed business policy.
pub(super) fn present_binding<'de, D>(d: D) -> Result<Option<BusinessPolicyBindingV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BusinessPolicyBindingV1::deserialize(d).map(Some)
}
