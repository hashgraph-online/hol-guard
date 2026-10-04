//! Versioned business selector representation and native predicates.
//! Predicates grant no permission. An enforcing consumer must authenticate the
//! facts and policy, preserve intrinsic floors, and bind managed dispatch.

use guard_contracts::{
    BusinessActionErrorV1, BusinessActionV1, BusinessAudienceKindV1, BusinessOperationV1,
    BusinessSensitivityV1, BusinessServiceV1, MAX_BUSINESS_ACTION_ITEMS, MAX_BUSINESS_WIRE_COUNT,
};
use serde::{Deserialize, Serialize};

pub const BUSINESS_POLICY_MATCH_SCHEMA: &str = "guard.business-policy-match.v1";
pub const BUSINESS_POLICY_MATCH_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessPolicyMatchErrorV1 {
    Invalid,
    UnsupportedVersion,
    BoundsExceeded,
    InvalidFacts,
    IncompleteFacts,
}

// Missing optional selectors mean wildcard; explicit null is malformed and
// must never silently widen the rule to that wildcard.
fn present_value<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BusinessPolicyMatchV1 {
    pub schema: String,
    pub version: u16,
    pub services: Vec<BusinessServiceV1>,
    pub operations: Vec<BusinessOperationV1>,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub account_bindings: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub audience_kinds: Option<Vec<BusinessAudienceKindV1>>,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub sensitivity_labels: Option<Vec<BusinessSensitivityV1>>,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_recipient_count: Option<u64>,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_record_count: Option<u64>,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_byte_count: Option<u64>,
}

fn valid_set<T: PartialEq>(values: &[T], maximum: usize) -> bool {
    !values.is_empty()
        && values.len() <= maximum
        && values
            .iter()
            .enumerate()
            .all(|(index, value)| !values[..index].contains(value))
}

impl BusinessPolicyMatchV1 {
    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, BusinessPolicyMatchErrorV1> {
        if bytes.len() > BUSINESS_POLICY_MATCH_MAX_BYTES {
            return Err(BusinessPolicyMatchErrorV1::BoundsExceeded);
        }
        let selector: Self =
            serde_json::from_slice(bytes).map_err(|_| BusinessPolicyMatchErrorV1::Invalid)?;
        selector.validate()?;
        Ok(selector)
    }

    pub fn validate(&self) -> Result<(), BusinessPolicyMatchErrorV1> {
        use BusinessPolicyMatchErrorV1 as Error;
        if self.schema != BUSINESS_POLICY_MATCH_SCHEMA || self.version != 1 {
            return Err(Error::UnsupportedVersion);
        }
        if !valid_set(&self.services, 3)
            || !valid_set(&self.operations, 11)
            || self
                .operations
                .iter()
                .any(|op| !self.services.contains(&op.service()))
            || self.account_bindings.as_ref().is_some_and(|values| {
                !valid_set(values, MAX_BUSINESS_ACTION_ITEMS)
                    || values.iter().any(|value| {
                        value.len() != 64
                            || !value
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
            })
            || self.audience_kinds.as_ref().is_some_and(|values| {
                !valid_set(values, 3) || values.contains(&BusinessAudienceKindV1::Unknown)
            })
            || self.sensitivity_labels.as_ref().is_some_and(|values| {
                !valid_set(values, 4) || values.contains(&BusinessSensitivityV1::Unknown)
            })
        {
            return Err(Error::Invalid);
        }
        if [
            self.min_recipient_count,
            self.min_record_count,
            self.min_byte_count,
        ]
        .into_iter()
        .flatten()
        .any(|count| count > MAX_BUSINESS_WIRE_COUNT)
            || serde_json::to_vec(self).map_err(|_| Error::Invalid)?.len()
                > BUSINESS_POLICY_MATCH_MAX_BYTES
        {
            return Err(Error::BoundsExceeded);
        }
        Ok(())
    }

    /// All dimensions intersect; values within a dimension are alternatives.
    /// Counts are inclusive lower bounds on this action, never a cumulative
    /// quota. Incomplete or contradictory facts are errors before any nonmatch,
    /// preventing uncertainty from falling through to an ordinary default.
    /// Complete shape is not producer authentication or an allow decision.
    pub fn matches(&self, facts: &BusinessActionV1) -> Result<bool, BusinessPolicyMatchErrorV1> {
        self.validate()?;
        facts
            .require_complete_facts()
            .map_err(|error| match error {
                BusinessActionErrorV1::Incomplete => BusinessPolicyMatchErrorV1::IncompleteFacts,
                _ => BusinessPolicyMatchErrorV1::InvalidFacts,
            })?;
        Ok(self.services.contains(&facts.provider.service)
            && self.operations.contains(&facts.operation)
            && self.account_bindings.as_ref().is_none_or(|bindings| {
                facts
                    .provider
                    .account_binding
                    .as_ref()
                    .is_some_and(|binding| bindings.contains(binding))
            })
            && self
                .audience_kinds
                .as_ref()
                .is_none_or(|kinds| kinds.contains(&facts.audience.kind))
            && self.sensitivity_labels.as_ref().is_none_or(|labels| {
                labels
                    .iter()
                    .any(|label| facts.content.sensitivity_labels.contains(label))
            })
            && self
                .min_recipient_count
                .is_none_or(|minimum| facts.volume.recipient_count >= minimum)
            && self
                .min_record_count
                .is_none_or(|minimum| facts.volume.record_count >= minimum)
            && self
                .min_byte_count
                .is_none_or(|minimum| facts.volume.byte_count >= minimum))
    }
}
