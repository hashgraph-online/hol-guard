use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretDeliveryBindingV1 {
    pub kind: crate::SecretDeliveryKindV1,
    pub name: String,
    pub process_digest: String,
    pub workspace_digest: String,
    pub purpose: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretDeliveryOutcomeV1 {
    Delivered,
    Refused,
    Cancelled,
    TimedOut,
    Reflected,
}
