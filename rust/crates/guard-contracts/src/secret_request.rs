use serde::{Deserialize, Serialize};

use crate::SecretCapabilityV1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretDestinationV1 {
    pub kind: crate::SecretDeliveryKindV1,
    pub name: String,
    pub process_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub provider_id: String,
    pub connection_id: String,
    pub reference_digest: String,
    pub capability: SecretCapabilityV1,
    pub version_selector: Option<String>,
    pub destination: SecretDestinationV1,
    pub workspace_digest: String,
    pub purpose: String,
    pub policy_digest: String,
    pub extension_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretMetadataResultV1 {
    pub schema: String,
    pub provider_id: String,
    pub reference_digest: String,
    pub state: crate::SecretResultStateV1,
    pub version_digest: Option<String>,
    pub lease: Option<SecretLeaseMetadataV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretLeaseMetadataV1 {
    pub lease_digest: String,
    pub expires_at: String,
    pub renewable: bool,
}
