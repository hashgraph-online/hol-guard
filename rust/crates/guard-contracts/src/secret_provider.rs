use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretProviderStatusV1 {
    FirstParty,
    External,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretCapabilityV1 {
    Metadata,
    Resolve,
    Lease,
    Verify,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretAuthModeV1 {
    NativeKeychain,
    ApiToken,
    OauthDevice,
    OauthLoopback,
    OidcWorkload,
    SpiffeWorkload,
    LocalPeer,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretDeliveryKindV1 {
    Environment,
    Stdin,
    FileDescriptor,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretResultStateV1 {
    Metadata,
    Available,
    Stale,
    Unavailable,
    Malformed,
    Revoked,
    ChangedBinding,
    UnsupportedSink,
    ApprovalRequired,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretProviderTrustBindingV1 {
    pub provider_id: String,
    pub manifest_digest: String,
    pub publisher_id: String,
    pub schema_version: String,
    pub adapter_version: String,
    pub status: SecretProviderStatusV1,
    pub local_enablement_required: bool,
    pub conformance_digest: String,
}
