use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretLeaseV1 {
    pub lease_digest: String,
    pub expires_at: String,
    pub renewable: bool,
    pub revoked: bool,
}
