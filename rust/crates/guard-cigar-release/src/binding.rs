use crate::BuildIdentity;
use serde::{Deserialize, Serialize};

/// Release identity recorded by older Guard versions that ran a separate CIGAR
/// package. Kept only so saved selection records stay readable; it never
/// selects or starts anything.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBinding {
    pub identity: BuildIdentity,
    pub profile_id: String,
    pub adapter_id: String,
    pub adapter_revision: u32,
    pub platform: String,
    pub profile_sha256: String,
}
