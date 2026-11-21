use serde::{Deserialize, Serialize};

/// Artifact identity is independent of SDK version. Same-version rebuilds must
/// have a new build ID and manifest binding; neither overwrites an installation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    pub build_id: String,
    pub sdk_version: String,
    pub core_version: String,
    pub source_revision: String,
    pub manifest_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Graph,
    Sharing,
    Persistence,
    ExecutionContext,
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_:-".contains(&byte))
}
pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
