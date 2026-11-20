use crate::{types, BuildIdentity, ReleaseError};
use pep440_rs::Version;
use serde::Serialize;
use std::{cmp::Ordering, str::FromStr};

pub(crate) fn version(text: &str) -> Result<Version, ReleaseError> {
    if text.is_empty() || text.len() > 128 || !text.is_ascii() {
        return Err(ReleaseError::InvalidVersion);
    }
    let parsed = Version::from_str(text).map_err(|_| ReleaseError::InvalidVersion)?;
    if parsed.to_string() != text {
        return Err(ReleaseError::InvalidVersion);
    }
    Ok(parsed)
}
impl BuildIdentity {
    pub fn validate(&self) -> Result<(), ReleaseError> {
        version(&self.sdk_version)?;
        if !crate::labels::producer_label(&self.core_version) {
            return Err(ReleaseError::InvalidVersion);
        }
        if !types::identifier(&self.build_id)
            || !types::hex(&self.source_revision, 40)
            || !types::hex(&self.manifest_sha256, 64)
        {
            return Err(ReleaseError::InvalidIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildChange {
    SameBuild,
    SameVersionReplacement,
    Upgrade,
    Downgrade,
}

pub fn compare_builds(
    current: &BuildIdentity,
    next: &BuildIdentity,
) -> Result<BuildChange, ReleaseError> {
    current.validate()?;
    next.validate()?;
    if current.build_id == next.build_id {
        return if current == next {
            Ok(BuildChange::SameBuild)
        } else {
            Err(ReleaseError::IdentityConflict)
        };
    }
    Ok(
        match version(&next.sdk_version)?.cmp(&version(&current.sdk_version)?) {
            Ordering::Equal => BuildChange::SameVersionReplacement,
            Ordering::Greater => BuildChange::Upgrade,
            Ordering::Less => BuildChange::Downgrade,
        },
    )
}
