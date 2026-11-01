//! Qualification, origins and optional compatibility annotations can evolve;
//! an existing build ID cannot acquire different SDK/dependency/worker bytes.
use crate::{PlatformBuild, Qualification, ReleaseError, WheelLock};

fn same_wheel(first: &WheelLock, second: &WheelLock) -> bool {
    (
        &first.distribution,
        &first.version,
        &first.filename,
        &first.sha256,
        first.bytes,
    ) == (
        &second.distribution,
        &second.version,
        &second.filename,
        &second.sha256,
        second.bytes,
    )
}
pub(crate) fn ensure(
    current: &PlatformBuild,
    installed: &PlatformBuild,
) -> Result<(), ReleaseError> {
    if current.platform != installed.platform
        || current.worker_sha256 != installed.worker_sha256
        || current
            .package_tree_sha256
            .as_ref()
            .is_some_and(|tree| Some(tree) != installed.package_tree_sha256.as_ref())
        || current.wheel.as_ref().is_some_and(|wheel| {
            installed
                .wheel
                .as_ref()
                .is_none_or(|old| !same_wheel(wheel, old))
        })
        || current.dependencies.iter().any(|wheel| {
            installed
                .dependencies
                .iter()
                .find(|old| old.distribution == wheel.distribution)
                .is_none_or(|old| !same_wheel(wheel, old))
        })
        || current.qualification == Qualification::GuardQualified
            && current.dependencies.len() != installed.dependencies.len()
    {
        return Err(ReleaseError::IdentityConflict);
    }
    // Missing data in an incomplete upstream-only listing is not withdrawal.
    // Origins/qualification and optional Requires-Python annotations can be
    // refreshed; installed wheel bytes already bind their actual metadata.
    Ok(())
}
