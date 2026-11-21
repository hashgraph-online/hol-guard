//! Package release order is PEP 440; publication counters are not versions.
use pep440_rs::Version;
use std::cmp::Ordering;
use std::str::FromStr;

fn installed(value: &str) -> Result<Version, String> {
    if value.is_empty() || value.len() > 64 {
        return Err("pack_lifecycle_version_invalid".into());
    }
    let version = Version::from_str(value).map_err(|_| "pack_lifecycle_version_invalid")?;
    // Public package releases only. Local build labels cannot create a newer
    // installed authority; retain the existing three-component release bound.
    if version.release().len() != 3 || !version.local().is_empty() {
        return Err("pack_lifecycle_profile_version_invalid".into());
    }
    Ok(version)
}

fn remote(value: &str) -> Result<Vec<u64>, String> {
    if value.is_empty() || value.len() > 64 {
        return Err("pack_lifecycle_version_invalid".into());
    }
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 2
        || parts
            .iter()
            .any(|s| s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err("pack_lifecycle_profile_version_invalid".into());
    }
    parts
        .into_iter()
        .map(|s| {
            s.parse()
                .map_err(|_| "pack_lifecycle_version_invalid".into())
        })
        .collect()
}

pub(super) fn validate(profile: &str, value: &str) -> Result<(), String> {
    compare(profile, value, value).map(|_| ())
}

pub(super) fn compare(profile: &str, new: &str, old: &str) -> Result<Ordering, String> {
    match profile {
        "installed" => Ok(installed(new)?.cmp(&installed(old)?)),
        "remote" => Ok(remote(new)?.cmp(&remote(old)?)),
        _ => Err("pack_lifecycle_profile_version_invalid".into()),
    }
}
