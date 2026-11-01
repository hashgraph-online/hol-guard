//! Interpreter patch constraints are locked release data, not an SDK pin.
use crate::{ReleaseError, ResolvedRelease, WheelLock};
use pep440_rs::{Version, VersionSpecifiers};
use std::str::FromStr;

pub(crate) fn validate_requirement(text: &str) -> Result<VersionSpecifiers, ReleaseError> {
    if text.is_empty()
        || text.len() > 256
        || !text.is_ascii()
        || text.trim() != text
        || text.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ReleaseError::InvalidCatalog);
    }
    VersionSpecifiers::from_str(text).map_err(|_| ReleaseError::InvalidCatalog)
}
impl WheelLock {
    pub fn check_python_version(&self, version: [u16; 3]) -> Result<(), ReleaseError> {
        if let Some(requirement) = &self.requires_python {
            let version = Version::new(version.map(u64::from));
            if !validate_requirement(requirement)?.contains(&version) {
                return Err(ReleaseError::PythonVersionRequired);
            }
        }
        Ok(())
    }
}
impl ResolvedRelease {
    /// Native probe/registration supplies measured final interpreter facts.
    /// Passing this metadata check alone is never proof of an interpreter.
    pub fn check_python_version(&self, version: [u16; 3]) -> Result<(), ReleaseError> {
        if version[0] != self.profile().python_major || version[1] != self.profile().python_minor {
            return Err(ReleaseError::PythonVersionRequired);
        }
        for wheel in self
            .platform()
            .wheel
            .iter()
            .chain(&self.platform().dependencies)
        {
            wheel.check_python_version(version)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustedCatalog;
    #[test]
    fn future_patch_requirement_is_data_and_existing_3147_remains_eligible() {
        let catalog = TrustedCatalog::bundled().unwrap();
        let build = &catalog.document().builds[0];
        let release = catalog
            .prepare(&build.identity.build_id, "darwin-arm64", false)
            .unwrap();
        release.check_python_version([3, 14, 7]).unwrap();
        assert_eq!(
            release.check_python_version([3, 13, 9]),
            Err(ReleaseError::PythonVersionRequired)
        );
        assert_eq!(
            release.check_python_version([3, 15, 0]),
            Err(ReleaseError::PythonVersionRequired)
        );
        let mut dependency = release.platform().dependencies[0].clone();
        dependency.requires_python = Some(">=3.14.8,<3.15,!=3.14.9".into());
        assert_eq!(
            dependency.check_python_version([3, 14, 7]),
            Err(ReleaseError::PythonVersionRequired)
        );
        dependency.check_python_version([3, 14, 8]).unwrap();
        assert_eq!(
            dependency.check_python_version([3, 14, 9]),
            Err(ReleaseError::PythonVersionRequired)
        );
        dependency.check_python_version([3, 14, 10]).unwrap();
        // Missing optional metadata retains compatibility with old archived
        // receipts. It does not bypass the shipped adapter's 3.14 check.
        dependency.requires_python = None;
        dependency.check_python_version([3, 14, 7]).unwrap();
    }
    #[test]
    fn malformed_or_unbounded_requirements_are_not_catalog_authority() {
        for text in [
            "",
            "3.14.7",
            ">=3.14\n",
            ">=3.14\r\nOther: x",
            " >=3.14",
            "https://example.com",
            ">=三",
        ] {
            assert!(validate_requirement(text).is_err(), "{text}");
        }
        assert!(validate_requirement(&">=3.14,".repeat(40)).is_err());
        validate_requirement(">=3.14,<3.15").unwrap();
    }
}
