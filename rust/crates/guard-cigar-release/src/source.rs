//! Declarative origins are confined to named upstream release hosts.
use crate::{types::hex, ReleaseError, WheelLock, WheelSource};

impl WheelLock {
    /// Returns a credential-free, fixed-origin URL. Hashes and exact lengths
    /// remain mandatory; a URL never grants permission to execute a wheel.
    pub fn download_url(&self) -> Result<Option<String>, ReleaseError> {
        if !crate::labels::wheel_filename(&self.filename) {
            return Err(ReleaseError::InvalidCatalog);
        }
        match &self.source {
            WheelSource::OfflineBundle => Ok(None),
            WheelSource::GithubCigarRelease { tag } => {
                if self.distribution != "hol-cigar" || !crate::labels::producer_label(tag) {
                    return Err(ReleaseError::InvalidCatalog);
                }
                Ok(Some(format!(
                    "https://github.com/hashgraph-online/hol-cigar/releases/download/{tag}/{}",
                    self.filename
                )))
            }
            WheelSource::PypiFile { path } => {
                let parts: Vec<_> = path
                    .strip_prefix("/packages/")
                    .ok_or(ReleaseError::InvalidCatalog)?
                    .split('/')
                    .collect();
                if self.distribution == "hol-cigar"
                    || parts.len() != 4
                    || !hex(parts[0], 2)
                    || !hex(parts[1], 2)
                    || !hex(parts[2], 60)
                    || parts[3] != self.filename
                    || path.len() > 400
                {
                    return Err(ReleaseError::InvalidCatalog);
                }
                Ok(Some(format!("https://files.pythonhosted.org{path}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dependency(path: &str) -> WheelLock {
        WheelLock {
            distribution: "protobuf".into(),
            version: "7.36.2".into(),
            filename: "protobuf-7.36.2-py3-none-any.whl".into(),
            sha256: "a".repeat(64),
            bytes: 10,
            requires_python: None,
            source: WheelSource::PypiFile { path: path.into() },
        }
    }
    #[test]
    fn only_exact_content_addressed_dependency_files_are_allowed() {
        let path = format!(
            "/packages/32/72/{}/protobuf-7.36.2-py3-none-any.whl",
            "a".repeat(60)
        );
        let lock = dependency(&path);
        assert_eq!(
            lock.download_url().unwrap(),
            Some(format!("https://files.pythonhosted.org{path}"))
        );
        for path in [
            format!("{path}?token=x"),
            format!("{path}#x"),
            path.replace("/32/", "/../"),
            path.replace("protobuf-7.36.2", "other-7.36.2"),
            format!("https://untrusted.example{path}"),
            path.replace("/packages/", "//packages/"),
            path.replace("/72/", "/%37%32/"),
        ] {
            assert!(dependency(&path).download_url().is_err(), "{path}");
        }
        let mut sdk = lock;
        sdk.distribution = "hol-cigar".into();
        assert!(sdk.download_url().is_err());
    }
}
