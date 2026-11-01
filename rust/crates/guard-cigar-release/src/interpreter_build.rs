//! Private interpreter distributions share the authenticated release catalog.
use crate::{
    types::{hex, identifier, platform},
    CatalogCheckpoint, Qualification, ReleaseError, TrustedCatalog,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterBuild {
    pub build_id: String,
    pub python_version: [u16; 3],
    pub platform: String,
    pub source_release: String,
    pub source_revision: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub tree_sha256: String,
    pub files: u32,
    pub expanded_bytes: u64,
    pub executable_sha256: String,
    pub qualification: Qualification,
    pub qualification_receipt_sha256: Option<String>,
    pub withdrawn: bool,
}
impl InterpreterBuild {
    pub fn target(&self) -> Result<&'static str, ReleaseError> {
        match self.platform.as_str() {
            "darwin-arm64" => Ok("aarch64-apple-darwin"),
            "darwin-x64" => Ok("x86_64-apple-darwin"),
            "linux-x64-gnu" => Ok("x86_64-unknown-linux-gnu"),
            "linux-arm64-gnu" => Ok("aarch64-unknown-linux-gnu"),
            "linux-x64-musl" => Ok("x86_64-unknown-linux-musl"),
            "linux-arm64-musl" => Ok("aarch64-unknown-linux-musl"),
            "win32-x64" => Ok("x86_64-pc-windows-msvc"),
            _ => Err(ReleaseError::PlatformUnavailable),
        }
    }
    pub fn executable(&self) -> &'static str {
        if self.platform == "win32-x64" {
            "python.exe"
        } else {
            "bin/python3.14"
        }
    }
    pub fn filename(&self) -> Result<String, ReleaseError> {
        Ok(format!(
            "cpython-{}.{}.{}+{}-{}-install_only_stripped.tar.gz",
            self.python_version[0],
            self.python_version[1],
            self.python_version[2],
            self.source_release,
            self.target()?
        ))
    }
    pub fn download_url(&self) -> Result<String, ReleaseError> {
        self.validate()?;
        Ok(format!(
            "https://github.com/astral-sh/python-build-standalone/releases/download/{}/{}",
            self.source_release,
            self.filename()?.replace('+', "%2B")
        ))
    }
    /// Source spelling, catalog revision and qualification do not replace the
    /// same immutable bytes. No installed interpreter is overwritten in place.
    pub fn slot_id(&self) -> Result<String, ReleaseError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&(
            "guard-cigar-python-slot.v1",
            &self.build_id,
            self.python_version,
            &self.platform,
            &self.source_revision,
            &self.archive_sha256,
            &self.tree_sha256,
            &self.executable_sha256,
        ))
        .map_err(|_| ReleaseError::InvalidCatalog)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if !identifier(&self.build_id)
            || self.python_version[..2] != [3, 14]
            || !platform(&self.platform)
            || self.source_release.len() != 8
            || !self.source_release.bytes().all(|b| b.is_ascii_digit())
            || !hex(&self.source_revision, 40)
            || !hex(&self.archive_sha256, 64)
            || !hex(&self.tree_sha256, 64)
            || !hex(&self.executable_sha256, 64)
            || self.archive_bytes == 0
            || self.archive_bytes > 128 * 1024 * 1024
            || self.files == 0
            || self.files > 8192
            || self.expanded_bytes == 0
            || self.expanded_bytes > 256 * 1024 * 1024
            || self.qualification == Qualification::LocalCandidate
            || self
                .qualification_receipt_sha256
                .as_ref()
                .is_some_and(|value| !hex(value, 64))
            || self.qualification == Qualification::GuardQualified
                && self.qualification_receipt_sha256.is_none()
        {
            return Err(ReleaseError::InvalidCatalog);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedInterpreterBuild {
    build: InterpreterBuild,
    checkpoint: CatalogCheckpoint,
    setup_qualified: bool,
}
impl ResolvedInterpreterBuild {
    pub(crate) fn from_installed(build: InterpreterBuild, checkpoint: CatalogCheckpoint) -> Self {
        Self {
            build,
            checkpoint,
            setup_qualified: true,
        }
    }
    pub fn build(&self) -> &InterpreterBuild {
        &self.build
    }
    pub fn checkpoint(&self) -> &CatalogCheckpoint {
        &self.checkpoint
    }
    pub fn setup_qualified(&self) -> bool {
        self.setup_qualified
    }
}
impl TrustedCatalog {
    /// Trusted bytes may be prepared for explicit synthetic qualification.
    /// This does not authorize automatic setup or SDK activation.
    pub fn prepare_interpreter(
        &self,
        id: &str,
        platform: &str,
    ) -> Result<ResolvedInterpreterBuild, ReleaseError> {
        let build = self
            .document()
            .interpreters
            .iter()
            .find(|build| build.build_id == id)
            .ok_or(ReleaseError::BuildUnknown)?;
        if build.withdrawn {
            return Err(ReleaseError::BuildWithdrawn);
        }
        if build.platform != platform {
            return Err(ReleaseError::PlatformUnavailable);
        }
        Ok(ResolvedInterpreterBuild {
            build: build.clone(),
            checkpoint: self.checkpoint().clone(),
            setup_qualified: false,
        })
    }
    pub fn interpreter_for_setup(
        &self,
        id: &str,
        platform: &str,
    ) -> Result<ResolvedInterpreterBuild, ReleaseError> {
        let mut result = self.prepare_interpreter(id, platform)?;
        if result.build.qualification != Qualification::GuardQualified {
            return Err(ReleaseError::QualificationRequired);
        }
        result.setup_qualified = true;
        Ok(result)
    }
}
pub(crate) fn validate(builds: &[InterpreterBuild]) -> Result<(), ReleaseError> {
    if builds.len() > 32 {
        return Err(ReleaseError::InvalidCatalog);
    }
    let mut ids = BTreeSet::new();
    for build in builds {
        build.validate()?;
        if !ids.insert(&build.build_id) {
            return Err(ReleaseError::DuplicateIdentity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{document, verify};
    #[test]
    fn interpreter_origins_are_fixed_and_setup_requires_qualification() {
        let catalog = TrustedCatalog::bundled().unwrap();
        let build = &catalog.document().interpreters[0];
        assert_eq!(build.python_version, [3, 14, 10]);
        assert_eq!(build.download_url().unwrap(),"https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.14.10%2B20261026-aarch64-apple-darwin-install_only_stripped.tar.gz");
        // Preparing never grants setup; only a qualified entry resolves for it.
        assert!(!catalog
            .prepare_interpreter(&build.build_id, "darwin-arm64")
            .unwrap()
            .setup_qualified());
        assert!(catalog
            .interpreter_for_setup(&build.build_id, "darwin-arm64")
            .unwrap()
            .setup_qualified());
        let mut doc = document();
        doc.interpreters[0].qualification = Qualification::UpstreamOnly;
        doc.interpreters[0].qualification_receipt_sha256 = None;
        assert_eq!(
            verify(&doc)
                .unwrap()
                .interpreter_for_setup(&build.build_id, "darwin-arm64")
                .unwrap_err(),
            ReleaseError::QualificationRequired
        );
        doc.interpreters[0].qualification = Qualification::GuardQualified;
        doc.interpreters[0].qualification_receipt_sha256 = Some("b".repeat(64));
        let qualified = verify(&doc)
            .unwrap()
            .interpreter_for_setup(&build.build_id, "darwin-arm64")
            .unwrap();
        assert!(qualified.setup_qualified());
        assert_eq!(
            qualified.build().slot_id().unwrap(),
            build.slot_id().unwrap()
        );
        assert_eq!(
            catalog
                .prepare_interpreter(&build.build_id, "win32-x64")
                .unwrap_err(),
            ReleaseError::PlatformUnavailable
        );
        doc.interpreters[0].withdrawn = true;
        assert_eq!(
            verify(&doc)
                .unwrap()
                .prepare_interpreter(&build.build_id, "darwin-arm64")
                .unwrap_err(),
            ReleaseError::BuildWithdrawn
        );
    }
    #[test]
    fn malformed_interpreter_builds_are_not_authenticated_catalog_data() {
        for field in ["family", "tag", "hash", "size", "receipt", "duplicate"] {
            let mut doc = document();
            if field == "duplicate" {
                doc.interpreters.push(doc.interpreters[0].clone());
                assert!(verify(&doc).is_err(), "{field}");
                continue;
            }
            let build = &mut doc.interpreters[0];
            match field {
                "family" => build.python_version = [3, 15, 0],
                "tag" => build.source_release = "../escape".into(),
                "hash" => build.tree_sha256 = "not-a-hash".into(),
                "size" => build.expanded_bytes = 257 * 1024 * 1024,
                "receipt" => {
                    build.qualification = Qualification::GuardQualified;
                    build.qualification_receipt_sha256 = None;
                }
                _ => unreachable!(),
            }
            assert!(verify(&doc).is_err(), "{field}");
        }
    }
}
