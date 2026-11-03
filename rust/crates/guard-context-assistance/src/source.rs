//! Protected native document reads. These host-only values cannot be supplied
//! as JSON authority. A root still needs an explicit app/workspace grant.
use crate::{ContextDocument, RuntimeError};
use guard_secure_fs::{
    classify_source_path, contains_symlink_component, credential_directory_path,
    credential_named_path, read_bounded,
};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_FILE_BYTES: usize = 65_536;
const CHUNK_BYTES: usize = 4_096;

#[derive(Clone)]
pub struct SourceRoot {
    path: PathBuf,
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(windows)]
    identity: guard_cigar_artifacts::host::FileId,
}

pub struct AdmittedFile {
    pub source_id: String,
    pub relative_path: String,
    pub sha256: String,
    pub documents: Vec<ContextDocument>,
}

impl SourceRoot {
    pub fn inspect(path: &Path) -> Result<Self, RuntimeError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            || credential_directory_path(path)
            || contains_symlink_component(path)
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let canonical = guard_cigar_artifacts::host::is_canonical(path)
            .map_err(|_| RuntimeError::ScopeDenied)?;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| RuntimeError::ScopeDenied)?;
        if !metadata.is_dir() || !canonical || contains_symlink_component(path) {
            return Err(RuntimeError::ScopeDenied);
        }
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(windows)]
        let identity =
            guard_cigar_artifacts::host::node_id(path).map_err(|_| RuntimeError::ScopeDenied)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn revalidate(&self) -> Result<(), RuntimeError> {
        let observed = Self::inspect(&self.path)?;
        if self.identity != observed.identity {
            return Err(RuntimeError::ContextStale);
        }
        Ok(())
    }

    /// No globbing, recursion, locator dereference, external path or symlink.
    /// Secret scans are native and failures never send partial text to the SDK.
    pub fn read(&self, relative: &str) -> Result<AdmittedFile, RuntimeError> {
        validate_relative(relative)?;
        self.revalidate()?;
        // The decision names the file by its canonical spelling, which on
        // Windows carries the `\\?\` prefix the stored root may leave off.
        let root = std::fs::canonicalize(&self.path).map_err(|_| RuntimeError::ScopeDenied)?;
        let decision = classify_source_path(relative, &self.path, None, false);
        let selected = decision
            .resolved_path
            .filter(|_| decision.allowed)
            .filter(|path| path.starts_with(&root))
            .ok_or(RuntimeError::ScopeDenied)?;
        let read = read_bounded(&selected, MAX_FILE_BYTES)
            .map_err(|_| RuntimeError::ArtifactUnreadable)?;
        self.revalidate()?;
        let text = String::from_utf8(read.bytes).map_err(|_| RuntimeError::RequestInvalid)?;
        if text.is_empty()
            || text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return Err(RuntimeError::RequestInvalid);
        }
        let scan = guard_scanner::scan_text(
            &text,
            true,
            false,
            MAX_FILE_BYTES,
            Some(Instant::now() + Duration::from_millis(100)),
        );
        if scan.budget_exhausted || scan.bytes_scanned != text.len() || !scan.matches.is_empty() {
            return Err(RuntimeError::ScopeDenied);
        }
        let source_id = format!("source:{:x}", Sha256::digest(relative.as_bytes()));
        let mut documents = Vec::new();
        let mut chunk = String::new();
        let mut start_line = 1_u32;
        let mut line = 1_u32;
        for piece in text.split_inclusive('\n') {
            if piece.len() > CHUNK_BYTES {
                return Err(RuntimeError::ResourceLimit);
            }
            if !chunk.is_empty() && chunk.len() + piece.len() > CHUNK_BYTES {
                documents.push(document(
                    &source_id,
                    documents.len(),
                    std::mem::take(&mut chunk),
                    start_line,
                ));
                start_line = line;
            }
            chunk.push_str(piece);
            line = line.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
        }
        if !chunk.is_empty() {
            documents.push(document(&source_id, documents.len(), chunk, start_line));
        }
        Ok(AdmittedFile {
            source_id,
            relative_path: relative.into(),
            sha256: read.sha256,
            documents,
        })
    }
}

pub(super) fn validate_relative(relative: &str) -> Result<(), RuntimeError> {
    let path = Path::new(relative);
    if relative.is_empty()
        || relative.len() > 1024
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || relative.contains('\\')
        || relative.contains(':')
        || credential_named_path(path)
        || credential_directory_path(path)
    {
        return Err(RuntimeError::ScopeDenied);
    }
    Ok(())
}

fn document(source: &str, index: usize, text: String, start_line: u32) -> ContextDocument {
    ContextDocument {
        id: format!("doc:{}:{index}", &source[7..]),
        text,
        start_line,
    }
}

#[cfg(test)]
#[path = "source_tests.rs"]
mod tests;
