//! One short, cross-process config writer lane. CIGAR preparation never owns
//! this lock: only the final settings read/compare/atomic replacement does.
use super::*;

#[cfg(unix)]
#[path = "guard_config_update_io_unix.rs"]
mod unix;
#[cfg(unix)]
pub(crate) use unix::catalog::CatalogPair;
#[cfg(all(test, unix))]
pub(crate) use unix::catalog::{fault_next as catalog_fault_next, Fault as CatalogFault};
#[cfg(all(test, unix))]
pub(crate) use unix::fail_next_config_write_after_rename;
#[cfg(unix)]
pub(crate) use unix::lifecycle::LifecycleFile;
#[cfg(all(test, unix))]
pub(crate) use unix::lifecycle::{
    fail_next_erasure_intent_after_rename, fail_next_lifecycle_record_after_rename,
};
#[cfg(unix)]
pub(crate) use unix::WriteLock;

// Preserve the existing writer on other hosts until its native CIGAR switching
// path has a separately qualified handle/ACL implementation.
#[cfg(not(unix))]
pub(crate) struct WriteLock(PathBuf);
#[cfg(not(unix))]
impl WriteLock {
    pub(crate) fn acquire(home: &Path) -> Result<Self, Failure> {
        Ok(Self(home.into()))
    }
    pub(crate) fn publish(&self, expected: Option<&str>, text: &str) -> Result<(), Failure> {
        if read_home_config(&self.0)?.as_deref() != expected {
            return Err(Failure::Error("config_file_changed".into()));
        }
        fs::write(self.0.join(HOME_CONFIG_FILENAME), text)
            .map_err(|_| Failure::Error("config_write_failed".into()))
    }
}

#[cfg(all(test, unix))]
#[path = "guard_config_update_io_tests.rs"]
mod tests;
