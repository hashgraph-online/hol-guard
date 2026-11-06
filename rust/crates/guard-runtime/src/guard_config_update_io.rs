//! One short, cross-process config writer lane. CIGAR preparation never owns
//! this lock: only the final settings read/compare/atomic replacement does.
use super::*;

#[path = "guard_config_update_io_writer.rs"]
mod writer;
pub(crate) use writer::catalog::CatalogPair;
#[cfg(all(test, unix))]
pub(crate) use writer::catalog::{fault_next as catalog_fault_next, Fault as CatalogFault};
#[cfg(all(test, unix))]
pub(crate) use writer::fail_next_config_write_after_rename;
pub(crate) use writer::lifecycle::LifecycleFile;
#[cfg(all(test, unix))]
pub(crate) use writer::lifecycle::{
    fail_next_erasure_intent_after_rename, fail_next_lifecycle_record_after_rename,
};
pub(crate) use writer::WriteLock;
/// The config directory's identity, compared across one switch.
pub(crate) use writer::{root_identity_of, Node as RootIdentity};

#[cfg(all(test, unix))]
#[path = "guard_config_update_io_tests.rs"]
mod tests;
