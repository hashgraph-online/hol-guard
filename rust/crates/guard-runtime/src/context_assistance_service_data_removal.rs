//! Profile ownership spans revocation, cleanup acknowledgment and deletion.
use crate::policy_store::context_assistance_registry::switching::{DataRemoval, ScopeRemoval};
use guard_context_assistance::{EvidenceScopeErasure, RuntimeError};
use std::path::Path;
pub(super) enum Removal {
    All(DataRemoval),
    Scope(Box<ScopeRemoval>),
}
impl Removal {
    pub(super) fn acquire(home: &Path, resume: bool) -> Result<Self, RuntimeError> {
        if resume {
            ScopeRemoval::resume(home).map(|removal| Self::Scope(Box::new(removal)))
        } else {
            DataRemoval::acquire(home).map(Self::All)
        }
    }
    pub(super) fn run(self) -> Result<Option<EvidenceScopeErasure>, RuntimeError> {
        match self {
            Self::All(removal) => removal.remove().map(|_| None),
            Self::Scope(removal) => (*removal).remove(None).map(Some),
        }
    }
}
