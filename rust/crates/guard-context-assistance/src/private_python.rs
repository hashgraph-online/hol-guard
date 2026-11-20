//! Complete private interpreter checks shared by startup and every new process.
use crate::{RuntimeError, RuntimeSelection};
use guard_cigar_artifacts::{check_python_binding, verify_python_binding, InstallError};
use guard_cigar_release::InterpreterBinding;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};

/// Only native-owned installation records may supply these paths and bindings.
/// Deserialization is metadata; the owner must authenticate its local receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePythonSelection {
    pub root: PathBuf,
    pub binding: InterpreterBinding,
}
fn runtime_error(error: InstallError) -> RuntimeError {
    match error {
        InstallError::Cancelled => RuntimeError::Cancelled,
        InstallError::DeadlineExceeded => RuntimeError::DeadlineExceeded,
        _ => RuntimeError::ApprovalMismatch,
    }
}
impl RuntimeSelection {
    /// Explicit preparation/activation only. This cache is never serialized;
    /// each new owner process must authenticate metadata and verify all bytes.
    pub fn verify_private_python(
        &mut self,
        cancel: Option<&AtomicBool>,
    ) -> Result<(), RuntimeError> {
        if let Some(python) = &self.python_bundle {
            if self.verified_python.is_none() {
                if self.python != python.root.join(python.binding.executable()) {
                    return Err(RuntimeError::ApprovalMismatch);
                }
                self.verified_python = Some(Arc::new(
                    verify_python_binding(&python.binding, &python.root, cancel)
                        .map_err(runtime_error)?,
                ));
            }
        }
        check_selection(self, None, cancel).map(|_| ())
    }
}
pub(crate) fn check_selection(
    selection: &RuntimeSelection,
    platform: Option<&str>,
    cancel: Option<&AtomicBool>,
) -> Result<Option<InterpreterBinding>, RuntimeError> {
    let Some(python) = &selection.python_bundle else {
        return if selection.verified_python.is_none() {
            Ok(None)
        } else {
            Err(RuntimeError::ApprovalMismatch)
        };
    };
    if selection.python != python.root.join(python.binding.executable())
        || platform.is_some_and(|value| value != python.binding.platform)
    {
        return Err(RuntimeError::ApprovalMismatch);
    }
    if let Some(snapshot) = &selection.verified_python {
        if !snapshot.matches(&python.root, &python.binding) {
            return Err(RuntimeError::ApprovalMismatch);
        }
        snapshot.recheck(cancel).map_err(runtime_error)?;
    } else {
        check_python_binding(&python.binding, &python.root, cancel).map_err(runtime_error)?;
    }
    Ok(Some(python.binding.clone()))
}

#[cfg(all(test, unix))]
#[path = "private_python_tests.rs"]
mod tests;
