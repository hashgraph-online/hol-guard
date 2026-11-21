//! Failure taxonomy of the workflow-capability authority port. Capability and
//! runtime failures are outcomes the Python caller re-raises as
//! `WorkflowCapabilityError` / `RuntimeError`; store failures keep the
//! `guard_store` mapping.

use rusqlite::ErrorCode;

use crate::guard_store_db::StoreError;

#[derive(Debug)]
pub(crate) enum WfError {
    /// Python `WorkflowCapabilityError(code)`.
    Capability(String),
    /// Python `RuntimeError(message)`.
    Runtime(String),
    Store(StoreError),
}

pub(crate) type WfResult<T> = Result<T, WfError>;

pub(crate) fn cap<T>(code: impl Into<String>) -> WfResult<T> {
    Err(WfError::Capability(code.into()))
}

impl From<StoreError> for WfError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<rusqlite::Error> for WfError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(StoreError::Sqlite(error))
    }
}

/// `except sqlite3.IntegrityError`.
pub(crate) fn is_integrity(error: &WfError) -> bool {
    matches!(
        error,
        WfError::Store(StoreError::Sqlite(inner))
            if inner.sqlite_error_code() == Some(ErrorCode::ConstraintViolation)
    )
}
