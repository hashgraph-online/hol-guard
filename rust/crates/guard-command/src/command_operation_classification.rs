//! Rust port of `runtime/command_operation_classification.py` — local
//! side-effect authority classes for Guard Cloud commands.
//!
//! Constants are byte-verbatim from the Python source; `frozenset`s map to
//! `&[&str]` lookup tables (callers test membership via `.contains`).

/// `READ_ONLY_COMMAND_OPERATIONS` (:4-10).
pub const READ_ONLY_COMMAND_OPERATIONS: &[&str] = &[
    "guard.packageShims.status",
    "guard.packageShims.test",
    "guard.packageShims.audit",
    "guard.app.status",
    "guard.app.updateCheck",
];

/// `LOCAL_CONFIRMATION_COMMAND_OPERATIONS` (:11-16).
pub const LOCAL_CONFIRMATION_COMMAND_OPERATIONS: &[&str] =
    &["guard.packageShims.remove", "guard.app.remove"];

/// `STATE_CHANGING_COMMAND_OPERATIONS` (:17-25).
pub const STATE_CHANGING_COMMAND_OPERATIONS: &[&str] = &[
    "guard.packageShims.repair",
    "guard.packageShims.sync",
    "guard.packageShims.install",
    "guard.app.repair",
    "guard.app.connect",
    "guard.app.update",
    "guard.review.syncPolicyMemory",
];

/// `POLICY_MEMORY_COMMAND_OPERATIONS` (:26).
pub const POLICY_MEMORY_COMMAND_OPERATIONS: &[&str] = &["guard.review.syncPolicyMemory"];

/// `REMOTE_STEP_UP_COMMAND_OPERATIONS` (:27) — intentionally empty.
pub const REMOTE_STEP_UP_COMMAND_OPERATIONS: &[&str] = &[];
