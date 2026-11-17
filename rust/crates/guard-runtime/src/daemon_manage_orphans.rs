//! Daemons of this home that a start finds running without state it can
//! adopt. Desktop updates leave them behind when a stop removes the old
//! daemon's state but the process keeps running: the replacement launch then
//! exits on the port it still holds, and that launch's receipt blocks every
//! later start, rollbacks included.

use std::path::Path;

use serde_json::{Map, Value};

use super::host::{self, Caller};
use super::records;
use super::retire::{self, Deadline};

/// The launch behind an abandoned receipt died without handing off, but a
/// daemon of this home it never started keeps the receipt open. Retire that
/// daemon so the receipt resolves instead of refusing every later start.
pub(super) fn release_abandoned_receipt(
    caller: &Caller,
    home: &Path,
    pending: Option<&Map<String, Value>>,
    deadline: Deadline,
) {
    if retire::pending_is_abandoned(pending)
        && !records::pending_is_resolved(home)
        && !retire::resolve_abandoned(caller, pending)
    {
        retire::retire_all(caller, None, deadline);
    }
}

/// A daemon of this home still running when a start is about to launch was
/// neither live under its state nor adoptable: its state was lost, or it runs
/// another runtime. It still holds its port, so a launch there would exit
/// without handing off. Retire it first; a launch then reports anything that
/// remains.
pub(super) fn retire_unadopted(caller: &Caller, deadline: Deadline) {
    if host::daemon_inventory(caller).is_some_and(|inventory| !inventory.is_empty()) {
        retire::retire_all(caller, None, deadline);
    }
}
