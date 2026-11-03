//! Distinct timestamps for naming test fixture directories.
//!
//! Tests share one process and run on parallel threads. macOS reports the wall
//! clock in whole microseconds, so two fixtures created in the same
//! microsecond were given the same `pid-nanos` name and wrote into one
//! directory. Each call here returns a later value than the call before it.

use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// Nanoseconds since the Unix epoch, strictly increasing within this process.
// Some test targets call this only from tests built for one platform.
#[allow(dead_code)]
pub(crate) fn unique_nanos() -> u128 {
    static LAST: Mutex<u128> = Mutex::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut last = LAST.lock().unwrap_or_else(PoisonError::into_inner);
    *last = now.max(*last + 1);
    *last
}
