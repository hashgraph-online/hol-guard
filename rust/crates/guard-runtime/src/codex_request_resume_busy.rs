//! One SQLite busy-wait budget shared by every statement of a resume call.
//!
//! A retry reads and updates the record before dispatch and again after it.
//! A per-statement `busy_timeout` would let each of those statements wait the
//! full timeout, so a contended store could outlast the caller's deadline of
//! `timeout_ms + busy_timeout_ms` plus grace while the resident still sends the
//! continuation. The budget below caps the summed waits of one call instead.

use std::cell::Cell;
use std::time::Duration;

use rusqlite::Connection;

const BUSY_STEP: Duration = Duration::from_millis(5);

thread_local! {
    static BUSY_BUDGET: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// Give `connection` a busy handler that draws from a fresh budget of
/// `busy_timeout_ms` for the call running on this thread.
pub(crate) fn arm(connection: &Connection, busy_timeout_ms: u64) -> rusqlite::Result<()> {
    BUSY_BUDGET.with(|budget| budget.set(Duration::from_millis(busy_timeout_ms)));
    connection.busy_handler(Some(wait_within_budget))
}

fn wait_within_budget(_attempt: i32) -> bool {
    BUSY_BUDGET.with(|budget| {
        let remaining = budget.get();
        if remaining.is_zero() {
            return false;
        }
        let step = remaining.min(BUSY_STEP);
        std::thread::sleep(step);
        budget.set(remaining - step);
        true
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use rusqlite::{Connection, ErrorCode};

    use super::arm;

    #[test]
    fn statements_of_one_call_share_a_single_busy_budget() {
        let dir = std::env::temp_dir().join(format!("resume-busy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        let holder = Connection::open(&path).unwrap();
        holder
            .execute_batch("CREATE TABLE t (v INTEGER); BEGIN EXCLUSIVE;")
            .unwrap();
        let caller = Connection::open(&path).unwrap();
        arm(&caller, 200).unwrap();

        let started = Instant::now();
        for _ in 0..3 {
            let error = caller
                .execute("INSERT INTO t (v) VALUES (1)", [])
                .unwrap_err();
            assert_eq!(error.sqlite_error_code(), Some(ErrorCode::DatabaseBusy));
        }

        // Three statements each waiting a 200 ms timeout would take 600 ms;
        // the shared budget stops waiting after the first 200 ms.
        let elapsed = started.elapsed();
        drop((caller, holder));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(elapsed < Duration::from_millis(450), "waited {elapsed:?}");
    }
}
