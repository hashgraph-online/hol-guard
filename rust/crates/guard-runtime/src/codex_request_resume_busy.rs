//! One SQLite busy-wait budget shared by every statement of a resume call.
//!
//! A retry reads and updates the record before dispatch and again after it.
//! A per-statement `busy_timeout` would let each of those statements wait the
//! full timeout, so a contended store could outlast the caller's deadline of
//! `timeout_ms + busy_timeout_ms` plus grace while the resident still sends the
//! continuation. The budget below caps the summed waits of one call instead,
//! measured as elapsed time rather than requested sleeps.

use std::cell::Cell;
use std::time::{Duration, Instant};

use rusqlite::Connection;

const BUSY_STEP: Duration = Duration::from_millis(5);

thread_local! {
    static BUSY_BUDGET: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

#[cfg(test)]
thread_local! {
    /// Sleeps this thread's busy handler has performed since `arm`. A test
    /// reads it to tell a shared budget from a per-statement one, which timing
    /// a loaded host cannot do.
    static BUSY_SLEEPS: Cell<u32> = const { Cell::new(0) };
}

#[cfg(test)]
fn busy_sleeps() -> u32 {
    BUSY_SLEEPS.with(Cell::get)
}

/// Give `connection` a busy handler that draws from a fresh budget of
/// `busy_timeout_ms` for the call running on this thread.
pub(crate) fn arm(connection: &Connection, busy_timeout_ms: u64) -> rusqlite::Result<()> {
    BUSY_BUDGET.with(|budget| budget.set(Duration::from_millis(busy_timeout_ms)));
    #[cfg(test)]
    BUSY_SLEEPS.with(|sleeps| sleeps.set(0));
    connection.busy_handler(Some(wait_within_budget))
}

fn wait_within_budget(_attempt: i32) -> bool {
    BUSY_BUDGET.with(|budget| {
        let remaining = budget.get();
        if remaining.is_zero() {
            return false;
        }
        // Charge the time actually slept: a loaded host can oversleep each
        // step many times over, and the cap is on wall-clock waiting.
        let started = Instant::now();
        std::thread::sleep(remaining.min(BUSY_STEP));
        budget.set(remaining.saturating_sub(started.elapsed()));
        #[cfg(test)]
        BUSY_SLEEPS.with(|sleeps| sleeps.set(sleeps.get().saturating_add(1)));
        true
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, ErrorCode};

    use super::{arm, busy_sleeps};

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

        let mut sleeps = Vec::new();
        for _ in 0..3 {
            let before = busy_sleeps();
            let error = caller
                .execute("INSERT INTO t (v) VALUES (1)", [])
                .unwrap_err();
            assert_eq!(error.sqlite_error_code(), Some(ErrorCode::DatabaseBusy));
            sleeps.push(busy_sleeps() - before);
        }
        drop((caller, holder));
        std::fs::remove_dir_all(&dir).unwrap();

        // The first statement spends the whole budget: at most the 40 five-
        // millisecond steps 200 ms buys, and fewer when a loaded host oversleeps
        // them. A per-statement timeout would then let the second and third wait
        // their own 200 ms, so their silence is what makes the budget shared.
        assert!((1..=40).contains(&sleeps[0]), "waited {sleeps:?}");
        assert_eq!((sleeps[1], sleeps[2]), (0, 0), "waited {sleeps:?}");
    }
}
