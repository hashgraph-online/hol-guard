//! Judging a command that the harness runs inside its own process.
//!
//! Some harness helpers run a program for the agent without starting a shell
//! tool call: Oh My Pi's `commit` eval prelude runs Git from the host
//! process. Guard judges such a helper as the command it stands for, but no
//! sink exists to rewrite that run into the workspace sandbox. While this
//! scope is active, containment is not offered, so the command must be proven
//! on its own or keep its review.

use std::cell::Cell;

thread_local! {
    static IN_PROCESS: Cell<bool> = const { Cell::new(false) };
}

/// Marks the evaluations on this thread as in-process until the guard drops.
/// A nested scope restores the outer state.
pub(in crate::pretool) fn scope() -> Scope {
    Scope(IN_PROCESS.with(|flag| flag.replace(true)))
}

#[must_use]
pub(in crate::pretool) struct Scope(bool);

impl Drop for Scope {
    fn drop(&mut self) {
        let outer = self.0;
        let _ = IN_PROCESS.try_with(|flag| flag.set(outer));
    }
}

/// Whether the command being judged runs in the harness process, where the
/// workspace sandbox cannot reach it.
pub(in crate::pretool) fn active() -> bool {
    IN_PROCESS.with(Cell::get)
}
