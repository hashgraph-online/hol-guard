//! The variables a jq command line binds before its filter runs.
//!
//! `--arg`, `--argjson`, `--slurpfile` and `--rawfile` each bind a `$name`
//! the filter may read. The argument proof has already checked what each one
//! holds, so while it checks the filter those names count as bound. Every
//! other check, such as a `gh --jq` filter, runs with none.

use std::cell::RefCell;

thread_local! {
    static NAMES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Clears the names when the check ends, even by unwinding, so they never
/// reach a later filter.
struct Scope;

impl Drop for Scope {
    fn drop(&mut self) {
        NAMES.with(|bound| bound.borrow_mut().clear());
    }
}

/// [`super::safe_filter`] for a filter jq runs with `names` already bound by
/// `--arg` and the like, so a `$name` among them reads a value the command
/// line supplied rather than the environment.
pub(in crate::pretool) fn safe_filter_binding(filter: &str, names: &[&str]) -> bool {
    with_names(names, || super::safe_filter(filter))
}

fn with_names<T>(names: &[&str], check: impl FnOnce() -> T) -> T {
    NAMES.with(|bound| {
        *bound.borrow_mut() = names.iter().map(|name| (*name).to_owned()).collect();
    });
    let _scope = Scope;
    check()
}

pub(super) fn bound(name: &str) -> bool {
    NAMES.with(|bound| bound.borrow().iter().any(|value| value == name))
}
