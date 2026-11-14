//! Per-evaluation memo of recursive metadata walks.
//!
//! A compound command is proven segment by segment and again as a whole, so
//! a large `grep -r` root would otherwise be walked many times over and run
//! past the hook's decision budget. Every proof within one evaluation shares
//! a single walk of each tree. The memo is dropped when the evaluation
//! returns, so the next evaluation walks the tree again.
use std::cell::RefCell;
use std::path::{Path, PathBuf};

type WalkKey = (PathBuf, Vec<String>, Vec<String>, bool, bool, bool);
type Memo = Option<Vec<(WalkKey, bool)>>;

/// Walks whose answer depends on more than the tree: the pattern a content
/// walk clears files with, or the globs an include walk selects by. Each is
/// remembered under a key that spells every input it read, beside the
/// two counters a content walk leaves its clearance at.
type KeyedMemo = Option<Vec<(String, KeyedAnswer)>>;

/// A remembered walk: its answer and what it left its clearance's byte and
/// file counters at, zero for a walk that charges none.
type KeyedAnswer = (bool, u64, u64);

thread_local! {
    static MEMO: RefCell<Memo> = const { RefCell::new(None) };
    static KEYED: RefCell<KeyedMemo> = const { RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Every walk a test's evaluation actually ran, by kind and root.
    static WALKS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Record a walk that read the filesystem, for a test that counts them.
#[cfg(test)]
pub(in crate::pretool) fn count_walk(kind: &str, root: &Path) {
    WALKS.with(|walks| {
        walks
            .borrow_mut()
            .push(format!("{kind} {}", root.display()))
    });
}

/// The walks recorded on this thread since the last call.
#[cfg(test)]
pub(in crate::pretool) fn take_walks() -> Vec<String> {
    WALKS.with(|walks| std::mem::take(&mut *walks.borrow_mut()))
}

pub(in crate::pretool) fn with_walk_memo<T>(evaluate: impl FnOnce() -> T) -> T {
    struct Restore(Memo, KeyedMemo);
    impl Drop for Restore {
        fn drop(&mut self) {
            MEMO.with(|memo| *memo.borrow_mut() = self.0.take());
            KEYED.with(|memo| *memo.borrow_mut() = self.1.take());
        }
    }
    let _restore = Restore(
        MEMO.with(|memo| memo.replace(Some(Vec::new()))),
        KEYED.with(|memo| memo.replace(Some(Vec::new()))),
    );
    evaluate()
}

/// The result of `walk` for this tree, walking it only on first use within
/// an evaluation. Outside an evaluation scope nothing is recorded.
pub(super) fn memoized(
    root: &Path,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    git_metadata: bool,
    follow_links: bool,
    skip_hidden: bool,
    walk: impl FnOnce() -> bool,
) -> bool {
    let key: WalkKey = (
        root.to_path_buf(),
        excluded_files
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        excluded_directories
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        git_metadata,
        follow_links,
        skip_hidden,
    );
    let cached = MEMO.with(|memo| {
        memo.borrow().as_ref().map(|entries| {
            entries
                .iter()
                .find(|(entry, _)| *entry == key)
                .map(|(_, value)| *value)
        })
    });
    match cached {
        Some(Some(value)) => value,
        Some(None) => {
            let value = walk();
            MEMO.with(|memo| {
                if let Some(entries) = memo.borrow_mut().as_mut() {
                    entries.push((key, value));
                }
            });
            value
        }
        None => walk(),
    }
}

/// The result of `walk` under `key`, walking only on first use within an
/// evaluation. The caller's key must name every input the walk reads besides
/// the filesystem, because two walks that share a key share one answer.
///
/// One submission proves the same `grep` segment once per reading of the
/// command -- each envelope pass, each floor that re-reads a segment, each
/// projection a rewrite reaches -- and every one of those proofs walks the
/// same tree with the same pattern and globs. On a loaded host those repeats,
/// not any single walk, are what spend the hook's decision budget.
pub(in crate::pretool) fn memoized_keyed(key: String, walk: impl FnOnce() -> bool) -> bool {
    keyed(key, || (walk(), 0, 0), |_| true).0
}

/// [`memoized_keyed`] for a walk that may also fail by running out of time.
/// Its `false` cannot tell a sensitive file from an expired clock, so only a
/// proof is remembered: a later reading that asks again walks again, with
/// whatever budget it has, exactly as it would without the memo.
pub(in crate::pretool) fn memoized_proof(key: String, walk: impl FnOnce() -> bool) -> bool {
    keyed(key, || (walk(), 0, 0), |proven| proven).0
}

/// [`memoized_keyed`] for a walk that charges counters the caller carries
/// on: `walk` returns them as it left them, and so does a remembered answer.
/// The key must name the counters the walk started from.
fn memoized_charged(key: String, walk: impl FnOnce() -> KeyedAnswer) -> KeyedAnswer {
    keyed(key, walk, |_| true)
}

fn keyed(
    key: String,
    walk: impl FnOnce() -> KeyedAnswer,
    keep: impl FnOnce(bool) -> bool,
) -> KeyedAnswer {
    let cached = KEYED.with(|memo| {
        memo.borrow().as_ref().map(|entries| {
            entries
                .iter()
                .find(|(entry, _)| *entry == key)
                .map(|(_, value)| *value)
        })
    });
    match cached {
        Some(Some(value)) => value,
        Some(None) => {
            let value = walk();
            if keep(value.0) {
                KEYED.with(|memo| {
                    if let Some(entries) = memo.borrow_mut().as_mut() {
                        entries.push((key, value));
                    }
                });
            }
            value
        }
        None => walk(),
    }
}

/// [`super::tree::walk_uncached`] under a pattern clearance, once per
/// evaluation for each tree, reach, pattern and clearance count.
///
/// A clearance depends on the pattern and on what it has already read, so
/// its walk is remembered under both, and a remembered walk leaves the
/// clearance's counters where the walk itself would have: the walks after it
/// get no more than they would have had.
pub(super) fn cleared(
    root: PathBuf,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    (git_metadata, follow_links, skip_hidden): (bool, bool, bool),
    clearance: &crate::pretool::search_pattern_clearance::PatternClearance,
) -> bool {
    let (spent, files) = clearance.charged();
    let key = format!(
        "cleared\0{root:?}\0{excluded_files:?}\0{excluded_directories:?}\0\
         {git_metadata}\0{follow_links}\0{skip_hidden}\0{spent}\0{files}\0{}",
        clearance.expression()
    );
    let (proven, spent, files) = memoized_charged(key, || {
        let proven = super::tree::walk_uncached(
            root,
            excluded_files,
            excluded_directories,
            git_metadata,
            follow_links,
            Some(clearance),
            skip_hidden,
        );
        let (spent, files) = clearance.charged();
        (proven, spent, files)
    });
    clearance.recharge(spent, files);
    proven
}

#[cfg(test)]
mod tests {
    use super::{memoized, memoized_keyed, memoized_proof, with_walk_memo};
    use std::cell::Cell;
    use std::path::Path;

    #[test]
    fn one_evaluation_answers_each_keyed_walk_once() {
        let walks = Cell::new(0);
        let walk = || {
            walks.set(walks.get() + 1);
            true
        };
        with_walk_memo(|| {
            assert!(memoized_keyed("a".to_owned(), walk));
            assert!(memoized_keyed("a".to_owned(), walk));
            assert!(memoized_keyed("b".to_owned(), walk));
        });
        assert_eq!(walks.get(), 2);
        with_walk_memo(|| assert!(memoized_keyed("a".to_owned(), walk)));
        assert!(memoized_keyed("a".to_owned(), walk));
        assert_eq!(walks.get(), 4);
    }

    #[test]
    fn a_refused_proof_is_asked_again() {
        let walks = Cell::new(0);
        with_walk_memo(|| {
            let refuse = || {
                walks.set(walks.get() + 1);
                false
            };
            assert!(!memoized_proof("a".to_owned(), refuse));
            assert!(!memoized_proof("a".to_owned(), refuse));
            let prove = || {
                walks.set(walks.get() + 1);
                true
            };
            assert!(memoized_proof("b".to_owned(), prove));
            assert!(memoized_proof("b".to_owned(), prove));
        });
        assert_eq!(walks.get(), 3);
    }

    #[test]
    fn one_evaluation_walks_each_tree_once() {
        let walks = Cell::new(0);
        let walk = || {
            walks.set(walks.get() + 1);
            true
        };
        with_walk_memo(|| {
            assert!(memoized(
                Path::new("/a"),
                &[],
                &[],
                true,
                false,
                false,
                walk
            ));
            assert!(memoized(
                Path::new("/a"),
                &[],
                &[],
                true,
                false,
                false,
                walk
            ));
            assert!(memoized(
                Path::new("/a"),
                &["x"],
                &[],
                true,
                false,
                false,
                walk
            ));
            assert!(memoized(
                Path::new("/a"),
                &[],
                &[],
                false,
                false,
                false,
                walk
            ));
            assert!(memoized(Path::new("/a"), &[], &[], true, true, false, walk));
            assert!(memoized(Path::new("/a"), &[], &[], true, false, true, walk));
        });
        assert_eq!(walks.get(), 5);
        with_walk_memo(|| {
            assert!(memoized(
                Path::new("/a"),
                &[],
                &[],
                true,
                false,
                false,
                walk
            ))
        });
        assert!(memoized(
            Path::new("/a"),
            &[],
            &[],
            true,
            false,
            false,
            walk
        ));
        assert_eq!(walks.get(), 7);
    }
}
