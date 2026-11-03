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

thread_local! {
    static MEMO: RefCell<Memo> = const { RefCell::new(None) };
}

pub(in crate::pretool) fn with_walk_memo<T>(evaluate: impl FnOnce() -> T) -> T {
    struct Restore(Memo);
    impl Drop for Restore {
        fn drop(&mut self) {
            MEMO.with(|memo| *memo.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(MEMO.with(|memo| memo.replace(Some(Vec::new()))));
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

#[cfg(test)]
mod tests {
    use super::{memoized, with_walk_memo};
    use std::cell::Cell;
    use std::path::Path;

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
