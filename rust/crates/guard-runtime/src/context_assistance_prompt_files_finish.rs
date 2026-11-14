//! What the walk counted, put together once it stops, and the whole-word
//! test behind its count of the files holding a name exactly.
use super::{ranked, scores, Seen, Walk};

/// The walk's result from the files it saw, what it checked, and per term
/// the files holding it with `_` and `-` dropped, per exact name the files
/// holding it as a word, kept only when it read every file, and whether it
/// did.
pub(super) fn finish(
    seen: Vec<Seen>,
    checked: usize,
    terms: &[String],
    phrases: &[String],
    (spelled, exact, complete): (Vec<usize>, Vec<(String, usize)>, bool),
) -> Walk {
    let (phrases, exact) = (phrases.len(), if complete { exact } else { Vec::new() });
    let holding = (0..terms.len())
        .map(|i| {
            seen.iter()
                .filter(|s| s.in_path[i] || s.hits[i] > 0)
                .count()
        })
        .collect();
    let words = (0..terms.len())
        .map(|i| seen.iter().filter(|s| s.whole[i]).count())
        .collect();
    let quoting = (0..phrases)
        .map(|i| seen.iter().filter(|s| s.quoted[i]).count())
        .collect();
    let (files, tests) = ranked(scores(seen, checked, terms.len(), phrases));
    Walk {
        files,
        tests,
        checked,
        holding,
        quoting,
        words,
        spelled,
        complete,
        exact,
    }
}

/// Whether `text` holds `word` as a rename's list reads a word: `-` and `_`
/// join, so neither `lru_cache` nor `x-cache` holds `cache` or `_cache`.
pub(super) fn holds_word(text: &str, word: &str) -> bool {
    let joins = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '-'));
    !word.is_empty()
        && (text.match_indices(word)).any(|(at, _)| {
            let label = word.starts_with('_') && link_label(&text[..at]);
            !(label
                || joins(text[..at].chars().next_back())
                || joins(text[at + word.len()..].chars().next()))
        })
}

/// Whether a name starting with `_` right after `before` opens a
/// reStructuredText link target, `.. _cache algorithm:`, where the `_` is
/// markup and the label is `cache algorithm`, not the name `_cache`.
fn link_label(before: &str) -> bool {
    before
        .rsplit('\n')
        .next()
        .is_some_and(|line| line.trim() == "..")
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_word_joined_by_an_underscore_or_dash_is_another_word() {
        let holds = |text: &str| super::holds_word(text, "_cache");
        assert!(holds("self._cache = {}") && holds("_cache"));
        assert!(!holds("@lru_cache") && !holds("x-_cache") && !holds("_cache_size"));
        assert!(!super::holds_word("anything", ""));
        assert!(!holds(".. _cache algorithm: https://example.org") && holds("x\n.. f(_cache)"));
    }

    /// The count reads each file as written, as the rename list does, so
    /// `_CACHE` is not `_cache`, and a name the prompt repeats counts once.
    #[test]
    fn the_walk_counts_files_holding_a_name_as_written() {
        let dir = tempfile::tempdir().unwrap();
        let root = super::super::plain(std::fs::canonicalize(dir.path()).unwrap());
        let files = [
            ("store.py", "self._cache = {}\n"),
            ("consts.py", "_CACHE = 1\n"),
            ("util.py", "from functools import lru_cache\n"),
        ];
        for (name, text) in files {
            std::fs::write(root.join(name), text).unwrap();
        }
        let (terms, name) = (["cache".to_owned()], "_cache".to_owned());
        let budget = std::time::Duration::from_secs(5);
        let exact = [name.clone(), name.clone()];
        let walk = super::super::walk_exact(&root, &terms, &[], &[], &exact, budget);
        assert!(walk.complete);
        assert_eq!(walk.exact, [(name, 1)]);
        assert_eq!(walk.spelled, [3]);
    }
}
