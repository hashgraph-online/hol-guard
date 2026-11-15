//! The one test run a Claude Code note gives for a stub.
use super::super::super::tests::{files, later, looking_for};
use super::super::super::{map, Asked};
use super::first_word;
use std::path::PathBuf;

const SOURCE: &str = "class Cache:\n    def get(self, key):\n        return key\n\n\n\
class TLRUCache(Cache):\n    def popitem(self):\n        raise NotImplementedError\n";
const MIXIN: &str = "class CacheTestMixin:\n    def test_popitem(self):\n        \
self.Cache().popitem()\n";
const TLRU: &str = "from cachetools import TLRUCache\nfrom . import CacheTestMixin\n\n\n\
class TLRUCacheTest(CacheTestMixin):\n    Cache = TLRUCache\n";
const LRU: &str = "from cachetools import LRUCache\n\n\nclass LRUCacheTest:\n    pass\n";

fn note(asked: &Asked) -> String {
    let list = files(&[
        ("src/cachetools/__init__.py", SOURCE),
        ("tests/__init__.py", MIXIN),
        ("tests/test_tlru.py", TLRU),
        ("tests/test_lru.py", LRU),
    ]);
    let terms = looking_for(&[("tlrucache", true, 2), ("popitem", true, 2)]);
    map(&list, &terms, asked, later()).unwrap().text
}

fn claude() -> Asked {
    Asked {
        reads_first: true,
        root: PathBuf::from("/work/cachetools"),
        ..Asked::default()
    }
}

/// The stub's tests sit in a base class; the file the runner collects is
/// the one named after the stub's class, and only that one is run.
#[test]
fn a_stub_on_claude_code_names_its_test_file_once() {
    let text = note(&claude());
    assert!(
        text.contains(
            "Tests:\nAfter the edit, run `cd '/work/cachetools' && python -m pytest -q \
tests/test_tlru.py` once to check it."
        ),
        "{text}"
    );
}

/// Other harnesses, and a root a shell would split, get no command.
#[test]
fn no_command_off_claude_code_or_for_an_odd_root() {
    let codex = Asked {
        reads_first: false,
        ..claude()
    };
    let quoted = Asked {
        root: PathBuf::from("/work/it's"),
        ..claude()
    };
    for asked in [codex, quoted] {
        let text = note(&asked);
        assert!(!text.contains("python -m pytest"), "{text}");
    }
}

#[test]
fn first_words_split_camel_case_and_underscores() {
    assert_eq!(first_word("TLRUCache"), Some("TLRU"));
    assert_eq!(first_word("SortedSet"), Some("Sorted"));
    assert_eq!(first_word("rr_cache"), Some("rr"));
    assert_eq!(first_word("popitem"), None);
}
