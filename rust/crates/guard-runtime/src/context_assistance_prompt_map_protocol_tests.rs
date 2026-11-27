//! A prompt about what a named class does reaches the special methods doing it.
use super::super::super::project_tests::{project, prompt_map, ON};

const RANGES: &str = "class numeric_range:\n    def __init__(self, *args):\n        \
self._len = 3\n\n    def __eq__(self, other):\n        return len(self) == len(other)\n\n    \
def __hash__(self):\n        return hash(len(self))\n\n    def __len__(self):\n        \
return self._len\n\n\nclass other_thing:\n    def __eq__(self, other):\n        return True\n";

fn map_of(prompt: &str) -> String {
    let (home, _project, root) = project(ON, &[("more.py", RANGES)]);
    prompt_map(home.path(), &root, prompt).unwrap_or_default()
}

#[test]
fn equality_and_hashing_of_a_named_class_place_its_special_methods() {
    let text = map_of("Fix numeric_range equality and hashing above sys.maxsize");
    assert!(text.contains("more.py:5-6 def __eq__(self, other):"), "{text}");
    assert!(text.contains("more.py:8-9 def __hash__(self):"), "{text}");
    // Only the named class's methods: `other_thing` has an `__eq__` too.
    assert!(!text.contains("more.py:17-18"), "{text}");
}

#[test]
fn a_protocol_word_without_a_named_class_places_no_special_method() {
    let text = map_of("Fix equality and hashing for large ranges");
    assert!(!text.contains("def __eq__"), "{text}");
    assert!(!text.contains("def __hash__"), "{text}");
}
