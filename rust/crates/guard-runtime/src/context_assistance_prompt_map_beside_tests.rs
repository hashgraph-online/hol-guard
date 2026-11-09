//! The definitions beside a function left to be written.
use super::project_tests::{project, prompt_map, ON};
use super::tests::{files, later, looking_for};
use super::{map, Asked};

const TRACE: &str = "\"\"\"Tracebacks.\"\"\"
import sys


class Frames(object):
    def __init__(self, frames):
        self.frames = frames

    @classmethod
    def from_traceback(cls, tb, limit=None):
        return cls([tb])

    def __str__(self):
        return 'Traceback'


def format_only(etype, value):
    return ['%s: %s' % (etype.__name__, value)]


def print_it(etype, value, tb, file=None):
    \"\"\"Print the traceback, then the exception.\"\"\"
    raise NotImplementedError


def install():
    sys.excepthook = print_it
";

const BAG: &str = "class Bag(dict):
    def __init__(self):
        self._map = {}

    def getlist(self, key):
        return list(self._map[key])

    def todict(self, multi=False):
        \"\"\"Return a plain dict.\"\"\"
        raise NotImplementedError


def helper():
    return Bag()
";

/// Writing a function again, the agent learns which helpers the file holds
/// from the first line of each definition beside it, with its lines, and a
/// class's members; it then opens just the ones it calls. A prompt about a
/// function that is already written gets no such list.
#[test]
fn a_function_left_to_be_written_comes_with_the_definitions_beside_it() {
    let (home, _project, root) = project(ON, &[("src/pkg/trace.py", TRACE)]);
    let prompt = "Tests fail because print_it is not implemented (src/pkg/trace.py). Write the \
implementation; the docstring and tests describe the expected behavior.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "\n\nOther definitions in src/pkg/trace.py:\n5-14 class Frames(object):\n  members: \
__init__ 6-7, from_traceback 9-11, __str__ 13-14\n17-18 def format_only(etype, value):\n```\n\
def format_only(etype, value):\n    return ['%s: %s' % (etype.__name__, value)]\n```\n\
26-27 def install():\n```\ndef install():\n    sys.excepthook = print_it\n```"
        ),
        "{text}"
    );
    let prompt = "Add a short usage example to the docstring of `format_only` in \
src/pkg/trace.py, written as a doctest.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(!text.contains("Other definitions in"), "{text}");
}

/// A method left to be written gets the other members of its class, not the
/// file's top-level functions.
#[test]
fn a_method_left_to_be_written_comes_with_its_classs_members() {
    let (home, _project, root) = project(ON, &[("src/pkg/bag.py", BAG)]);
    let prompt = "Tests fail because Bag.todict is not implemented (src/pkg/bag.py). Write the \
implementation; the docstring and tests describe the expected behavior.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "\n\nOther members of Bag in src/pkg/bag.py:\n2-3 def __init__(self):\n```\n\
    def __init__(self):\n        self._map = {}\n```\n5-6 def getlist(self, key):\n```\n\
    def getlist(self, key):\n        return list(self._map[key])\n```"
        ),
        "{text}"
    );
    assert!(!text.contains("def helper"), "{text}");
}

const TWO: &str = "def first_stub(x):
    \"\"\"Return x.\"\"\"
    raise NotImplementedError


def helper(x):
    return second_stub(x)


def second_stub(x):
    \"\"\"Return x twice.\"\"\"
    raise NotImplementedError
";

/// Only the first line of each definition beside a stub is shown, so only
/// those lines count as shown later in the session: writing the next stub,
/// the agent still gets the line in a listed function's body that calls it.
#[test]
fn listing_a_definition_beside_a_stub_does_not_hide_its_body() {
    let list = files(&[("src/pkg/two.py", TWO)]);
    let first = map(
        &list,
        &looking_for(&[("firststub", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap();
    assert!(
        first.text.contains("\n6-7 def helper(x):"),
        "{}",
        first.text
    );
    // The stub shown whole, and one span for the whole list.
    assert_eq!(first.shown.len(), 2, "{:?}", first.shown);
    let again = Asked {
        earlier: first.shown.clone(),
        ..Asked::default()
    };
    let next = map(
        &list,
        &looking_for(&[("secondstub", true, 1)]),
        &again,
        later(),
    )
    .unwrap()
    .text;
    assert!(next.contains("return second_stub(x)"), "{next}");
}

const DECORATED: &str = "@second_stub
def helper(x):
    return x


def first_stub(x):
    \"\"\"Return x.\"\"\"
    raise NotImplementedError


def second_stub(f):
    \"\"\"Return f.\"\"\"
    raise NotImplementedError
";

/// A listed definition's code shown beside one stub does not count as shown
/// for the next: a decorator naming the next stub is still listed for it.
#[test]
fn listing_a_decorated_definition_does_not_hide_its_decorator() {
    let list = files(&[("src/pkg/deco.py", DECORATED)]);
    let first = map(
        &list,
        &looking_for(&[("firststub", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap();
    assert!(
        first
            .text
            .contains("1-3 def helper(x):\n```\n@second_stub\ndef helper(x):"),
        "{}",
        first.text
    );
    let again = Asked {
        earlier: first.shown.clone(),
        ..Asked::default()
    };
    let next = map(
        &list,
        &looking_for(&[("secondstub", true, 1)]),
        &again,
        later(),
    )
    .unwrap()
    .text;
    assert!(next.contains("@second_stub"), "{next}");
}

const CACHE: &str = "class Cache(object):
    def __init__(self, capacity):
        self.capacity = capacity
        self._mapping = {}

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def setdefault(self, key, default=None):
        \"\"\"Set default if the key is not in the cache.\"\"\"
        raise NotImplementedError

    def __getitem__(self, key):
        return self._mapping[key]
";

/// Writing a method again, the agent reads how its neighbors use the class's
/// state before it writes. The nearest short ones come with their code, so
/// it can write the body without opening the class; one too long for what is
/// left of the room is still listed by its lines.
#[test]
fn a_stub_comes_with_the_code_of_its_nearest_neighbors() {
    let long: String = (0..70)
        .map(|n| format!("        self._mapping[{n}] = {n}\n"))
        .collect();
    let text = format!("{CACHE}\n    def fill(self):\n{long}");
    let list = files(&[("src/pkg/cache.py", &text)]);
    let mapped = map(
        &list,
        &looking_for(&[("setdefault", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap()
    .text;
    for code in [
        "```\n    def get(self, key, default=None):\n        try:\n            return self[key]",
        "```\n    def __getitem__(self, key):\n        return self._mapping[key]\n```",
        "```\n    def __init__(self, capacity):\n        self.capacity = capacity",
    ] {
        assert!(mapped.contains(code), "{code} in {mapped}");
    }
    assert!(mapped.contains("\n19-89 def fill(self):"), "{mapped}");
    assert!(!mapped.contains("self._mapping[7] = 7"), "{mapped}");
}
