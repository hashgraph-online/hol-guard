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
__init__ 6-7, from_traceback 9-11, __str__ 13-14\n17-18 def format_only(etype, value):\n\
26-27 def install():"
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
            "\n\nOther members of Bag in src/pkg/bag.py:\n2-3 def __init__(self):\n\
5-6 def getlist(self, key):"
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
