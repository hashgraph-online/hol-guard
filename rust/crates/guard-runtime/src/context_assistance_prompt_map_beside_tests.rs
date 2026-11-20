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
/// file's top-level functions, and the code of those the note does not
/// already show.
#[test]
fn a_method_left_to_be_written_comes_with_its_classs_members() {
    let (home, _project, root) = project(ON, &[("src/pkg/bag.py", BAG)]);
    let prompt = "Tests fail because Bag.todict is not implemented (src/pkg/bag.py). Write the \
implementation; the docstring and tests describe the expected behavior.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "\n\nOther members of Bag in src/pkg/bag.py:\n2-3 def __init__(self):\n\
5-6 def getlist(self, key):\n```\n    def getlist(self, key):\n        \
return list(self._map[key])\n```"
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
/// the agent still gets the line in a listed function's body that calls it,
/// once.
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
    // Once: in the helper's code, not again in the lines naming the stub.
    assert_eq!(next.matches("return second_stub(x)").count(), 1, "{next}");
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
    assert_eq!(next.matches("@second_stub").count(), 1, "{next}");
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

/// A line calling the stub inside a neighbor's code is left out of the stub's
/// list because the code beside it shows that line. When the map has no room
/// left for that block, the list keeps the line, so it is not lost.
#[test]
fn a_line_left_to_the_code_beside_a_stub_is_listed_when_that_code_does_not_fit() {
    let path = format!("src/{}cache.py", "deep/".repeat(359));
    let text =
        format!("{CACHE}\n    def ensure(self, key):\n        return self.setdefault(key, None)\n");
    let mapped = map(
        &files(&[(&path, &text)]),
        &looking_for(&[("setdefault", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap()
    .text;
    assert!(!mapped.contains("Other members of Cache"), "{mapped}");
    assert!(
        mapped.contains("return self.setdefault(key, None)"),
        "{mapped}"
    );
}

/// A unittest class that inherits its tests from a mixin names the code they
/// run only in its own body, so that class is the test for a stub it names,
/// listed by the name a runner selects it with.
#[test]
fn a_test_class_inheriting_its_tests_is_listed_for_the_name_its_body_uses() {
    let func = "def lru_cache(maxsize=128):\n    return 1\n\n\n\
def mru_cache(maxsize=128):\n    raise NotImplementedError\n";
    let tests = [
        "import unittest\n\n",
        "class DecoratorTestMixin:",
        "    def test_decorator(self):",
        "        self.assertEqual(self.DECORATOR(2), 1)\n\n",
        "class LRUDecoratorTest(unittest.TestCase, DecoratorTestMixin):",
        "    DECORATOR = staticmethod(func.lru_cache)\n\n",
        "class MRUDecoratorTest(unittest.TestCase, DecoratorTestMixin):",
        "    DECORATOR = staticmethod(func.mru_cache)\n",
    ]
    .join("\n");
    let tests = tests.as_str();
    let mapped = map(
        &files(&[("src/func.py", func), ("tests/test_func.py", tests)]),
        &looking_for(&[("mrucache", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap()
    .text;
    assert!(
        mapped.contains("Tests:\ntests/test_func.py: 1 related tests, last MRUDecoratorTest 13-14"),
        "{mapped}"
    );
}

/// A class inside a test is part of that test, not one of its own, and the
/// last related test is the last in the file whichever way it counts.
#[test]
fn a_class_inside_a_test_is_not_listed_and_the_last_test_is_last_in_the_file() {
    let func = "def mru_cache(maxsize=128):\n    raise NotImplementedError\n";
    let tests = [
        "import unittest\n\n",
        "class DecoratorTestMixin:",
        "    def test_decorator(self):",
        "        self.assertEqual(self.DECORATOR(2), 1)\n\n",
        "class MRUDecoratorTest(unittest.TestCase, DecoratorTestMixin):",
        "    DECORATOR = staticmethod(func.mru_cache)\n\n",
        "def test_factory():",
        "    class LocalTest(unittest.TestCase):",
        "        DECORATOR = staticmethod(func.mru_cache)\n\n",
        "def test_mru():",
        "    assert func.mru_cache(2)\n",
    ]
    .join("\n");
    let mapped = map(
        &files(&[
            ("src/func.py", func),
            ("tests/test_func.py", tests.as_str()),
        ]),
        &looking_for(&[("mrucache", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap()
    .text;
    assert!(
        mapped.contains("tests/test_func.py: 3 related tests, last test_mru "),
        "{mapped}"
    );
}

/// Claude Code reads a file before it edits it, so only the first named
/// definition is shown whole there; the rest go by their lines.
#[test]
fn claude_code_gets_only_the_first_named_definition_whole() {
    let plain = "def first_part(x):\n    return x + 1\n\n\ndef second_part(x):\n    return x * 2\n";
    let list = files(&[("src/pkg/two.py", plain)]);
    let terms = looking_for(&[("firstpart", true, 1), ("secondpart", true, 1)]);
    let text = |asked: &Asked| map(&list, &terms, asked, later()).unwrap().text;
    let shown = |text: &str, name: &str| text.contains(&format!("```\ndef {name}(x):"));
    let all = text(&Asked::default());
    assert!(
        shown(&all, "first_part") && shown(&all, "second_part"),
        "{all}"
    );
    let claude = Asked {
        reads_first: true,
        ..Asked::default()
    };
    let one = text(&claude);
    assert!(
        shown(&one, "first_part") != shown(&one, "second_part"),
        "{one}"
    );
}

/// A constructor stays whole in Claude Code: it holds the fields a method the
/// agent writes uses.
#[test]
fn claude_code_still_gets_a_named_constructor_whole() {
    let code = "class Box:\n    def __init__(self, size):\n        self.__size = size\n\n    \
def fill(self, x):\n        return x\n\n    def empty(self):\n        raise NotImplementedError\n";
    let list = files(&[("src/pkg/box.py", code)]);
    let terms = looking_for(&[("fill", true, 1), ("init", true, 1)]);
    let claude = Asked {
        reads_first: true,
        ..Asked::default()
    };
    let text = map(&list, &terms, &claude, later()).unwrap().text;
    assert!(
        text.contains("```\n    def __init__(self, size):"),
        "{text}"
    );
}

#[test]
fn claude_code_does_not_show_a_long_constructor_whole() {
    let doc = "        \"\"\"Long docstring line about the box.\"\"\"\n".repeat(20);
    let code = format!(
        "class Box:\n    def fill(self, x):\n        return x\n\n    \
def __init__(self, size):\n{doc}        self.__size = size\n"
    );
    let list = files(&[("src/pkg/box.py", code.as_str())]);
    let terms = looking_for(&[("fill", true, 1), ("init", true, 1)]);
    let claude = Asked {
        reads_first: true,
        ..Asked::default()
    };
    let text = map(&list, &terms, &claude, later()).unwrap().text;
    assert!(text.contains("```\n    def fill(self, x):"), "{text}");
    assert!(
        !text.contains("```\n    def __init__(self, size):"),
        "{text}"
    );
}

#[test]
fn a_decorated_short_constructor_stays_whole_in_claude_code() {
    let code = "class Box:\n    def fill(self, x):\n        return x\n\n    \
@validate\n    def __init__(self, size):\n        self.__size = size\n";
    let list = files(&[("src/pkg/box.py", code)]);
    let terms = looking_for(&[("fill", true, 1), ("init", true, 1)]);
    let claude = Asked {
        reads_first: true,
        ..Asked::default()
    };
    let text = map(&list, &terms, &claude, later()).unwrap().text;
    assert!(
        text.contains("    def __init__(self, size):\n        self.__size"),
        "{text}"
    );
}
