//! Rename notes for names a line builds on.
use super::project_tests::{project, prompt_map, ON};

const ENVIRONMENT: &str = "class Template:
    def _get_default_module(self, ctx=None):
        return self.module

    async def _get_default_module_async(self, ctx=None):
        return self.module
";

/// A line writing the old name in a string with more after it builds a
/// longer name from it: `f"_get_default_module{choose_async('_async')}"`
/// also calls `_get_default_module_async`, so renaming only the first breaks
/// the async path. The note names that line and the longer name; a string
/// merely holding the name builds nothing.
#[test]
fn a_rename_names_the_lines_building_a_longer_name_from_it() {
    let environment = "class Template:
    def _get_default_module(self, ctx=None):
        log(\"_get_default_module called\")
        return self.module

    async def _get_default_module_async(self, ctx=None):
        return self.module

    def module(self):
        return self._get_default_module()
";
    let compiler = "class CodeGenerator:
    def visit_Import(self, node):
        self.write(f\"_get_default_module{self.choose_async('_async')}(context)\")
";
    let list = [
        ("src/pkg/environment.py", environment),
        ("src/pkg/compiler.py", compiler),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the internal method `_get_default_module` to `_get_default_module_impl` \
everywhere in the project, including tests. Behavior must not change.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "\n\nThese lines build a longer name from `_get_default_module`, such as \
`_get_default_module_async`; with `_get_default_module_impl` written in place of \
`_get_default_module`, they would build `_get_default_module_impl_async` instead. Every name they \
build must still be defined after the rename:\n\
src/pkg/compiler.py:3:        self.write(f\"_get_default_module{self.choose_async('_async')}(context)\")\n"
        ),
        "{text}"
    );
    let block = text
        .split("\n\n")
        .find(|block| block.starts_with("These lines build"));
    assert!(!block.unwrap().contains("log("), "{text}");
}

/// The new name is the one the prompt renames the old name to, not the next
/// name it writes: the old name written twice, or a name to update beside
/// it, is no new name.
#[test]
fn a_rename_takes_the_new_name_from_the_words_saying_so() {
    let compiler = "class CodeGenerator:
    def visit_Import(self, node):
        self.write(f\"_get_default_module{self.choose_async('_async')}(context)\")
";
    let list = [
        ("src/pkg/environment.py", ENVIRONMENT),
        ("src/pkg/compiler.py", compiler),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "`_get_default_module` is a confusing name. Rename `_get_default_module` to \
`_get_default_module_impl` everywhere in the project.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains("they would build `_get_default_module_impl_async` instead"),
        "{text}"
    );
    let prompt = "Rename `_get_default_module` everywhere in the project and update \
`test_compiler` to match.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("These lines build a longer name"), "{text}");
    assert!(!text.contains("they would build"), "{text}");
}

/// The ending a building line adds comes from that line: a longer name
/// another file holds is no ending the line writes.
#[test]
fn a_building_line_names_only_an_ending_it_writes() {
    let loader = "def load(self, which):
    return getattr(self, \"_get_default_module\" + which)()
";
    let list = [
        ("src/pkg/environment.py", ENVIRONMENT),
        ("src/pkg/loader.py", loader),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the internal method `_get_default_module` to `_get_default_module_impl` \
everywhere in the project, including tests.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "These lines build a longer name from `_get_default_module`, such as \
`_get_default_module_async`. Every name they build"
        ),
        "{text}"
    );
}

/// Each line naming the old name keeps its indentation, as a search prints
/// it, so the agent can write the renamed lines at the right depth without
/// searching again first.
#[test]
fn a_rename_lists_each_line_at_its_indentation() {
    let cache = "class Cache:
    def _evict(self):
        self.items.clear()

    def put(self, key, value):
        if len(self.items) > 8:
            self._evict()
        self.items[key] = value
";
    let list = [
        ("src/pkg/cache.py", cache),
        (
            "tests/test_cache.py",
            "def test_evict():\n    Cache()._evict()\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the private method `_evict` to `_evict_all` everywhere in the project.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "\n\nEvery line naming `_evict`; no other project file holds it:\n\
src/pkg/cache.py:2:    def _evict(self):\n\
src/pkg/cache.py:7:            self._evict()\n\
tests/test_cache.py:2:    Cache()._evict()\n"
        ),
        "{text}"
    );
}

/// A rename the list covers whole opens with the one command making it:
/// every whole-word use rewritten in each file holding it, then the test
/// files among them run. An agent given it ran it instead of opening and
/// editing each file in turn.
#[cfg(not(windows))]
#[test]
fn a_whole_rename_opens_with_the_command_making_it() {
    let cache = "class Cache:
    def _evict(self):
        self.items.clear()

    def put(self, key, value):
        if len(self.items) > 8:
            self._evict()
        self._evict_later = None
";
    let list = [
        ("src/pkg/cache.py", cache),
        (
            "tests/test_cache.py",
            "def test_evict():\n    Cache()._evict()\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the private method `_evict` to `_evict_all` everywhere in the project.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    let first = text.split("\n\n").nth(1).unwrap();
    // From the project root, since the session may have started below it.
    assert_eq!(
        first,
        format!(
            "One command makes this whole rename: it writes `_evict_all` in place of every \
`_evict` written as a whole word, in each file holding it, then runs the tests named in it. Run \
it instead of opening and editing each file, then check its output:\n\
cd '{}' && perl -pi -e 's/(?<![\\w-])_evict(?![\\w-])/_evict_all/g' src/pkg/cache.py \
tests/test_cache.py && python -m pytest -q tests/test_cache.py",
            root.display()
        ),
        "{text}"
    );
    assert!(text.contains("Every line naming `_evict`; no other project file holds it:"));
}

/// With no test naming the old name, the command runs the tests the map
/// lists for the definitions using it.
#[cfg(not(windows))]
#[test]
fn a_rename_no_test_names_runs_the_tests_of_its_callers() {
    let maths = "def _sumprod(a, b):
    return sum(x * y for x, y in zip(a, b))


def dot(a, b):
    return _sumprod(a, b)
";
    let list = [
        ("src/pkg/maths.py", maths),
        (
            "tests/test_maths.py",
            "from pkg.maths import dot\n\n\ndef test_dot():\n    assert dot([1], [2]) == 2\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the internal helper `_sumprod` to `_sumprod_impl` everywhere in the \
project, including tests.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "perl -pi -e 's/(?<![\\w-])_sumprod(?![\\w-])/_sumprod_impl/g' src/pkg/maths.py \
&& python -m pytest -q tests/test_maths.py\n"
        ),
        "{text}"
    );
}

/// No command where one replacement would be wrong or unsafe to run: a
/// line building a longer name from the old one, or a path a shell would
/// split.
#[test]
fn a_rename_gives_no_command_where_one_replacement_is_wrong() {
    let compiler = "class CodeGenerator:
    def visit_Import(self, node):
        self.write(f\"_get_default_module{self.choose_async('_async')}(context)\")
";
    let list = [
        ("src/pkg/environment.py", ENVIRONMENT),
        ("src/pkg/compiler.py", compiler),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the internal method `_get_default_module` to `_get_default_module_impl` \
everywhere in the project, including tests.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(!text.contains("One command makes"), "{text}");
    let list = [(
        "src/my pkg/cache.py",
        "def _evict():\n    pass\n\n\n_evict()\n",
    )];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the private function `_evict` to `_evict_all` everywhere in the project.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("Every line naming `_evict`"), "{text}");
    assert!(!text.contains("One command makes"), "{text}");
}

/// No command where `perl` would change a line the list does not name, or
/// one it should not: a changelog's released entry, a name touching a letter
/// past ASCII, which `perl` reads as a break, or a name a string part before
/// it builds into a longer one.
#[cfg(not(windows))]
#[test]
fn a_rename_gives_no_command_where_perl_reads_the_name_apart() {
    let cache = "class Cache:\n    def _evict(self):\n        pass\n\n    def put(self):\n        self._evict()\n";
    let prompt = "Rename the private method `_evict` to `_evict_all` everywhere in the project.";
    for (path, text) in [
        (
            "CHANGES.md",
            "# Changes\n\n## 1.2.0\n\n- Fixed a leak in `_evict`.\n",
        ),
        ("src/pkg/greek.py", "_evict\u{3c0} = 1\n_evict()\n"),
        (
            "src/pkg/hooks.py",
            "def run(self, prefix):\n    getattr(self, f\"{prefix}_evict\")()\n",
        ),
        (
            "src/pkg/joined.py",
            "def run(self, prefix):\n    getattr(self, prefix + \"_evict\")()\n",
        ),
    ] {
        let list = [("src/pkg/cache.py", cache), (path, text)];
        let (home, _project, root) = project(ON, &list);
        let text = prompt_map(home.path(), &root, prompt).unwrap();
        assert!(
            text.contains("Every line naming `_evict`"),
            "{path}: {text}"
        );
        assert!(!text.contains("One command makes"), "{path}: {text}");
    }
}

/// A helper beside the tests is not a test file: the command does not run
/// pytest on `tests/support.py`, which collects no tests.
#[cfg(not(windows))]
#[test]
fn a_rename_command_runs_no_helper_beside_the_tests() {
    let cache = "class Cache:\n    def _evict(self):\n        pass\n\n    def clear(self):\n        self._evict()\n";
    let list = [
        ("src/pkg/cache.py", cache),
        (
            "tests/support.py",
            "from pkg.cache import Cache\n\n\ndef emptied():\n    return Cache()._evict()\n",
        ),
        (
            "tests/test_cache.py",
            "from pkg.cache import Cache\n\n\ndef test_clear():\n    Cache().clear()\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the private method `_evict` to `_evict_all` everywhere in the project.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("One command makes"), "{text}");
    assert!(!text.contains("pytest -q tests/support.py"), "{text}");
}

/// Renaming `_cache` in a project where many more files say `lru_cache`:
/// the walk counts the files holding `_cache` as a word, so the note says
/// its list is every line naming it, though it read only some of the files
/// holding `cache`, and gives the one command making the rename.
#[test]
fn a_rename_list_is_whole_when_only_longer_names_are_left_unread() {
    let store = "class Store:\n    def __init__(self):\n        self._cache = {}\n\n    def get(self, key):\n        return self._cache.get(key)\n";
    let users: Vec<(String, String)> = (0..40)
        .map(|i| {
            let text = format!("from functools import lru_cache\n\n\n@lru_cache\ndef load_{i}():\n    return {i}\n");
            (format!("src/users/user_{i}.py"), text)
        })
        .collect();
    let mut list = vec![("src/store.py", store)];
    list.extend(
        users
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    );
    let (home, _project, root) = project(ON, &list);
    let text = prompt_map(
        home.path(),
        &root,
        "Rename `_cache` to `_entries` in Store.",
    )
    .unwrap();
    assert!(
        text.contains(
            "Every line naming `_cache`; no other project file holds it:\n\
             src/store.py:3:        self._cache = {}\nsrc/store.py:6:        return self._cache.get(key)"
        ),
        "{text}"
    );
    assert!(text.contains("perl -pi -e"), "{text}");
}

/// In reStructuredText `.. _cache algorithm:` opens a link labelled
/// `cache algorithm`; its `_` is markup. Renaming `_cache` leaves the label
/// alone: the note neither lists it nor counts its file, and is still whole.
#[test]
fn a_rename_leaves_a_link_label_alone() {
    let source = "def _cache(size):\n    return {}\n\n\ndef lru(size):\n    return _cache(size)\n";
    let readme = "Caches\n======\n\nSee the `cache algorithm`_.\n\n.. _cache algorithm: https://example.org/cache\n";
    let (home, _project, root) = project(ON, &[("src/func.py", source), ("README.rst", readme)]);
    let text = prompt_map(
        home.path(),
        &root,
        "Rename `_cache` to `_cache_impl` in func.py.",
    )
    .unwrap();
    assert!(
        text.contains(
            "Every line naming `_cache`; no other project file holds it:\n\
             src/func.py:1:def _cache(size):\nsrc/func.py:6:    return _cache(size)"
        ),
        "{text}"
    );
    assert!(!text.contains("README.rst:6"), "{text}");
    assert!(
        text.contains("perl -pi -e") && !text.contains("README.rst "),
        "{text}"
    );
    // Renaming `cache`, the label's `_cache` is a longer word, not the name.
    let source = "def cache(size):\n    return {}\n";
    let readme = readme.replace("org/cache", "org/algorithms");
    let files = [("src/func.py", source), ("README.rst", readme.as_str())];
    let (home, _project, root) = project(ON, &files);
    let prompt = "Rename `cache` to `cache_store` in func.py.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    let listed = text.split("Every line naming").nth(1).unwrap_or_default();
    let listed = listed.split("\n\n").next().unwrap_or_default();
    assert!(listed.contains("README.rst:4:"), "{text}");
    assert!(!listed.contains("README.rst:6:"), "{text}");
}
