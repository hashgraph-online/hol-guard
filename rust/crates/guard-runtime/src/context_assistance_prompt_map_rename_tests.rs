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
