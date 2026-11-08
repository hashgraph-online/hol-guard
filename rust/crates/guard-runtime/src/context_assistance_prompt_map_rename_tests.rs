//! Rename notes for names a line builds on.
use super::project_tests::{project, prompt_map, ON};

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
`_get_default_module_async`; every name they build must still be defined after the rename:\n\
src/pkg/compiler.py:3: self.write(f\"_get_default_module{self.choose_async('_async')}(context)\")\n"
        ),
        "{text}"
    );
    let block = text
        .split("\n\n")
        .find(|block| block.starts_with("These lines build"));
    assert!(!block.unwrap().contains("log("), "{text}");
}
