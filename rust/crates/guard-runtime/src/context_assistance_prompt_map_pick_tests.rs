//! A prompt whose words are placed nowhere maps by the outline of the one
//! source file named for one of them.
use super::super::project_tests::{project, prompt_map, ON};

const ROUTE: &str =
    "package mux\n\n// Route stores information to match a request.\ntype Route struct {\n\
\tname string\n\tregexp routeRegexpGroup\n}\n\nfunc (r *Route) Name(name string) *Route {\n\
\tr.name = name\n\treturn r\n}\n\nfunc (r *Route) GetName() string {\n\treturn r.name\n}\n";

/// Ten more files that say `route`, so the word places nothing.
fn routing_files() -> Vec<(String, String)> {
    (0..10)
        .map(|at| {
            let text = format!(
                "package mux\n\nfunc helper{at}(r *Route) *Route {{\n\treturn r // route\n}}\n"
            );
            (format!("part{at}.go"), text)
        })
        .collect()
}

fn map_of(extra: &[(&str, &str)], prompt: &str) -> String {
    let files = routing_files();
    let mut list: Vec<(&str, &str)> = (files.iter())
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    list.extend_from_slice(extra);
    let (home, _project, root) = project(ON, &list);
    prompt_map(home.path(), &root, prompt).unwrap_or_default()
}

#[test]
fn a_common_word_naming_one_source_file_maps_its_outline() {
    let prompt = "Feature route metadata\n\nAdded metadata to route, as proposed in the issue.";
    let text = map_of(
        &[("route.go", ROUTE), ("route_test.go", "package mux\n")],
        prompt,
    );
    assert!(text.contains("route.go:4-7 type Route struct {"), "{text}");
    assert!(
        text.contains("route.go:14-16 func (r *Route) GetName() string {"),
        "{text}"
    );
    // Two files named for the word: neither is the one the prompt means.
    let both = map_of(&[("route.go", ROUTE), ("v2/route.go", ROUTE)], prompt);
    assert!(!both.contains("type Route struct"), "{both}");
    // Only the last extension is dropped: `route.pb.go` is not `route.go`.
    let generated = map_of(&[("route.go", ROUTE), ("route.pb.go", ROUTE)], prompt);
    assert!(
        generated.contains("route.go:4-7 type Route struct {"),
        "{generated}"
    );
    // A generic file name is no subject: `main` names nothing.
    let main = map_of(
        &[("main.go", ROUTE)],
        "Feature main metadata for the route.",
    );
    assert!(!main.contains("type Route struct"), "{main}");
}

/// The short type the outlined file is named for, `Route` in `route.go`, is
/// what such a request changes: it comes whole, fields and all, while its
/// methods stay one line each.
#[test]
fn the_short_type_an_outlined_file_is_named_for_is_shown_whole() {
    let prompt = "Feature route metadata\n\nAdded metadata to route, as proposed in the issue.";
    let text = map_of(&[("route.go", ROUTE)], prompt);
    assert!(text.contains("\tregexp routeRegexpGroup\n}\n```"), "{text}");
    assert!(!text.contains("\treturn r.name"), "{text}");
}

/// A Go method is named after its receiver, so a prompt naming it maps to it.
#[test]
fn a_go_method_is_named_past_its_receiver() {
    use super::super::super::sections::written_name;
    assert_eq!(
        written_name("func (r *Route) GetName() string {").as_deref(),
        Some("GetName")
    );
    assert_eq!(
        written_name("func (Route) Kind() int {").as_deref(),
        Some("Kind")
    );
    assert_eq!(
        written_name("func (l *List[T]) Push(v T) {").as_deref(),
        Some("Push")
    );
    assert_eq!(written_name("func New() *Router {").as_deref(), Some("New"));
    let text = map_of(
        &[("route.go", ROUTE)],
        "Make `GetName` return the empty name for a route built without one.",
    );
    assert!(
        text.contains("route.go:14-16 func (r *Route) GetName() string {"),
        "{text}"
    );
}

/// A common word no file is named for still places nothing.
#[test]
fn a_common_word_no_file_is_named_for_places_nothing() {
    use super::super::tests::{files, later, looking_for};
    use super::super::{map, Asked, MAX_PLAIN_FILES};
    let uses = "def read():\n    token = 1\n    return token\n";
    let common = looking_for(&[("token", false, MAX_PLAIN_FILES + 1)]);
    let named = files(&[
        ("src/read.py", uses),
        ("src/token.py", "class Token:\n    pass\n"),
    ]);
    let text = map(&named, &common, &Asked::default(), later())
        .unwrap()
        .text;
    assert!(text.contains("src/token.py:1-2 class Token:"), "{text}");
    assert!(!text.contains("src/read.py"), "{text}");
    let unnamed = files(&[
        ("src/read.py", uses),
        ("src/lexer.py", "class Token:\n    pass\n"),
    ]);
    assert!(map(&unnamed, &common, &Asked::default(), later()).is_none());
}

/// A bug report with no code name, whose words appear in no line of code,
/// maps by the file named for one of them: "encoding" is `encoding.ts`, though
/// only import paths spell it.
#[test]
fn a_rare_word_naming_one_source_file_maps_its_outline() {
    let encoding = "const SPACE_RE = / /g;\n\nexport function encode(text: string): string {\n  \
return encodeURI(text);\n}\n\nexport function encodePath(text: string): string {\n  \
return encode(text).replace(SPACE_RE, \"%20\");\n}\n";
    let utils =
        "import { encodePath } from \"./encoding\";\n\nexport function withBase(input: string, \
base: string): string {\n  return encodePath(base + input);\n}\n";
    let files = [
        ("src/encoding.ts", encoding),
        ("src/utils.ts", utils),
        ("src/utility.ts", utils),
    ];
    let (home, _project, root) = project(ON, &files);
    let prompt = "Encoding a path with spaces gives %2520 instead of %20";
    let text = prompt_map(home.path(), &root, prompt).unwrap_or_default();
    assert!(
        text.contains("src/encoding.ts:7-9 export function encodePath(text: string): string {"),
        "{text}"
    );
    // A word no file is named for still places nothing.
    let other = prompt_map(home.path(), &root, "Decoding a path with spaces is wrong");
    assert!(other.is_none_or(|text| !text.contains("src/encoding.ts")));
    // A grab-bag file is never the topic, even when the report names it.
    let generic = prompt_map(home.path(), &root, "Utils behaves incorrectly on Windows");
    assert!(generic.is_none_or(|text| !text.contains("src/utils.ts:")));
    let generic = prompt_map(
        home.path(),
        &root,
        "Utilities behave incorrectly on Windows",
    );
    assert!(generic.is_none_or(|text| !text.contains("src/utility.ts:")));
}

#[test]
fn a_module_constant_the_prompt_names_is_placed() {
    let parser = "import sys\nfrom typing import Final\n\n# Nesting limit.\n\
MAX_INLINE_NESTING: Final = sys.getrecursionlimit()\n\nMAX_KEY_PARTS: Final = 100\n\n\
def parse_inline_table(src, pos, nest_lvl):\n    if nest_lvl > MAX_INLINE_NESTING:\n        \
raise RecursionError\n    return pos\n";
    let (home, _project, root) = project(ON, &[("src/tomli/_parser.py", parser)]);
    let prompt = "Set smaller MAX_INLINE_NESTING to avoid worker thread crash";
    let text = prompt_map(home.path(), &root, prompt).unwrap_or_default();
    assert!(text.contains("src/tomli/_parser.py:5"), "{text}");
    assert!(
        text.contains("MAX_INLINE_NESTING: Final = sys.getrecursionlimit()"),
        "{text}"
    );
}

/// Methods the prompt calls by name, with no class named, come from the
/// class that holds them all: `update()` beside `add()` is the list's
/// `update`, not the dict's that sorts before it.
#[test]
fn called_methods_come_from_the_class_holding_them_all() {
    let dict = "class SortedDict(dict):\n    def update(self, *args):\n        return dict.update(self, *args)\n";
    let list = "class SortedList:\n    def add(self, value):\n        self._items.append(value)\n\n    def update(self, iterable):\n        self._items.extend(sorted(iterable))\n";
    let (home, _project, root) = project(
        ON,
        &[("pkg/sorteddict.py", dict), ("pkg/sortedlist.py", list)],
    );
    let prompt = "Fix update() ordering to be more consistent with add() ordering";
    let text = prompt_map(home.path(), &root, prompt).unwrap_or_default();
    assert!(text.contains("pkg/sortedlist.py:5-6 def update"), "{text}");
    assert!(!text.contains("pkg/sorteddict.py"), "{text}");
}

/// A fix to a method usually has to be made again where another class in the
/// same file overrides it, so that override's first line is listed too,
/// without its code.
#[test]
fn a_named_method_points_at_its_override_in_the_same_file() {
    let list = "class SortedList:\n    def add(self, value):\n        self._items.append(value)\n\n    def update(self, iterable):\n        self._items.extend(sorted(iterable))\n\n\nclass SortedKeyList(SortedList):\n    def update(self, iterable):\n        self._items.extend(sorted(iterable, key=self._key))\n";
    let (home, _project, root) = project(ON, &[("pkg/sortedlist.py", list)]);
    let prompt = "Fix update() ordering to be more consistent with add() ordering";
    let text = prompt_map(home.path(), &root, prompt).unwrap_or_default();
    assert!(text.contains("pkg/sortedlist.py:5-6 def update"), "{text}");
    let first = text
        .find("pkg/sortedlist.py:5-6 def update")
        .unwrap_or(usize::MAX);
    let other = text.find("pkg/sortedlist.py:10-11 def update").unwrap_or(0);
    assert!(
        first < other,
        "the override follows the method it overrides: {text}"
    );
    assert!(!text[first..other].contains("def add"), "{text}");
    let after = &text[other..];
    assert!(
        after.contains("a change to `SortedList.update` usually belongs here too"),
        "{text}"
    );
}
