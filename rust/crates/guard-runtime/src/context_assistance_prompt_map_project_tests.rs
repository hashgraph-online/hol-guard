//! The map from a typed prompt, through the walk and Guard's own read of a
//! project on disk.
use super::tests::{files, later, looking_for, CORE};
use super::*;
use crate::context_assistance_prompt_files::{plain, walk};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub(super) const ON: &str = "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n";

/// A Guard home with `config`, and a project holding `list`.
pub(super) fn project(
    config: &str,
    list: &[(&str, &str)],
) -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), config).unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = plain(std::fs::canonicalize(project.path()).unwrap());
    for (path, text) in list {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    (home, project, root)
}

pub(super) fn prompt_map(home: &Path, root: &Path, prompt: &str) -> Option<String> {
    changes_map(home, root, prompt, false)
}

/// The map as the hook builds it, for a prompt about this session's changes
/// when `about_changes`.
fn changes_map(home: &Path, root: &Path, prompt: &str, about_changes: bool) -> Option<String> {
    let terms = crate::context_assistance_prompt_words::marked_terms(prompt);
    let words: Vec<String> = terms.iter().map(|(term, _)| term.clone()).collect();
    let quoted = crate::context_assistance_prompt_files::phrases(prompt);
    let found = walk(
        root,
        &words,
        &quoted,
        &named(prompt),
        Duration::from_secs(5),
    );
    let until = Instant::now() + Duration::from_secs(5);
    let map = mapped(
        home,
        root,
        "codex",
        &found,
        &terms,
        &quoted,
        prompt,
        about_changes,
        &[],
        until,
    );
    map.map(|rendered| rendered.text)
}

/// From a typed prompt to the map, through the walk and Guard's own read: a
/// file holding a private key is never read or named, and a workspace that
/// has not allowed project context gets nothing.
#[test]
fn a_prompt_maps_to_allowed_project_code_only() {
    let armour = |edge: &str| format!("-----{edge} RSA {}-----", "PRIVATE KEY");
    let key = format!(
        "def case_sensitive_key():\n    return '''{}\nMIIEowIBAAKCAQEA1c7b0q2xQ0keykeykeykeykey\n{}'''\n",
        armour("BEGIN"),
        armour("END")
    );
    let list = [
        ("src/core.py", CORE),
        ("src/signing.py", key.as_str()),
        (
            "tests/test_core.py",
            "def test_choice():\n    Choice(['a'], case_sensitive=False)\n",
        ),
    ];
    let prompt = "Make `Choice` honour `case_sensitive` when converting values";
    let (home, _project, root) = project(ON, &list);
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("\nsrc/core.py:"), "{text}");
    assert!(
        text.contains(
            "tests/test_core.py: 1 related tests, last test_choice 1-2\n\
             tests/test_core.py:1-2\n```\ndef test_choice():\n    Choice(['a'], case_sensitive=False)\n```"
        ),
        "{text}"
    );
    assert!(!text.contains("signing.py"), "{text}");
    let (home, _project, root) = project("", &list);
    assert_eq!(prompt_map(home.path(), &root, prompt), None);
}

/// A changelog at the project root is read through Guard's own check and
/// named on the map with its newest section; it was left out before, since
/// `.rst` counted as source only inside a docs folder. A review of the
/// session's changes keeps it and drops the uses of its plain words.
#[test]
fn a_root_changelog_reaches_the_map() {
    let changes = "Changes\n=======\n\nUnreleased\n----------\n\n- Fix thing.\n";
    let list = [
        ("src/core.py", CORE),
        ("CHANGES.rst", changes),
        ("docs/changes.rst", ".. include:: ../CHANGES.rst\n"),
    ];
    let prompt = "Make `Choice` honour `case_sensitive` and describe it in CHANGES.rst";
    let (home, _project, root) = project(ON, &list);
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains("\nCHANGES.rst:4-7 newest section: Unreleased"),
        "{text}"
    );
    let review = "Review every change against the original code and make sure \
CHANGES.rst describes everything.";
    let text = changes_map(home.path(), &root, review, true).unwrap();
    assert!(text.contains("\nCHANGES.rst:4-7"), "{text}");
    assert!(!text.contains("'original'"), "{text}");
}

/// A prompt about recent changes that names a function as code is shown its
/// body, since the diff holds only the lines that changed.
#[test]
fn a_change_prompt_naming_a_function_shows_it() {
    let (home, _project, root) = project(ON, &[("src/core.py", CORE)]);
    let prompt = "Something in `convert` broke recently. Track it down and fix it.";
    let text = changes_map(home.path(), &root, prompt, true).unwrap();
    assert!(
        text.contains("```") && text.contains("if not self.case_sensitive:"),
        "{text}"
    );
}

/// A prompt naming a file and a function too common a word to look for, as
/// in "last is not implemented", is shown that file's function left to be
/// written, whole, and the tests that call it; the short functions beside it
/// come with their code, but not their tests.
#[test]
fn a_stub_named_by_its_file_is_shown_whole() {
    let more = "def first(iterable):\n    return next(iter(iterable))\n\n\n\
def last(iterable):\n    \"\"\"Return the last item.\"\"\"\n    raise NotImplementedError\n\n\n\
def nth(iterable, n):\n    return list(iterable)[n]\n";
    let tests =
        "class FirstTests:\n    def test_basic(self):\n        assert mi.first([1]) == 1\n\n\n\
class LastTests:\n    def test_basic(self):\n        assert mi.last([1, 2]) == 2\n";
    let list = [("pkg/more.py", more), ("tests/test_more.py", tests)];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Tests fail because last is not implemented (pkg/more.py). Write the \
implementation; the docstring and tests describe the expected behavior.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains("```\ndef last(iterable):") && text.contains("mi.last([1, 2]) == 2"),
        "{text}"
    );
    assert!(
        text.contains(
            "\n1-2 def first(iterable):\n```\ndef first(iterable):\n    return next(iter(iterable))\n```"
        ),
        "{text}"
    );
    assert!(!text.contains("mi.first("), "{text}");
}

/// A rename of `_batched` lists the lines naming `_batched` as the whole
/// list, not those naming the public `batched` beside it, which the rename
/// leaves alone.
#[test]
fn a_rename_lists_the_name_as_the_prompt_spells_it() {
    let recipes = "def _batched(iterable, n):\n    return iterable\n\n\n\
batched = _batched\n\n\ndef matrix(rows):\n    return batched(rows, 2)\n";
    let list = [
        ("pkg/recipes.py", recipes),
        (
            "tests/test_recipes.py",
            "def test_batched():\n    mi.batched([1], 1)\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Rename the internal helper `_batched` to `_batched_impl` everywhere in the \
project, including tests. Behavior must not change.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "\n\nEvery line naming `_batched`; no other project file holds it:\n\
pkg/recipes.py:1: def _batched(iterable, n):\npkg/recipes.py:5: batched = _batched\n"
        ),
        "{text}"
    );
    assert!(
        !text.contains("pkg/recipes.py:9:") && !text.contains("test_recipes.py:2:"),
        "{text}"
    );
}

/// A name the prompt writes is the definition spelled that way: the
/// `cachedmethod` function, not the `CachedMethod` class whose name differs
/// only in case. A method written after its class (`peekable.prepend`) is
/// that method, not a `prepend` function in another file, and its rename
/// lists the lines naming the method, not those naming the class.
#[test]
fn a_name_is_the_definition_spelled_as_the_prompt_writes_it() {
    let cache =
        "class CachedMethod:\n    def __init__(self, func):\n        self.func = func\n\n\n\
def cachedmethod(func):\n    return CachedMethod(func)\n";
    let more =
        "class peekable:\n    def __init__(self, iterable):\n        self._it = iterable\n\n    \
def prepend(self, *items):\n        self._cache = list(items)\n\n\n\
def spy(iterable):\n    return peekable(iterable)\n";
    let list = [
        ("pkg/cache.py", cache),
        ("pkg/more.py", more),
        (
            "pkg/recipes.py",
            "def prepend(value, iterator):\n    return [value, *iterator]\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let text = prompt_map(
        home.path(),
        &root,
        "Fix `cachedmethod` so it returns the wrapper.",
    )
    .unwrap();
    assert!(text.contains("pkg/cache.py:6-7"), "{text}");
    assert!(!text.contains("pkg/cache.py:1-"), "{text}");
    let prompt = "Rename the method `peekable.prepend` to `peekable.push_front` everywhere, \
keeping tests passing.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("pkg/more.py:5-"), "{text}");
    assert!(!text.contains("pkg/recipes.py:1-"), "{text}");
    assert!(text.contains("naming `prepend`"), "{text}");
    assert!(!text.contains("naming `peekable`"), "{text}");
}

/// A function left to be written comes with what it builds on: its class's
/// constructor, the method and error its docstring writes as code, and the
/// nearest function named like it.
#[test]
fn a_stub_comes_with_what_its_docstring_names() {
    let dicts = "class ManyToMany:\n    def __init__(self):\n        self.data = {}\n\n    \
def add(self, key, val):\n        self.data.setdefault(key, set()).add(val)\n\n    \
def update(self, iterable):\n        \"\"\"Add each pair as :meth:`add` does, raising\n        \
``PairError`` for anything else.\"\"\"\n        raise NotImplementedError\n";
    let list = [
        ("pkg/dictutils.py", dicts),
        (
            "pkg/errors.py",
            "class PairError(ValueError):\n    \"\"\"Raised by ManyToMany.update.\"\"\"\n",
        ),
        (
            "pkg/ranks.py",
            "def combination_index(element, iterable):\n    return sorted(element)\n\n\n\
def permutation_index(element, iterable):\n    \"\"\"Its index.\"\"\"\n    raise NotImplementedError\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Tests fail because permutation_index is not implemented (pkg/ranks.py). \
Write the implementation.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("return sorted(element)"), "{text}");
    let prompt = "`ManyToMany.update` in pkg/dictutils.py was stubbed out and now raises \
NotImplementedError. Implement it again so it does what its docstring says.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("pkg/dictutils.py:8-11"), "{text}");
    assert!(text.contains("self.data = {}"), "{text}");
    assert!(text.contains("setdefault(key"), "{text}");
    assert!(text.contains("pkg/errors.py:1-"), "{text}");
}

/// Prompts from varied tasks reach the definition they mean: a method named as
/// code is a named definition, and a rename lists every line naming it, in
/// source, tests and docs, as the whole list; a file the prompt names wins over another defining the same
/// name, even when it is named like a test file; and the file's folders are not
/// searched for as words. A file named alone maps by its outline, and a plain
/// word is placed in source, not in an example defining it too.
#[test]
fn everyday_prompts_reach_the_definition_they_mean() {
    let compiler =
        "class CodeGenerator:\n    def _import_common(self, node):\n        return node\n\n    \
def visit_Import(self, node):\n        self._import_common(node)\n        return node\n\n    \
def visit_FromImport(self, node):\n        self._import_common(node)\n        return node\n";
    let list = [
        ("src/pkg/compiler.py", compiler),
        (
            "tests/test_compiler.py",
            "def test_import():\n    CodeGenerator()._import_common(None)\n",
        ),
        ("docs/api.md", "Call `_import_common` once.\n"),
        (
            "src/pkg/termui.py",
            "_getchar = None\n\n\ndef getchar(echo=False):\n    raise NotImplementedError\n",
        ),
        (
            "src/pkg/_termui_impl.py",
            "def getchar(echo):\n    return echo\n",
        ),
        (
            "src/pkg/tests.py",
            "def test_undefined(value):\n    return value is None\n",
        ),
        ("src/pkg/parse.py", "def parse(text):\n    return text\n"),
        (
            "examples/aliases/parse.py",
            "def parse(text):\n    return text\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let map = |prompt: &str| prompt_map(home.path(), &root, prompt).unwrap();
    let text =
        map("Rename the private helper `_import_common` to `_import_common_impl` everywhere.");
    assert!(
        text.contains("\nsrc/pkg/compiler.py:2-3 def _import_common(self, node):"),
        "{text}"
    );
    assert!(
        text.contains("\n\nEvery line naming `_import_common`; no other project file holds it:\n"),
        "{text}"
    );
    for listed in [
        "\nsrc/pkg/compiler.py:2: def _import_common(self, node):",
        "\nsrc/pkg/compiler.py:6: self._import_common(node)",
        "\nsrc/pkg/compiler.py:10: self._import_common(node)",
        "\ntests/test_compiler.py:2: CodeGenerator()._import_common(None)",
        "\ndocs/api.md:1: Call `_import_common` once.",
    ] {
        assert!(text.contains(listed), "{text}");
    }
    assert!(!text.contains("```"), "{text}");
    let text = map("Tests fail: `getchar` in src/pkg/termui.py raises NotImplementedError.");
    assert!(
        text.contains("\nsrc/pkg/termui.py:4-5 def getchar"),
        "{text}"
    );
    assert!(!text.contains("_termui_impl.py:1-2"), "{text}");
    assert!(
        text.contains("def getchar(echo=False):\n```\ndef getchar(echo=False):\n    raise NotImplementedError\n```"),
        "{text}"
    );
    // The stub's other names, with their text, and not its own lines.
    for listed in [
        "\n\nOther lines naming `getchar` in the files read:\n",
        "\nsrc/pkg/termui.py:1: _getchar = None",
        "\nsrc/pkg/_termui_impl.py:1: def getchar(echo):",
    ] {
        assert!(text.contains(listed), "{text}");
    }
    assert!(!text.contains("termui.py:4: "), "{text}");
    let text = map("Add a usage example to the docstring of `test_undefined` in src/pkg/tests.py.");
    assert!(
        text.contains("\nsrc/pkg/tests.py:1-2 def test_undefined(value):"),
        "{text}"
    );
    assert!(!text.contains("'src'") && !text.contains("'pkg'"), "{text}");
    let text = map("Look at src/pkg/termui.py and add examples.");
    assert!(
        text.contains("\nsrc/pkg/termui.py:4-5 def getchar"),
        "{text}"
    );
    let text = map("Make parse strip whitespace before returning.");
    assert!(text.contains("\nsrc/pkg/parse.py:1-2 def parse"), "{text}");
    assert!(!text.contains("examples/aliases/parse.py:1-2"), "{text}");
}

/// A function the prompt names is shown whole, so the agent need not read
/// it, even at 60 lines, and only once a session. A rename asks where it is
/// used, and a very long function or a class is given by its lines.
#[test]
fn a_short_named_function_is_shown_whole_once_a_session() {
    let long = format!("def long_one():\n{}", "    x = 1\n".repeat(85));
    let medium = format!("def medium_one():\n{}", "    x = 1\n".repeat(60));
    let list = files(&[
        ("src/core.py", CORE),
        ("src/long.py", &long),
        ("src/medium.py", &medium),
    ]);
    let other = looking_for(&[("other", true, 1)]);
    let first = map(&list, &other, &Asked::default(), later()).unwrap();
    assert!(
        first.text.contains(
            "Definitions this request names:\nsrc/core.py:17-18 def other():\n\
             ```\ndef other():\n    return 1\n```"
        ),
        "{}",
        first.text
    );
    assert!(first.text.starts_with(&format!("{HEADER} {SHOWN_NOTE}")));
    assert_eq!(first.shown.len(), 1);
    let again = Asked {
        earlier: first.shown.clone(),
        ..Asked::default()
    };
    let next = map(&list, &other, &again, later()).unwrap().text;
    assert!(next.contains("\nsrc/core.py:17-18 def other():"), "{next}");
    assert!(
        !next.contains("```") && !next.contains(SHOWN_NOTE),
        "{next}"
    );
    let rename = Asked {
        everywhere: true,
        ..Asked::default()
    };
    let text = map(&list, &other, &rename, later()).unwrap().text;
    assert!(!text.contains("```"), "{text}");
    let text = map(
        &list,
        &looking_for(&[("longone", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap()
    .text;
    assert!(text.contains("\nsrc/long.py:1-"), "{text}");
    assert!(!text.contains("```"), "{text}");
    let text = map(
        &list,
        &looking_for(&[("mediumone", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap()
    .text;
    assert!(
        text.contains("\nsrc/medium.py:1-61 def medium_one():\n```"),
        "{text}"
    );
    let text = map(
        &list,
        &looking_for(&[("choice", true, 1)]),
        &Asked::default(),
        later(),
    )
    .unwrap()
    .text;
    assert!(!text.contains("```"), "{text}");
}

/// A rename lists each line naming the old name with its text, and says
/// the list is whole only when the walk read the whole project and counted
/// no file holding the name beyond the ones read. A longer name holding it
/// is listed apart, so a rename that has to cover it too can.
#[test]
fn a_rename_list_is_whole_only_when_no_file_is_left_out() {
    let list = files(&[
        (
            "src/core.py",
            "def _old_name():\n    return 1\n\n\ndef caller():\n    return _old_name()\n",
        ),
        (
            "tests/test_core.py",
            "def test_old():\n    assert _old_name() == 1\n",
        ),
        (
            "docs/api.md",
            "Call `_old_name` once.\n\n`_old_name_cache` is separate.\n",
        ),
    ]);
    let terms = [("oldname".to_owned(), true)];
    let asked = Asked {
        everywhere: true,
        spellings: vec!["_old_name".to_owned()],
        renames: Vec::new(),
        ..Asked::default()
    };
    let walk = |holding: usize, complete: bool| Walk {
        checked: 200,
        holding: vec![holding],
        words: vec![holding],
        spelled: vec![holding],
        complete,
        ..Walk::default()
    };
    let text = map(&list, &sought(&walk(3, true), &terms, &[]), &asked, later())
        .unwrap()
        .text;
    assert!(
        text.contains(
            "\n\nEvery line naming `_old_name`; no other project file holds it:\n\
             src/core.py:1: def _old_name():\nsrc/core.py:6: return _old_name()\n\
             tests/test_core.py:2: assert _old_name() == 1\ndocs/api.md:1: Call `_old_name` once.\n\n\
             Lines naming a longer name holding `_old_name`:\ndocs/api.md:3: `_old_name_cache`"
        ),
        "{text}"
    );
    assert!(!text.contains("Where "), "{text}");
    for walk in [walk(4, true), walk(3, false)] {
        let text = map(&list, &sought(&walk, &terms, &[]), &asked, later())
            .unwrap()
            .text;
        assert!(
            text.contains(
                "\n\nLines naming `_old_name` in the files read; other files may hold it too:\n\
                 src/core.py:1: def _old_name():"
            ),
            "{text}"
        );
    }
}
