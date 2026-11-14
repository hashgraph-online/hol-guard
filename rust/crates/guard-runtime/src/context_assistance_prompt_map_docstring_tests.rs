use super::docstring::{asks_for_docstring, Asks};
use super::tests::{files, later, looking_for};
use super::*;
use std::path::Path;

/// A function of more than 80 lines with `docstring` as its docstring's
/// opening line, or no docstring when it is empty.
fn long_function(signature: &str, docstring: &str) -> String {
    let mut text = format!("import os\n\n\n{signature}\n");
    if !docstring.is_empty() {
        text.push_str(&format!(
            "    {docstring}\n\n    >>> remap({{}}, len)\n    {{}}\n    \"\"\"\n"
        ));
    }
    for n in 0..90 {
        text.push_str(&format!("    step_{n} = os.sep\n"));
    }
    text.push_str("    return step_0\n");
    text
}

fn mapped(text: &str, docstring: bool) -> String {
    mapped_in("src/iterutils.py", text, docstring)
}

fn mapped_in(path: &str, text: &str, docstring: bool) -> String {
    mapped_at(Path::new(""), path, text, docstring)
}

/// The map of `text` at `path` in a project at `root`.
fn mapped_at(root: &Path, path: &str, text: &str, docstring: bool) -> String {
    let asked = Asked {
        docstring: Asks {
            any: docstring,
            examples: docstring,
        },
        root: root.to_path_buf(),
        ..Asked::default()
    };
    let list = files(&[(path, text)]);
    map(&list, &looking_for(&[("remap", true, 1)]), &asked, later())
        .unwrap()
        .text
}

const RUN: &str = "\nRun just its doctest with `python -m pytest -q --doctest-modules ";
const CHECK: &str = "That run is the check an added example needs, and the edit's own reply \
confirms the edit, so the file need not be read again.";

#[test]
fn prompts_about_docstrings_or_doctests_are_told_apart_from_docs() {
    assert!(asks_for_docstring("Add a doctest to remap's docstring"));
    assert!(asks_for_docstring("Fix the Docstrings in iterutils"));
    assert!(asks_for_docstring("make the doctests pass"));
    assert!(!asks_for_docstring("Update the docs for remap"));
    assert!(!asks_for_docstring("document remap"));
    assert!(asks_for_docstring(
        "Add a usage example to remap's docstring"
    ));
    assert!(asks_for_docstring("put a little >>> line in remap"));
    // An example names no docstring by itself.
    assert!(!asks_for_docstring(
        "Fix remap, for example when root is empty"
    ));
    assert!(!asks_for_docstring("Fix remap in example.py"));
    assert!(!asks_for_docstring("update the examples folder"));
    // A prompt that reads a docstring for what to build asks for the code.
    assert!(!asks_for_docstring(
        "remap was stubbed out. Implement it again so it does what its docstring says."
    ));
    assert!(!asks_for_docstring(
        "Write the implementation; the docstring and tests describe the expected behavior."
    ));
}

/// A stub's docstring says what to build, so a prompt pointing at it asks
/// for code, and a docstring with no example has no doctest to run: named
/// one, agents ran the command, read "not found" and tried others.
#[test]
fn a_docstring_without_an_example_gets_no_doctest_command() {
    assert!(!asks_for_docstring(
        "someone left rr_cache as a NotImplementedError stub in src/cachetools/func.py. \
fill it in please, the tests and docstring say what it should do"
    ));
    assert!(!asks_for_docstring(
        "make remap do what its docstring explains"
    ));
    let plain = "def remap(root):\n    \"\"\"Remap it.\"\"\"\n    raise NotImplementedError\n";
    let shown_with = |asks: Asks, text: &str| {
        let asked = Asked {
            docstring: asks,
            ..Asked::default()
        };
        let list = files(&[("src/iterutils.py", text)]);
        let terms = looking_for(&[("remap", true, 1)]);
        map(&list, &terms, &asked, later()).unwrap().text
    };
    let docstring = Asks {
        any: true,
        examples: false,
    };
    let shown = shown_with(docstring, plain);
    assert!(!shown.contains("--doctest-modules"), "{shown}");
    assert!(!shown.contains("not a raw string"), "{shown}");
    let example =
        "def remap(root):\n    \"\"\"Remap it.\n\n    >>> remap(1)\n    1\n    \"\"\"\n    \
raise NotImplementedError\n";
    let shown = shown_with(docstring, example);
    assert!(shown.contains(RUN), "{shown}");
    assert!(shown.contains("not a raw string"), "{shown}");
    let wanted = Asks {
        any: true,
        examples: true,
    };
    assert!(shown_with(wanted, plain).contains(RUN));
}

/// The doctest and backslash notes are said in full once, for the first
/// function shown: a function shown beside it gets the command for its own
/// doctest only.
#[test]
fn the_doctest_note_is_given_once() {
    let text = "def remap(root):\n    \"\"\"Remap it.\"\"\"\n    return root\n\n\n\
def walk(root):\n    \"\"\"Walk it.\"\"\"\n    return root\n";
    let asked = Asked {
        docstring: Asks {
            any: true,
            examples: true,
        },
        ..Asked::default()
    };
    let list = files(&[("src/iterutils.py", text)]);
    let terms = looking_for(&[("remap", true, 1), ("walk", true, 1)]);
    let shown = map(&list, &terms, &asked, later()).unwrap().text;
    assert_eq!(shown.matches("```").count(), 4, "{shown}");
    assert_eq!(shown.matches(CHECK).count(), 1, "{shown}");
    assert_eq!(shown.matches("--doctest-modules").count(), 2, "{shown}");
    assert!(shown.contains("iterutils.py::iterutils.walk`."), "{shown}");
    assert_eq!(shown.matches("not a raw string").count(), 1, "{shown}");
    // With no command to name, the backslash note is still said once.
    let spaced = files(&[("my src/iterutils.py", text)]);
    let shown = map(&spaced, &terms, &asked, later()).unwrap().text;
    assert_eq!(shown.matches("not a raw string").count(), 1, "{shown}");
}

/// A prompt about the docstring of a function too long to show whole gets
/// its signature and docstring, and a note that the docstring is not raw, so
/// an example's backslash is written twice. Other prompts get its lines only.
#[test]
fn a_long_function_shows_its_signature_and_docstring_for_a_docstring_prompt() {
    let text = long_function(
        "def remap(root, visit=None,\n          enter=None):",
        "\"\"\"Remap a structure.",
    );
    let shown = mapped(&text, true);
    assert!(
        shown.contains(
            "```\ndef remap(root, visit=None,\n          enter=None):\n    \"\"\"Remap a structure.\n\n    \
>>> remap({}, len)\n    {}\n    \"\"\"\n```\nThose are lines 4-10 only, its signature and docstring.\n\
Its docstring is not a raw string"
        ),
        "{shown}"
    );
    assert!(!shown.contains("step_0 ="), "{shown}");
    let plain = mapped(&text, false);
    assert!(plain.contains("src/iterutils.py:4-"), "{plain}");
    assert!(!plain.contains("```"), "{plain}");
}

#[test]
fn a_raw_docstring_gets_no_backslash_note() {
    let text = long_function("def remap(root):", "r\"\"\"Remap a structure.");
    let shown = mapped(&text, true);
    assert!(
        shown.contains("Those are lines 4-9 only, its signature and docstring."),
        "{shown}"
    );
    assert!(!shown.contains("not a raw string"), "{shown}");
}

#[test]
fn a_long_function_without_a_docstring_shows_its_signature() {
    let text = long_function("def remap(root):  # walk it", "");
    let shown = mapped(&text, true);
    assert!(
        shown.contains("```\ndef remap(root):  # walk it\n```\nThose are lines 4-4 only, its signature; it has no docstring."),
        "{shown}"
    );
    assert!(!shown.contains("not a raw string"), "{shown}");
}

/// A short function is shown whole as before, with the backslash note when
/// the prompt is about its docstring.
#[test]
fn a_short_function_keeps_showing_whole_with_the_note() {
    let text =
        "def remap(root):\n    '''Remap it.\n\n    >>> remap(1)\n    1\n    '''\n    return root\n";
    let shown = mapped(text, true);
    assert!(
        shown.contains("    return root\n```\nIts docstring is not a raw string"),
        "{shown}"
    );
    assert!(!shown.contains("Those are lines"), "{shown}");
    assert!(!mapped(text, false).contains("not a raw string"));
}

/// A prompt about a Python function's docstring names the command that
/// runs just its doctest, by the node id pytest gives it: the file, then
/// `<module>.<name>`, with the class for a method, the folder for a
/// package's `__init__.py`, and each folder above holding an `__init__.py`.
/// A node id runs that doctest alone, where `-k toolz.utils.remap` would
/// also run `remap_more`'s. Shown none, agents guessed a node id, ran the
/// whole module and then the test suite.
#[test]
fn a_docstring_prompt_names_the_run_of_just_its_doctest() {
    let text = "def remap(root):\n    r\"\"\"Remap it.\"\"\"\n    return root\n";
    let shown = mapped(text, true);
    let run = format!("```{RUN}src/iterutils.py::iterutils.remap`. {CHECK}");
    assert!(shown.contains(&run), "{shown}");
    assert!(!shown.contains("outside its package"), "{shown}");
    assert!(!mapped(text, false).contains("--doctest-modules"));

    let project = tempfile::tempdir().unwrap();
    let write = |path: &str, text: &str| {
        let file = project.path().join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    };
    let method = "class Tree:\n    def remap(self, root):\n        \"\"\"Remap it.\"\"\"\n        return root\n";
    write("src/tree/__init__.py", method);
    let shown = mapped_at(project.path(), "src/tree/__init__.py", method, true);
    let run = format!("{RUN}src/tree/__init__.py::tree.Tree.remap`. {CHECK}");
    assert!(shown.contains(&run), "{shown}");

    let both = "def remap(root):\n    r\"\"\"Remap it.\"\"\"\n    return root\n\n\ndef remap_more(root):\n    r\"\"\"Remap more.\"\"\"\n    return root\n";
    write("toolz/__init__.py", "");
    write("toolz/utils.py", both);
    let shown = mapped_at(project.path(), "toolz/utils.py", both, true);
    let run = format!("{RUN}toolz/utils.py::toolz.utils.remap`. {CHECK}");
    assert!(shown.contains(&run) && !shown.contains(" -k "), "{shown}");
}

/// `python -m doctest` fails on a module that imports from its own package by
/// a relative import, so the note says why the command is pytest. Where no
/// single doctest can be named, as for a function inside another, the
/// command runs the whole module's.
#[test]
fn a_module_with_relative_imports_says_why_the_command_is_pytest() {
    let text = "from .recipes import take\n\n\ndef remap(root):\n    r\"\"\"Remap it.\"\"\"\n    return take(1, root)\n";
    let shown = mapped(text, true);
    let run = format!(
        "```{RUN}src/iterutils.py::iterutils.remap`. {CHECK} `python -m doctest` would load \
the file outside its package, where its relative imports fail."
    );
    assert!(shown.contains(&run), "{shown}");
    assert!(!mapped(text, false).contains("--doctest-modules"));

    let nested = "from .recipes import take\n\n\ndef walk(root):\n    def remap(item):\n        \"\"\"Remap it.\"\"\"\n        return take(1, item)\n\n    return remap(root)\n";
    let shown = mapped(nested, true);
    assert!(shown.contains("def remap(item):"), "{shown}");
    assert!(
        shown.contains(
            "\nRun its doctests with `python -m pytest --doctest-modules src/iterutils.py`: \
`python -m doctest` loads the file outside its package, so its relative imports fail."
        ),
        "{shown}"
    );
    assert!(!shown.contains("::"), "{shown}");
    let absolute = nested.replace("from .recipes", "from recipes");
    assert!(!mapped(&absolute, true).contains("--doctest-modules"));
}

/// A docstring in single quotes ends on its line, raw or not, and a comment
/// is not a statement, so a docstring after one is still the docstring.
#[test]
fn a_single_quoted_docstring_after_a_comment_is_found() {
    let text = long_function(
        "def remap(root):\n    # walk it\n    \"Remap a structure.\"",
        "",
    );
    let shown = mapped(&text, true);
    assert!(
        shown.contains(
            "    \"Remap a structure.\"\n```\nThose are lines 4-6 only, its signature and \
docstring.\nIts docstring is not a raw string"
        ),
        "{shown}"
    );
    let raw = mapped(
        &long_function("def remap(root):\n    r'Remap it.'", ""),
        true,
    );
    assert!(
        raw.contains("Those are lines 4-5 only, its signature and docstring."),
        "{raw}"
    );
    assert!(!raw.contains("not a raw string"), "{raw}");
}

/// A `#` or bracket in a default string is neither a comment nor a bracket,
/// so the signature still ends where its colon is.
#[test]
fn string_defaults_do_not_hide_the_signature() {
    let text = long_function(
        "def remap(root, marker=\"#\",\n          pattern=\"(\"):",
        "\"\"\"Remap a structure.",
    );
    let shown = mapped(&text, true);
    assert!(
        shown.contains(
            "```\ndef remap(root, marker=\"#\",\n          pattern=\"(\"):\n    \"\"\"Remap"
        ),
        "{shown}"
    );
    assert!(
        shown.contains("Those are lines 4-10 only, its signature and docstring."),
        "{shown}"
    );
}

/// A quote after a backslash does not end the docstring.
#[test]
fn an_escaped_quote_does_not_end_the_docstring() {
    let text = long_function(
        "def remap(root):",
        "\"\"\"Remap it, as in \\\"\"\" strings.",
    );
    let shown = mapped(&text, true);
    assert!(
        shown.contains("Those are lines 4-9 only, its signature and docstring."),
        "{shown}"
    );
}
