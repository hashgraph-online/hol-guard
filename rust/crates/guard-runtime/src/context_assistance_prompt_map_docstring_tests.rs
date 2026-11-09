use super::docstring::asks_for_docstring;
use super::tests::{files, later, looking_for};
use super::*;

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
    let asked = Asked {
        docstring,
        ..Asked::default()
    };
    let list = files(&[("src/iterutils.py", text)]);
    map(&list, &looking_for(&[("remap", true, 1)]), &asked, later())
        .unwrap()
        .text
}

#[test]
fn prompts_about_docstrings_or_doctests_are_told_apart_from_docs() {
    assert!(asks_for_docstring("Add a doctest to remap's docstring"));
    assert!(asks_for_docstring("Fix the Docstrings in iterutils"));
    assert!(asks_for_docstring("make the doctests pass"));
    assert!(!asks_for_docstring("Update the docs for remap"));
    assert!(!asks_for_docstring("document remap"));
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
