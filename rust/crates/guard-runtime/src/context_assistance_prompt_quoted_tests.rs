use super::*;

/// A test kept because it alone holds the prompt's quote repeats more of the
/// prompt's words than the source the prompt names. Both show: only source
/// excerpts set the bar the others are measured against.
#[test]
fn a_quoted_test_cannot_raise_the_bar_for_the_named_source() {
    let picked = [
        excerpt("src/types.py", "def convert(raw):\n    return raw"),
        excerpt(
            "src/test_types.py",
            "def test_invalid_choice_suggests():\n    convert(choice, value)",
        ),
    ];
    let found = words(&["src/types.py", "src/test_types.py"]);
    let asked = words(&["choice", "invalid", "value", "convert", "suggest"]);
    let rendered = render(&picked, &found, &asked).unwrap();
    assert!(rendered.contains("src/types.py (lines"), "{rendered}");
    assert!(rendered.contains("src/test_types.py (lines"), "{rendered}");
}

/// The same through the search: the prompt names `types.py` and quotes a
/// message only its test holds.
#[test]
fn a_named_source_shows_beside_the_test_that_holds_the_quote() {
    let prompt = "In types.py, convert should say \"suggest a choice for an invalid value\".";
    let source = "def convert(raw):\n    return raw\n";
    let test = "def test_invalid_choice_suggests():\n    \
assert convert('bad') == 'suggest a choice for an invalid value'\n";
    let files = [("src/types.py", source), ("src/test_types.py", test)];
    let (home, _project, root) = project(ON, &files);
    let words = crate::context_assistance_prompt_files::terms(prompt);
    let named = crate::context_assistance_prompt_words::named(prompt);
    let found = walk(
        &root,
        &words,
        &phrases(prompt),
        &named,
        Duration::from_secs(5),
    )
    .found(&words);
    assert_eq!(found, ["src/types.py", "src/test_types.py"]);
    let later = Instant::now() + Duration::from_secs(5);
    let read = read_matched(home.path(), &root, "codex", &found, &words, &[], later).unwrap();
    assert!(read.text.contains("src/types.py (lines"), "{}", read.text);
    assert!(
        read.text.contains("src/test_types.py (lines"),
        "{}",
        read.text
    );
}
