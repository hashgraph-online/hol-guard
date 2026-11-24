//! Which prompt words the uses list looks for.
use super::super::tests::{files, later, looking_for};
use super::super::{map, Asked};

const PARSE: &str =
    "def parse(text):\n    value = text.strip()\n    return 1\n\n\ndef other():\n    pass\n";

/// A keyword written plainly is prose, so a function holding a prompt word
/// on one line and `return` on another is not where the change goes. Written
/// as a name, the keyword still counts.
#[test]
fn a_plain_keyword_places_no_code() {
    let list = files(&[("src/parse.py", PARSE)]);
    let plain = looking_for(&[("value", false, 2), ("return", false, 2)]);
    let text = map(&list, &plain, &Asked::default(), later()).map(|mapped| mapped.text);
    assert!(
        text.as_deref()
            .is_none_or(|text| !text.contains("src/parse.py")),
        "{text:?}"
    );
    let named = looking_for(&[("value", false, 2), ("return", true, 2)]);
    let text = map(&list, &named, &Asked::default(), later()).unwrap().text;
    assert!(
        text.contains("Where 'value', 'return' appear in source:"),
        "{text}"
    );
    assert!(
        text.contains("src/parse.py:1-3 parse (lines 2, 3)"),
        "{text}"
    );
}
