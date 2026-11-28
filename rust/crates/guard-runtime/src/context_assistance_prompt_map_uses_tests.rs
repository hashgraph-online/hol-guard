//! Which prompt words the uses list looks for.
use super::super::tests::{files, later, looking_for};
use super::super::{map, Asked};
use super::sought;
use crate::context_assistance_prompt_files::Walk;

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

/// A plain keyword that a source file defines is still that definition's
/// name: "fix catch" places `def catch`.
#[test]
fn a_plain_keyword_still_names_its_definition() {
    let source = "def catch(error):\n    return str(error)\n\n\ndef other():\n    pass\n";
    let list = files(&[("src/errors.py", source)]);
    let plain = looking_for(&[("catch", false, 1)]);
    let text = map(&list, &plain, &Asked::default(), later()).unwrap().text;
    assert!(text.contains("src/errors.py:1-2"), "{text}");
}

/// Plain words place no definition too long to be a place to look: a
/// table or page of text holding them is not the code a prompt is about.
/// Written as a name, a word still places it.
#[test]
fn plain_words_place_no_long_definition() {
    let mut long = String::from("def table():\n    pause = 1\n    restart = 2\n");
    long.push_str(&"    filler = 0\n".repeat(200));
    let short = "def handler():\n    pause = 1\n    restart = 2\n";
    let plain = looking_for(&[("pause", false, 1), ("restart", false, 1)]);
    let list = files(&[("src/table.py", long.as_str())]);
    let text = map(&list, &plain, &Asked::default(), later()).map(|mapped| mapped.text);
    assert!(
        text.as_deref()
            .is_none_or(|text| !text.contains("src/table.py")),
        "{text:?}"
    );
    let list = files(&[("src/table.py", long.as_str()), ("src/handler.py", short)]);
    let text = map(&list, &plain, &Asked::default(), later()).unwrap().text;
    assert!(
        text.contains("src/handler.py:1-3 handler (lines 2, 3)"),
        "{text}"
    );
    assert!(!text.contains("src/table.py"), "{text}");
    let named = looking_for(&[("pause", true, 1), ("restart", false, 1)]);
    let list = files(&[("src/table.py", long.as_str())]);
    let text = map(&list, &named, &Asked::default(), later()).unwrap().text;
    assert!(
        text.contains("src/table.py:1-203 table (lines 2, 3)"),
        "{text}"
    );
}

/// A new name written as code that ends like a family of defined names is
/// read beside the shortest of them: `filterQuery` beside `getQuery` and
/// `parseQuery`. One name with that ending is no family.
#[test]
fn a_new_name_finds_the_family_it_ends_like() {
    let source = "export function getQuery(input) {\n  return parseQuery(input);\n}\n\n\
export function parseQuery(text) {\n  return {};\n}\n\n\
export function withBase(input, base) {\n  return base + input;\n}\n";
    let walk = Walk {
        checked: 200,
        holding: vec![0],
        words: vec![0],
        spelled: vec![0],
        complete: true,
        ..Walk::default()
    };
    let mapped = |text: &str, name: bool| {
        let list = files(&[("src/query.ts", text)]);
        let sought = sought(&walk, &[("filterquery".to_owned(), name)], &[]);
        map(&list, &sought, &Asked::default(), later()).map(|mapped| mapped.text)
    };
    let text = mapped(source, true).unwrap();
    assert!(text.contains("src/query.ts:1-3"), "{text}");
    assert!(!text.contains("withBase"), "{text}");
    assert!(mapped(source, false).is_none_or(|text| !text.contains("src/query.ts:1-3")));
    let lone = source.replace("parseQuery(text)", "parseItems(text)");
    let lone = mapped(&lone, true);
    assert!(
        lone.is_none_or(|text| !text.contains("src/query.ts:1-3")),
        "one is no family"
    );
}
