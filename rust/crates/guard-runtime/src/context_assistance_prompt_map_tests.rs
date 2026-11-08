use super::*;
use std::time::{Duration, Instant};

pub(super) const CORE: &str = "import os


class Choice(ParamType):
    name = \"choice\"

    def __init__(self, choices, case_sensitive=True):
        self.choices = choices
        self.case_sensitive = case_sensitive

    def convert(self, value, param, ctx):
        if not self.case_sensitive:
            value = value.lower()
        return value


def other():
    return 1
";

/// What the map looks for when `checked` files were walked and each term,
/// marked when the prompt wrote it as a name, is in that many code files.
pub(super) fn looking_for(terms: &[(&str, bool, usize)]) -> Vec<Sought> {
    let holding: Vec<usize> = terms.iter().map(|(_, _, holding)| *holding).collect();
    let walk = Walk {
        checked: 200,
        holding: holding.clone(),
        words: holding,
        ..Walk::default()
    };
    let terms: Vec<(String, bool)> = terms
        .iter()
        .map(|(term, name, _)| ((*term).to_owned(), *name))
        .collect();
    sought(&walk, &terms, &[])
}

pub(super) fn files(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
        .collect()
}

pub(super) fn later() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn mapped_text(list: &[(&str, &str)], terms: &[(&str, bool, usize)]) -> Option<String> {
    map(
        &files(list),
        &looking_for(terms),
        &Asked::default(),
        later(),
    )
    .map(|rendered| rendered.text)
}

/// The class the prompt names is listed with its members' lines, and the
/// function that uses the prompt's other name with the lines it is on, so the
/// agent opens just what it needs. No code is pasted.
#[test]
fn the_named_class_and_the_function_using_the_other_name_are_listed() {
    let terms = looking_for(&[("choice", true, 3), ("casesensitive", true, 2)]);
    let mapped = map(
        &files(&[("src/core.py", CORE)]),
        &terms,
        &Asked::default(),
        later(),
    )
    .unwrap();
    let text = mapped.text;
    assert!(text.starts_with(HEADER), "{text}");
    assert!(
        text.contains(
            "Definitions this request names:\nsrc/core.py:4-14 class Choice(ParamType):\n  \
             members: __init__ 7-9, convert 11-14"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "Where 'casesensitive' appear in source:\nsrc/core.py:7-9 Choice.__init__ (lines 7, 9)"
        ),
        "{text}"
    );
    assert!(!text.contains("def other"), "{text}");
    assert!(!text.contains("```"), "{text}");
    assert!(mapped.shown.is_empty());
}

/// A function that mentions a word once is not where the change goes, however
/// long it is.
#[test]
fn a_function_mentioning_a_word_once_is_not_listed() {
    let mut long = String::from("def handle(choice, case_sensitive):\n");
    for _ in 0..300 {
        long.push_str("    step()\n");
    }
    let short = "def choice():\n    return 1\n";
    let text = mapped_text(
        &[("src/long.py", &long), ("src/short.py", short)],
        &[("casesensitive", true, 2), ("choice", true, 3)],
    )
    .unwrap();
    assert!(text.contains("src/short.py:1-2 def choice():"), "{text}");
    assert!(!text.contains("src/long.py"), "{text}");
}

/// After the source come the test files that test it, with the last related
/// test, then the doc sections asked for and the newest changelog section,
/// where an entry for the change belongs.
#[test]
fn tests_docs_and_the_newest_changelog_section_follow_the_source() {
    let mut tests = String::new();
    for n in 0..5 {
        tests.push_str(&format!(
            "def test_case_sensitive_{n}():\n    case_sensitive()\n\n"
        ));
    }
    let docs = "Options\n=======\n\nUse ``case_sensitive`` to match exactly.\n";
    let changes = "Changes\n=======\n\nUnreleased\n----------\n\n- Fix thing.\n\n\
Version 8.1.0\n-------------\n\n- Old case_sensitive fix.\n";
    let asked = Asked {
        docs: true,
        changelog: false,
        named: vec!["CHANGES.rst".into()],
        changes: false,
        everywhere: false,
        earlier: Vec::new(),
    };
    let text = map(
        &files(&[
            ("CHANGES.rst", changes),
            ("docs/options.rst", docs),
            ("tests/test_core.py", &tests),
            ("src/core.py", CORE),
        ]),
        &looking_for(&[("casesensitive", true, 4)]),
        &asked,
        later(),
    )
    .unwrap()
    .text;
    let at = |part: &str| text.find(part).unwrap_or_else(|| panic!("{part}: {text}"));
    let source = at("src/core.py:7-9 Choice.__init__ (lines 7, 9)");
    let tests = at("Tests:\ntests/test_core.py: 5 related tests, last test_case_sensitive_4 13-14");
    let docs = at("Docs:\ndocs/options.rst:1-4 Options");
    let changelog = at("CHANGES.rst:4-8 newest section: Unreleased");
    assert!(source < tests && tests < docs && docs < changelog, "{text}");
}

/// A class the prompt names finds the tests that use it, however its name is
/// cased there.
#[test]
fn tests_that_use_a_named_class_are_listed() {
    let tests = "def test_a():\n    click.Choice(['a'])\n\n\
def test_b():\n    click.Choice(['b'])\n\n\
def test_other():\n    return 1\n";
    let text = mapped_text(
        &[("src/core.py", CORE), ("tests/test_types.py", tests)],
        &[("choice", true, 3)],
    )
    .unwrap();
    assert!(
        text.contains("Tests:\ntests/test_types.py: 2 related tests, last test_b 4-5"),
        "{text}"
    );
}

/// The few tests that use the request's rare word come before the many that
/// only use the class it names.
#[test]
fn tests_using_a_rare_word_come_first() {
    let mut many = String::new();
    for n in 0..6 {
        many.push_str(&format!("def test_choice_{n}():\n    Choice(['a'])\n\n"));
    }
    let rare = "def test_plain():\n    Choice(['a'])\n\n\
def test_sensitive_a():\n    Choice(['a'], case_sensitive=False)\n\n\
def test_sensitive_b():\n    Choice(['b'], case_sensitive=False)\n";
    let text = mapped_text(
        &[
            ("src/core.py", CORE),
            ("tests/test_many.py", &many),
            ("tests/test_rare.py", rare),
        ],
        &[("choice", true, 3), ("casesensitive", true, 2)],
    )
    .unwrap();
    assert!(
        text.contains(
            "Tests:\ntests/test_rare.py: 2 related tests, last test_sensitive_b 7-8\n\
tests/test_many.py: 6 related tests"
        ),
        "{text}"
    );
}

/// The doc section that quotes the request's rare name wins over sections
/// that only say it in prose or quote everyday words, and a docs folder keeps
/// the top-level README out.
#[test]
fn docs_rank_by_quoted_names_from_the_docs_folder() {
    let mut list = vec![
        ("src/core.py".to_owned(), CORE.to_owned()),
        (
            "README.md".to_owned(),
            "# Choice\n\n``choice``\n".to_owned(),
        ),
        (
            "docs/options.rst".to_owned(),
            "Choice Options\n==============\n\nPick one with :class:`Choice`.\n".to_owned(),
        ),
        (
            "docs/prose.rst".to_owned(),
            "Choice and more\n===============\n\nA choice, a choice, an example to run.\n"
                .to_owned(),
        ),
    ];
    for n in 0..5 {
        list.push((
            format!("docs/page{n}.rst"),
            format!("Page {n}\n======\n\nAn example to ``run`` and check.\n"),
        ));
    }
    let asked = Asked {
        docs: true,
        ..Asked::default()
    };
    let terms = looking_for(&[
        ("choice", true, 3),
        ("example", false, 20),
        ("run", false, 20),
        ("check", false, 20),
    ]);
    let text = map(&list, &terms, &asked, later()).unwrap().text;
    assert!(
        text.contains("Docs:\ndocs/options.rst:1-4 Choice Options"),
        "{text}"
    );
    assert!(!text.contains("README.md"), "{text}");
    assert!(!text.contains("docs/prose.rst"), "{text}");
}

/// A class too long to read whole gives its first line and its members'
/// lines, the member list cut short past its limit.
#[test]
fn a_long_class_is_listed_by_its_members() {
    let mut big = String::from("class Registry:\n");
    for n in 0..100 {
        big.push_str(&format!("    def m{n}(self):\n        return {n}\n"));
    }
    let text = mapped_text(&[("src/big.py", &big)], &[("registry", true, 2)]).unwrap();
    assert!(
        text.contains(
            "src/big.py:1 (201 lines) class Registry:\n  members: m0 2-3, m1 4-5, m2 6-7"
        ),
        "{text}"
    );
    assert!(text.ends_with(", ..."), "{text}");
    assert!(text.len() <= MAX_MAP_CHARS, "{}", text.len());
}

/// A plain word in many of the project's code files places nothing, even
/// where a file defines it; a rarer one that a file defines is listed like a
/// name.
#[test]
fn a_common_plain_word_places_nothing() {
    let uses = "def read():\n    token = 1\n    return token\n";
    let list = files(&[
        ("src/read.py", uses),
        ("src/token.py", "class Token:\n    pass\n"),
    ]);
    let rare = looking_for(&[("token", false, MAX_PLAIN_FILES)]);
    let text = map(&list, &rare, &Asked::default(), later()).unwrap().text;
    assert!(text.contains("src/token.py:1-2 class Token:"), "{text}");
    let common = looking_for(&[("token", false, MAX_PLAIN_FILES + 1)]);
    assert!(map(&list, &common, &Asked::default(), later()).is_none());
    let named = looking_for(&[("token", true, 50)]);
    assert!(map(&list, &named, &Asked::default(), later()).is_some());
    // A name as common as a package's own is still listed where it is
    // defined, but its uses place nothing.
    let used_only = files(&[("src/read.py", uses)]);
    assert!(map(&used_only, &named, &Asked::default(), later()).is_none());
}

/// A plain word an example script defines is not a name: "commit" in a
/// prompt does not name `examples/aliases/aliases.py`'s `commit`. Library code
/// defining the word still counts, and so does the word written as a name.
#[test]
fn a_plain_word_defined_only_in_examples_names_nothing() {
    let example = "def commit(repo):\n    repo.save()\n";
    let plain = [("commit", false, 1)];
    let named = [("commit", true, 1)];
    let text = mapped_text(&[("examples/aliases/aliases.py", example)], &plain);
    assert!(!text.unwrap_or_default().contains(NAMED_TITLE));
    let text = mapped_text(&[("examples/aliases/aliases.py", example)], &named).unwrap();
    assert!(text.contains(NAMED_TITLE), "{text}");
    let text = mapped_text(&[("src/vcs/commit.py", example)], &plain).unwrap();
    assert!(text.contains(NAMED_TITLE), "{text}");
}

/// A plain word only in comments and docstrings is prose about the code and
/// places nothing; on a code line it does.
#[test]
fn words_in_comments_and_docstrings_place_nothing() {
    let prose = "def run(value):\n    \"\"\"\n    Reticulate it.\n    Reticulate it again.\n    \"\"\"\n    # reticulate\n    return value\n";
    let words = [("reticulate", false, 1)];
    assert_eq!(mapped_text(&[("src/run.py", prose)], &words), None);
    let code = "def run(value):\n    reticulate = value\n    return reticulate\n";
    let text = mapped_text(&[("src/run.py", code)], &words).unwrap();
    assert!(text.contains("src/run.py:1-3 run (lines 2, 3)"), "{text}");
}

/// Definitions run from their decorators over a long signature to the end
/// of their body, in indented and braced languages alike, and a docstring
/// that starts a line with `class` defines nothing.
#[test]
fn definitions_cover_decorators_signatures_and_bodies() {
    let python = "@cached\ndef load(\n    path,\n) -> str:\n    \"\"\"\n    class of loaders\n    \"\"\"\n    return path\n\nx = 1\n";
    let lines: Vec<&str> = python.lines().collect();
    let found: Vec<(usize, usize)> = sections("a.py", &lines)
        .iter()
        .map(|s| (s.start, s.end))
        .collect();
    assert_eq!(found, vec![(1, 8)]);
    let rust = "#[inline]\npub fn load<T>(path: T) -> T\nwhere\n    T: Clone,\n{\n    path\n}\n\nfn next() {}\n";
    let lines: Vec<&str> = rust.lines().collect();
    let found: Vec<(usize, usize, Option<String>)> = sections("a.rs", &lines)
        .into_iter()
        .map(|s| (s.start, s.end, s.name))
        .collect();
    assert_eq!(
        found,
        vec![(1, 7, Some("load".into())), (9, 9, Some("next".into()))]
    );
    let nested = "impl Loader {\n    fn target() {}\n}\n";
    let lines: Vec<&str> = nested.lines().collect();
    let found: Vec<(usize, usize)> = sections("a.rs", &lines)
        .iter()
        .map(|s| (s.start, s.end))
        .collect();
    assert_eq!(found, vec![(1, 3), (2, 2)], "the outer brace is the impl's");
}

/// Markdown and reStructuredText headings split a prose file; a `#` line in
/// a fenced block is code, not a heading.
#[test]
fn headings_split_prose_but_fenced_code_does_not() {
    let markdown = "# Guide\n\nIntro.\n\n```sh\n# not a heading\n```\n\n## Install\n\nRun it.\n";
    let lines: Vec<&str> = markdown.lines().collect();
    let found: Vec<(usize, usize)> = sections("README.md", &lines)
        .iter()
        .map(|s| (s.start, s.end))
        .collect();
    assert_eq!(found, vec![(1, 8), (9, 11)]);
    let nested = "# Guide\n\n````md\n```sh\n# inner\n```\n~~~\n# still code\n````\n\n## Install\n";
    let lines: Vec<&str> = nested.lines().collect();
    let found: Vec<(usize, usize)> = sections("README.md", &lines)
        .iter()
        .map(|s| (s.start, s.end))
        .collect();
    assert_eq!(
        found,
        vec![(1, 10), (11, 11)],
        "only a matching fence closes"
    );
}

/// A source file named like a changelog is mapped as source.
#[test]
fn only_prose_files_are_changelogs() {
    assert_eq!(kind("src/history.py"), Kind::Source);
    assert_eq!(kind("changes.rs"), Kind::Source);
    assert_eq!(kind("HISTORY.md"), Kind::Changelog);
    let history = "def history_entry(case_sensitive):\n    return case_sensitive\n";
    let text = mapped_text(
        &[("src/history.py", history)],
        &[("casesensitive", true, 1)],
    )
    .unwrap();
    assert!(
        text.contains("src/history.py:1-2 history_entry (lines 1, 2)"),
        "{text}"
    );
}

/// A changelog the prompt names is on the map with its newest section, even
/// when nothing in it matches the prompt's words.
#[test]
fn a_named_changelog_stays_on_the_map() {
    let changes = "Changes\n=======\n\nUnreleased\n----------\n\n- Fix thing.\n";
    let list = files(&[("CHANGES.rst", changes), ("src/core.py", CORE)]);
    let terms = looking_for(&[("casesensitive", true, 2)]);
    let unnamed = map(&list, &terms, &Asked::default(), later()).unwrap();
    assert!(!unnamed.text.contains("CHANGES.rst"), "{}", unnamed.text);
    let asked = Asked {
        docs: false,
        changelog: false,
        named: vec!["CHANGES.rst".into()],
        changes: false,
        everywhere: false,
        earlier: Vec::new(),
    };
    let named = map(&list, &terms, &asked, later()).unwrap();
    assert!(
        named
            .text
            .contains("CHANGES.rst:4-7 newest section: Unreleased"),
        "{}",
        named.text
    );
}

/// A prompt about this session's changes, such as "review every change
/// against the original code", gets no uses of its plain words: the changes
/// are listed already, and "original" names no code. The changelog it names
/// stays.
#[test]
fn a_review_of_changes_skips_its_plain_words() {
    let changes = "Changes\n=======\n\nUnreleased\n----------\n\n- Fix thing.\n";
    let list = files(&[("CHANGES.rst", changes), ("src/core.py", CORE)]);
    let terms = looking_for(&[("value", false, 2)]);
    let mut asked = Asked {
        named: vec!["CHANGES.rst".into()],
        ..Asked::default()
    };
    let plain = map(&list, &terms, &asked, later()).unwrap();
    assert!(
        plain.text.contains("Where 'value' appear"),
        "{}",
        plain.text
    );
    asked.changes = true;
    let review = map(&list, &terms, &asked, later()).unwrap();
    assert!(!review.text.contains("'value'"), "{}", review.text);
    assert!(review.text.contains("CHANGES.rst:4-7"), "{}", review.text);
}

/// The map gives up once its time is up, however big the files.
#[test]
fn the_map_stops_at_its_deadline() {
    let many: String = (0..5_000)
        .map(|n| format!("def check_{n}():\n    case_sensitive()\n    case_sensitive()\n"))
        .collect();
    let list = files(&[("src/many.py", &many)]);
    let terms = looking_for(&[("casesensitive", true, 1)]);
    assert!(map(&list, &terms, &Asked::default(), later()).is_some());
    assert!(map(&list, &terms, &Asked::default(), Instant::now()).is_none());
}

/// The map stays within its limit however much matches.
#[test]
fn the_map_stays_within_the_context_limit() {
    let mut many = Vec::new();
    for n in 0..MAX_PLAIN_FILES {
        let path = format!("src/{}/module_{n}.py", "deep/".repeat(300));
        many.push((
            path,
            format!("def check_{n}():\n    case_sensitive()\n    case_sensitive()\n"),
        ));
    }
    let list: Vec<(&str, &str)> = many.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
    let text = mapped_text(&list, &[("casesensitive", true, 5)]).unwrap();
    assert!(text.len() <= MAX_MAP_CHARS, "{}", text.len());
}
