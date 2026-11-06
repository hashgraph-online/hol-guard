use super::*;
use crate::context_assistance_prompt_files::{plain, walk};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const CORE: &str = "import os


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
/// marked when the prompt wrote it as a name, is in that many files.
fn looking_for(terms: &[(&str, bool, usize)]) -> Vec<Sought> {
    let walk = Walk {
        checked: 200,
        holding: terms.iter().map(|(_, _, holding)| *holding).collect(),
        ..Walk::default()
    };
    let terms: Vec<(String, bool)> = terms
        .iter()
        .map(|(term, name, _)| ((*term).to_owned(), *name))
        .collect();
    sought(&walk, &terms, &[])
}

fn files(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
        .collect()
}

fn later() -> Instant {
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

/// The definition that holds the prompt's names is listed by its lines, and
/// the class around it with its members' lines, so the agent opens just the
/// method it needs. No code is pasted.
#[test]
fn the_definition_holding_the_prompts_names_and_its_class_are_listed() {
    let terms = looking_for(&[("casesensitive", true, 2), ("choice", false, 30)]);
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
        text.contains("src/core.py:7-9 def __init__(self, choices, case_sensitive=True):"),
        "{text}"
    );
    assert!(
        text.contains(
            "src/core.py:4-14 class Choice(ParamType):\n  members: __init__ 7-9, convert 11-14"
        ),
        "{text}"
    );
    assert!(!text.contains("def other"), "{text}");
    assert!(!text.contains("```"), "{text}");
    assert!(mapped.shown.is_empty());
}

/// A long function that mentions everything comes after the short one the
/// prompt names.
#[test]
fn a_long_function_that_mentions_the_words_does_not_outrank_the_named_one() {
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
    let short = text.find("src/short.py:1-2 def choice():").unwrap();
    let long = text.find("src/long.py:1-301 def handle").unwrap();
    assert!(short < long, "{text}");
}

/// Source comes first, then a few tests, then docs, and a changelog gives
/// its newest section, where an entry for the change belongs.
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
    let text = mapped_text(
        &[
            ("CHANGES.rst", changes),
            ("docs/options.rst", docs),
            ("tests/test_core.py", &tests),
            ("src/core.py", CORE),
        ],
        &[("casesensitive", true, 4)],
    )
    .unwrap();
    let map = text.split(MAP_TITLE).nth(1).unwrap();
    let listed: Vec<&str> = map
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .collect();
    let test_lines = listed
        .iter()
        .filter(|line| line.starts_with("tests/"))
        .count();
    assert_eq!(test_lines, 3, "{text}");
    let at = |prefix: &str| {
        listed
            .iter()
            .position(|line| line.starts_with(prefix))
            .unwrap()
    };
    assert!(at("src/core.py") < at("tests/"), "{text}");
    assert!(at("tests/") < at("docs/options.rst:1-4"), "{text}");
    assert_eq!(
        listed.last().unwrap(),
        &"CHANGES.rst:4-8 Unreleased",
        "{text}"
    );
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

/// A plain word in many files places nothing, unless a file read defines it.
#[test]
fn a_common_plain_word_places_nothing_unless_a_file_defines_it() {
    let uses = "def read():\n    token = 1\n    return token\n";
    let terms = [("token", false, 50)];
    assert_eq!(mapped_text(&[("src/read.py", uses)], &terms), None);
    let defines = "class Token:\n    pass\n";
    let text = mapped_text(&[("src/read.py", uses), ("src/token.py", defines)], &terms).unwrap();
    assert!(text.contains("src/token.py (lines 1-2)"), "{text}");
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
    let history = "def history_entry():\n    return case_sensitive\n";
    let text = mapped_text(
        &[("src/history.py", history)],
        &[("casesensitive", true, 1)],
    )
    .unwrap();
    assert!(text.contains("src/history.py (lines 1-2)"), "{text}");
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
        named: vec!["CHANGES.rst".into()],
    };
    let named = map(&list, &terms, &asked, later()).unwrap();
    assert!(
        named.text.contains("CHANGES.rst:4-7 Unreleased"),
        "{}",
        named.text
    );
}

/// The map gives up once its time is up, however big the files.
#[test]
fn the_map_stops_at_its_deadline() {
    let many: String = (0..5_000)
        .map(|n| format!("def case_sensitive_{n}():\n    case_sensitive()\n"))
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
    for n in 0..60 {
        let path = format!("src/{}/module_{n}.py", "deep/".repeat(300));
        many.push((
            path,
            format!("def case_sensitive_{n}():\n    case_sensitive()\n"),
        ));
    }
    let list: Vec<(&str, &str)> = many.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
    let text = mapped_text(&list, &[("casesensitive", true, 60)]).unwrap();
    assert!(text.len() <= MAX_MAP_CHARS, "{}", text.len());
}

const ON: &str = "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n";

/// A Guard home with `config`, and a project holding `list`.
fn project(config: &str, list: &[(&str, &str)]) -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
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

fn prompt_map(home: &Path, root: &Path, prompt: &str) -> Option<String> {
    let terms = crate::context_assistance_prompt_words::marked_terms(prompt);
    let words: Vec<String> = terms.iter().map(|(term, _)| term.clone()).collect();
    let quoted = crate::context_assistance_prompt_files::phrases(prompt);
    let found = walk(root, &words, &quoted, &[], Duration::from_secs(5));
    let until = Instant::now() + Duration::from_secs(5);
    mapped(home, root, "codex", &found, &terms, &quoted, prompt, until).map(|r| r.text)
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
    assert!(!text.contains("```"), "{text}");
    assert!(
        text.contains("tests/test_core.py:1-2 def test_choice"),
        "{text}"
    );
    assert!(!text.contains("signing.py"), "{text}");
    let (home, _project, root) = project("", &list);
    assert_eq!(prompt_map(home.path(), &root, prompt), None);
}
