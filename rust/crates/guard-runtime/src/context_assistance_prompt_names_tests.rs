use super::*;
use crate::context_assistance_prompt_files::{named, phrases, plain, walk};
use crate::context_assistance_prompt_words::marked_terms;
use std::time::{Duration, Instant};

const ON: &str = "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n";

const PROMPT: &str = "Something in `Parser.parse_filter_block` broke recently: a filter \
block renders wrong. Find the cause and fix it.";

const PARSER: &str = "class Parser:\n    def parse_filter_block(self):\n        \
node = self.parse_statements((\"name:endfilter\",))\n        return node\n";

const FILTERS: &str = "def do_filter(value, block):\n    \
\"\"\"Apply a filter to a block of text before it renders.\"\"\"\n    return value\n";

fn terms(prompt: &str) -> Vec<String> {
    marked_terms(prompt).into_iter().map(|(term, _)| term).collect()
}

fn excerpt(path: &str, text: &str) -> PickedExcerpt {
    PickedExcerpt {
        path: path.into(),
        start_line: 1,
        end_line: 3,
        text: text.into(),
    }
}

/// A name the project holds counts, without the class it is read on; a
/// name no file holds, such as a helper the prompt asks to add, does not.
#[test]
fn only_names_the_project_holds_count() {
    let prompt = "Fix `Parser.parse_filter_block` and add a `make_slug` helper for `list_entries`.";
    let terms = terms(prompt);
    let spelled: Vec<usize> = (terms.iter())
        .map(|term| usize::from(term != "makeslug"))
        .collect();
    let names = held_names(prompt, &terms, &spelled);
    assert_eq!(names, ["parsefilterblock", "listentries"], "{terms:?}");
    let none = vec![0; terms.len()];
    assert!(held_names(prompt, &terms, &none).is_empty());
}

/// Excerpts that hold none of the names are dropped, written either way;
/// with no names, or one excerpt holding one, all of them stay.
#[test]
fn excerpts_holding_no_named_code_are_dropped() {
    let picked = [
        excerpt("src/filters.py", FILTERS),
        excerpt("src/lexer.py", "def tokenize(source):\n    return []"),
    ];
    let names = vec!["parsefilterblock".to_owned()];
    assert!(holding(&picked, &names).is_empty());
    assert_eq!(holding(&picked, &[]).len(), 2);
    let named = [
        excerpt("src/filters.py", FILTERS),
        excerpt("src/parser.py", "def parse-filter-Block():"),
    ];
    assert_eq!(holding(&named, &names).len(), 2);
}

/// The seed this came from: the prompt names `Parser.parse_filter_block`,
/// and the file holding it could not be read, so the only excerpt left came
/// from `filters.py`, which shares the words filter and block but not the
/// code asked about. The matched files are named instead.
#[test]
fn a_read_without_the_named_code_names_the_files() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), ON).unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = plain(std::fs::canonicalize(project.path()).unwrap());
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/parser.py"), PARSER).unwrap();
    std::fs::write(root.join("src/filters.py"), FILTERS).unwrap();
    let words = terms(PROMPT);
    let searched = walk(
        &root,
        &words,
        &phrases(PROMPT),
        &named(PROMPT),
        Duration::from_secs(5),
    );
    let found = searched.found(&words);
    assert!(found.contains(&"src/parser.py".to_owned()), "{found:?}");
    let names = held_names(PROMPT, &words, &searched.spelled);
    assert_eq!(names, ["parsefilterblock"]);
    let read = |found: &[String], names: &[String]| {
        let later = Instant::now() + Duration::from_secs(5);
        super::super::read_matched(home.path(), &root, "codex", (found, names), &words, &[], later)
            .unwrap()
            .text
    };
    let filters = ["src/filters.py".to_owned()];
    let text = read(&filters, &names);
    assert!(text.starts_with(super::super::MATCHED_HEADER), "{text}");
    assert!(!text.contains("def do_filter"), "{text}");
    // Without the name the same read shows the unrelated code.
    assert!(read(&filters, &[]).contains("def do_filter"));
    // The file that holds it is still shown when it can be read.
    assert!(read(&found, &names).contains("def parse_filter_block"));
}
