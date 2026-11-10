use super::*;
use crate::context_assistance_engine::PickedExcerpt;
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
    marked_terms(prompt)
        .into_iter()
        .map(|(term, _)| term)
        .collect()
}

fn excerpt(path: &str, text: &str) -> PickedExcerpt {
    PickedExcerpt {
        path: path.into(),
        start_line: 1,
        end_line: 3,
        text: text.into(),
    }
}

/// Once the project holds one of the names, every name the prompt writes as
/// code counts, beside its singular form, without the class it is read on:
/// a search cut short may not reach the file holding `list_entries`, and a
/// new helper such as `make_slug` holds nothing to drop. With no name held,
/// none count.
#[test]
fn named_code_counts_once_the_project_holds_some() {
    let prompt = "Fix `Parser.parse_filter_block` and add a `make_slug` helper for `list_entries`.";
    let words = terms(prompt);
    let only = |held: &str| -> Vec<usize> {
        let spelled = words.iter().map(|term| usize::from(term == held));
        spelled.collect()
    };
    let all = ["parsefilterblock", "makeslug", "listentries", "listentry"];
    let names = held_names(prompt, &words, &only("parsefilterblock"));
    assert_eq!(names, all, "{words:?}");
    assert_eq!(held_names(prompt, &words, &only("listentry")), all);
    assert!(held_names(prompt, &words, &only("")).is_empty());
    let plural = "Fix `parse_filters`.";
    let words = terms(plural);
    let names = held_names(plural, &words, &vec![1; words.len()]);
    assert!(holds("def parse_filter(source):", &names), "{names:?}");
}

/// The excerpts that are shown must hold a name, written either way: the
/// one holding it can lose to code matching more of the prompt's words, and
/// what is left is then about something else.
#[test]
fn shown_excerpts_must_hold_the_named_code() {
    let asked = "parse filter block lexer token stream line source";
    let words: Vec<String> = asked.split(' ').map(String::from).collect();
    let lexer = "def tokenize(source, line):\n    \
return lexer(stream, token)  # parse filter block";
    let picked = [
        excerpt(
            "src/parser.py",
            "def parse-filter-Block(self):\n    return self.body",
        ),
        excerpt("src/lexer.py", lexer),
    ];
    let names = vec!["parsefilterblock".to_owned()];
    let render = |picked: &[PickedExcerpt], names: &[String]| {
        super::super::render(picked, &[], &words, &[], names).map(|rendered| rendered.text)
    };
    assert_eq!(render(&picked, &names), None);
    let unnamed = render(&picked, &[]).unwrap();
    assert!(unnamed.contains("def tokenize") && !unnamed.contains("parse-filter"));
    let parser = render(&picked[..1], &names).unwrap();
    assert!(parser.contains("def parse-filter-Block"));
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
    let read = |found: &[String], held: &[String]| {
        let later = Instant::now() + Duration::from_secs(5);
        let read = super::super::read_matched;
        read(home.path(), &root, "codex", found, &words, &[], held, later)
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
