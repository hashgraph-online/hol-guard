//! `search_glob_pattern_is_safe` on the recursive and alternation spellings a
//! search tool accepts. The recorded Python parity vectors in
//! `sfrs_token_vectors` cover the spellings that predate them.

use crate::shell_secret_read_support::search_glob_pattern_is_safe;

fn safe(pattern: &str) -> bool {
    search_glob_pattern_is_safe(pattern, None)
}

#[test]
fn recursive_and_alternation_globs_reach_ordinary_sources() {
    // `rg -g '**/*.{md,yml}'` is how a search is narrowed to a file type
    // across a tree. Every spelling it stands for names ordinary sources.
    assert!(safe("**/*.{md,yml,yaml,sh}"));
    assert!(safe("**/*.md"));
    assert!(safe("src/**/*.rs"));
    assert!(safe("*.{ts,tsx}"));
    assert!(safe("{src,tests}/**/*.py"));
}

#[test]
fn an_expanded_spelling_is_screened_like_any_other() {
    // The screen reads the names around `**`, so a sensitive one still stops
    // the pattern however it is spelled.
    assert!(!safe("**/.ssh/*"));
    assert!(!safe("**/.env"));
    assert!(!safe("**/credentials"));
    assert!(!safe("**/{src,.ssh}/*.md"));
    assert!(!safe("{src,.aws}/**/*.py"));
}

#[test]
fn a_pattern_of_only_recursion_names_everything() {
    assert!(!safe("**"));
    assert!(!safe("**/**"));
    // A single `*` is a name pattern that matches every sensitive name, which
    // the component screen has always refused.
    assert!(!safe("**/*"));
}

#[test]
fn a_trailing_recursion_names_every_file_under_a_directory() {
    // `src/**` selects `src/credentials.json` as readily as `src/*` does, and
    // the component screen has always refused `src/*`. Only the recursion
    // that stands between two named components is a run of directories.
    assert!(!safe("src/**"));
    assert!(!safe("src/sub/**"));
    assert!(!safe("{src,tests}/**"));
    assert!(safe("src/**/*.rs"));
    assert!(safe("src/**/main.rs"));
}

#[test]
fn braces_outside_a_filename_pattern_stay_refused() {
    // jq filters, GraphQL documents and `sed` expressions reach this screen as
    // operands. None of them is a glob, and expansion must not admit them.
    assert!(!safe("{tests: .tests, total: .total}"));
    assert!(!safe("TagSet=[{Key=env,Value=prod}]"));
    assert!(!safe(r"s/old\{1,2\}/new/g"));
    assert!(!safe("[.data.viewer | {login, name}]"));
    assert!(!safe("${GH:-gh}"));
    assert!(!safe("{}"));
    assert!(!safe("{"));
    assert!(!safe("}"));
    assert!(!safe("a{b"));
    assert!(!safe("{a}"));
    assert!(!safe("{a,}"));
}

#[test]
fn expansion_stays_bounded() {
    // Three groups exceed the brace-group bound, and two wide groups exceed
    // the spelling bound; both are refused rather than expanded.
    assert!(!safe("{a,b}/{c,d}/{e,f}/x.md"));
    assert!(!safe("{a,b,c,d,e,f,g,h,i}/{a,b,c,d,e,f,g,h}/x.md"));
    assert!(safe("{a,b}/{c,d}/x.md"));
}

#[test]
fn an_exclusion_keeps_its_plain_spelling() {
    // An exclusion is admitted without reading its components, so it is not
    // given recursion or alternation.
    assert!(safe("!*.map"));
    assert!(!safe("!**/*.map"));
    assert!(!safe("!*.{map,min.js}"));
}
