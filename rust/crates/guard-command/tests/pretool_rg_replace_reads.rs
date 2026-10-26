//! `rg -r` / `--replace` only rewrites the text `rg` prints, and grep's
//! `--include` is not an `rg` flag at all, so `rg` rejects the command line
//! before it opens a file. Neither spelling widens what a search reads, so
//! none of them sends an otherwise provable search, or a chain of them, to
//! review; the operands are still held to the same proof.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn replace_spellings_and_grep_only_filters_keep_a_provable_search_allowed() {
    let layout = layout("rg-replace");
    let child = layout.org.join("app-portal").display().to_string();
    for command in [
        format!("rg -n 'alpha|beta_gamma|delta' {child}/src/main.rs {child}/src | head -30"),
        format!("rg -n 'alpha|beta_gamma|delta' {child}/src/main.rs {child}/src -r | head -30"),
        format!("rg -n 'alpha|delta' {child}/src --replace | head -30"),
        format!("rg -n 'alpha|delta' {child}/src --replace='<x>' | head -30"),
        format!(
            "rg -rn 'a\\b|b.*c\\b' {child}/src/main.rs {child}/src/main.rs 2>/dev/null | head -10"
        ),
        format!("rg -rn 'p\\(|q' {child}/src --include='*.rs' -l | head -8"),
        format!("rg -n 'p\\(|q' {child}/src --exclude-dir=target -l | head -8"),
        format!(
            "rg -rn 'a\\b|b.*c\\b' {child}/src/main.rs {child}/src/main.rs 2>/dev/null | head -10; \
             rg -rn 'p\\(|q' {child}/src --include='*.rs' -l | head -8"
        ),
    ] {
        assert_decision(&layout.org, &layout.home, &command, true);
    }
}

#[test]
fn a_valueless_option_that_names_a_pattern_path_or_glob_stays_reviewed() {
    let layout = layout("rg-valueless");
    let child = layout.org.join("app-portal").display().to_string();
    for command in [
        format!("rg -n fixture {child}/src -e"),
        format!("rg -n fixture {child}/src --regexp"),
        format!("rg -n fixture {child}/src -f"),
        format!("rg -n fixture {child}/src -g"),
        format!("rg -n fixture {child}/src --type"),
    ] {
        assert_decision(&layout.org, &layout.home, &command, false);
    }
}

#[test]
fn replace_and_grep_only_filters_do_not_clear_the_operand_proof() {
    let layout = layout("rg-replace-negative");
    let child = layout.org.join("app-portal");
    write(child.join(".env"), "TOKEN=fixture\n");
    let child = child.display().to_string();
    for command in [
        format!("rg -n fixture {child}/.env -r | head -3"),
        format!("rg -rn fixture {child}/.env | head -3"),
        format!("rg -n fixture {child} --include='*.rs' --hidden | head -3"),
        // rg takes the next word as -r's value even when it starts with a
        // dash, so the widening flag has to follow a value to be a flag.
        format!("rg -n fixture {child}/src -r x --no-ignore | head -3"),
        format!("rg -n fixture {child}/src --include='*.rs' --pre cat | head -3"),
        "rg -n fixture ~/.ssh --include='*.pub' | head -3".to_string(),
        format!("rg -n fixture {child}/.env --include='*.rs'"),
    ] {
        assert_decision(&layout.org, &layout.home, &command, false);
    }
}
