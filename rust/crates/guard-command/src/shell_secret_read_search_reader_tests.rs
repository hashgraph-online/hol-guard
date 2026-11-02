//! `ag` and `ack` are search tools: their first non-option word is a pattern.
//!
//! Both sat in `OTHER_READERS`, where every non-option word becomes a path
//! candidate, so `ag private_key src/` classified its own pattern as a wallet
//! key file and escalated an ordinary code search to a sensitive-access
//! review. Neither tool is modelled as a command, so the segment stays
//! unmodelled and the search is reviewed either way; what the fix changes is
//! the reason, from `native_sensitive_access_review` back to the ordinary
//! review floor. The benign gate records only allow or not-allow, so it cannot
//! see that shift, and the operand reader is pinned here instead.
use crate::shell_secret_read_support::{
    direct_secret_read_paths_from_tokens, search_args_expand_hidden_files,
    shell_segment_file_operand_tokens, OTHER_READERS, SEARCH_READERS,
};

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn secret_paths(values: &[&str]) -> Vec<String> {
    direct_secret_read_paths_from_tokens(&words(values), None, None)
}

#[test]
fn search_pattern_is_not_a_path_candidate() {
    assert!(secret_paths(&["ag", "private_key", "src/"]).is_empty());
    assert!(secret_paths(&["ack", "wallet-key", "."]).is_empty());
    assert!(secret_paths(&["ag", "-l", "privatekey", "src/"]).is_empty());
    // The spelling the rest of the family already answered this way.
    assert!(secret_paths(&["grep", "-rn", "private_key", "src/"]).is_empty());
}

#[test]
fn search_operand_is_still_read() {
    assert!(!secret_paths(&["ag", "token", "/home/dev/.ssh/id_rsa"]).is_empty());
    assert!(!secret_paths(&["ack", "token", "/home/dev/.aws/credentials"]).is_empty());
}

#[test]
fn boolean_short_options_do_not_swallow_an_operand() {
    // `-t` is `--all-text` and `-f` is `--follow` in `ag`, so neither takes a
    // value; the shared rg-shaped table used to eat the next word and read the
    // key path as the pattern.
    assert!(!secret_paths(&["ag", "-t", ".", "/home/dev/.ssh/id_rsa"]).is_empty());
    assert!(!secret_paths(&["ag", "-f", "token", "/home/dev/.ssh/id_rsa"]).is_empty());
    // `ack -f` lists files and takes no pattern at all.
    assert!(!secret_paths(&["ack", "-f", "/home/dev/.aws/credentials"]).is_empty());
    // `rg -t` still takes its type name.
    assert!(secret_paths(&["rg", "-t", "rust", "private_key", "src/"]).is_empty());
}

#[test]
fn file_name_search_carries_its_own_pattern() {
    // `-g` searches file names, so the word after its value is already a path.
    assert!(!secret_paths(&["ag", "-g", "id_", "/home/dev/.ssh/id_rsa"]).is_empty());
    assert!(secret_paths(&["ag", "-g", "private_key", "src/"]).is_empty());
}

#[test]
fn search_readers_read_their_operands() {
    assert_eq!(
        shell_segment_file_operand_tokens(&words(&["ag", "private_key", "src/"])),
        words(&["src/"])
    );
    assert_eq!(
        shell_segment_file_operand_tokens(&words(&["ack", "private_key", "src/"])),
        words(&["src/"])
    );
}

#[test]
fn search_readers_are_not_blanket_readers() {
    for name in ["ag", "ack"] {
        assert!(SEARCH_READERS.contains(&name));
        assert!(!OTHER_READERS.contains(&name));
    }
}

#[test]
fn unrestricted_search_expands_hidden_files() {
    assert!(search_args_expand_hidden_files(
        "ag",
        &words(&["--hidden", "token", "src/"])
    ));
    assert!(search_args_expand_hidden_files(
        "ag",
        &words(&["-u", "token", "src/"])
    ));
    assert!(search_args_expand_hidden_files(
        "ack",
        &words(&["--unrestricted", "token", "src/"])
    ));
    assert!(!search_args_expand_hidden_files(
        "ag",
        &words(&["-l", "token", "src/"])
    ));
    assert!(!search_args_expand_hidden_files(
        "ack",
        &words(&["--", "-u"])
    ));
}
