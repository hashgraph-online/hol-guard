use super::{literal_words, quoted_words};

#[test]
fn a_backslash_in_double_quotes_stays_before_an_ordinary_character() {
    let words = literal_words(r#"grep -n "staging.hol\|https://.*staging" deploy.sh"#);
    assert!(words.contains(&r"staging.hol\|https://.*staging".to_owned()));
}

#[test]
fn a_backslash_in_double_quotes_escapes_only_the_shell_specials() {
    let words = literal_words(r#"grep "a\"b\\c\$d\`e*" notes.txt"#);
    assert!(words.contains(&r#"a"b\c$d`e*"#.to_owned()));
    let words = quoted_words("grep \"one\\\ntwo\" notes.txt").expect("words");
    assert_eq!(words[1].value, "onetwo");
}

#[test]
fn a_backslash_in_single_quotes_is_an_ordinary_character() {
    let words = literal_words(r"grep 'a\|b.*\$' notes.txt");
    assert!(words.contains(&r"a\|b.*\$".to_owned()));
}

#[test]
fn a_quoted_backslash_keeps_the_glob_quoted() {
    let words = quoted_words(r#"ls "x\*" y*"#).expect("words");
    assert!(words[1].quoted_glob && !words[1].unquoted_glob);
    assert!(words[2].unquoted_glob);
}

#[test]
fn substitutions_and_unquoted_backslashes_still_yield_no_words() {
    assert!(literal_words(r#"grep "a\|$HOME*" notes.txt"#).is_empty());
    assert!(literal_words(r#"grep "a\|`id`*" notes.txt"#).is_empty());
    assert!(quoted_words(r"grep a\|b.* notes.txt").is_none());
    assert!(quoted_words(r#"grep "a\|b"#).is_none());
}

#[test]
fn a_quoted_word_sharing_text_with_an_unquoted_glob_is_left_out() {
    let words = literal_words(r#"grep -e "x\|.en*" x\|.en*"#);
    assert!(words.is_empty());
    let words = literal_words(r#"grep "x\|.en*" .en*"#);
    assert!(!words.contains(&r"x\|.en*".to_owned()));
}
