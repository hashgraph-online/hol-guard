//! Reads of awk's input list.
//!
//! awk opens the next file by reading `ARGV[ARGC-1]`, so a program that
//! writes an `ARGV` entry or raises `ARGC` reads a file no one named on the
//! command line. A program that only reads them is as bounded as one that
//! prints `FILENAME`: `FILENAME == ARGV[2] { print }` picks lines from the
//! second file the command already names.
//!
//! The check reads code only, with string literals, regular expressions and
//! comments already blanked. Each use has to be one of:
//!
//! * `ARGV[...]` used as a value: not assigned, incremented, decremented or
//!   deleted, and not the target of `sub` or `gsub`;
//! * `ARGC` used as a value the same way.
//!
//! Bare `ARGV` is refused, since that is how the whole array reaches
//! `split`, `match`, `asort`, a `for (... in ARGV)` loop or a user function
//! that can write it. A program that names `sub` or `gsub` beside either word
//! is refused outright rather than parsing which argument each call edits.

/// The names awk keeps its input list in.
pub(super) const INPUT_LIST: &[&str] = &["ARGV", "ARGC"];

/// What may sit between a name and the operator that writes it. A trailing
/// `\` continues the line, so `ARGV[1] \` and a `= "x"` on the next line are
/// still one assignment; the newline itself is skipped too, which only
/// refuses more.
const SPACE: &[char] = &[' ', '\t', '\\', '\n', '\r'];

/// Functions that write their last argument in place.
const IN_PLACE_EDITS: &[&str] = &["sub", "gsub"];

/// Operators that write the value to their left.
const WRITES_AFTER: &[&str] = &["++", "--", "+=", "-=", "*=", "/=", "%=", "^=", "**="];

/// Whether every use of `ARGV` and `ARGC` in `code` only reads it.
pub(super) fn reads_only(code: &str) -> bool {
    let words = words(code);
    if !words.iter().any(|(_, word)| INPUT_LIST.contains(word)) {
        return true;
    }
    if words.iter().any(|(_, word)| IN_PLACE_EDITS.contains(word)) {
        return false;
    }
    words.iter().enumerate().all(|(position, (start, word))| {
        if !INPUT_LIST.contains(word) {
            return true;
        }
        let previous = position.checked_sub(1).map(|index| words[index]);
        let before = code[..*start].trim_end_matches(SPACE);
        if before.ends_with("++")
            || before.ends_with("--")
            || previous.is_some_and(|(previous_start, previous_word)| {
                previous_word == "delete"
                    && code[previous_start + previous_word.len()..*start]
                        .trim_matches(SPACE)
                        .is_empty()
            })
        {
            return false;
        }
        let mut end = start + word.len();
        if *word == "ARGV" {
            let Some(close) = subscript_end(code, end) else {
                return false;
            };
            end = close;
        }
        value_use(&code[end..])
    })
}

/// Each name or number in `code` with the byte offset it starts at.
fn words(code: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let mut start = None;
    for (index, character) in code.char_indices().chain([(code.len(), ' ')]) {
        let part = character.is_ascii_alphanumeric() || character == '_';
        match (start, part) {
            (None, true) => start = Some(index),
            (Some(begin), false) => {
                words.push((begin, &code[begin..index]));
                start = None;
            }
            _ => {}
        }
    }
    words
}

/// The index just past the `]` closing the subscript that opens right at
/// `start`, or `None` when no `[` opens there.
fn subscript_end(code: &str, start: usize) -> Option<usize> {
    if !code[start..].starts_with('[') {
        return None;
    }
    let mut depth = 0usize;
    for (offset, character) in code[start..].char_indices() {
        match character {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start + offset + 1);
                }
            }
            '\n' => return None,
            _ => {}
        }
    }
    None
}

/// Whether the code after a use leaves it a value: no assignment or
/// increment follows, and it is not the loop variable of `for (... in ...)`.
fn value_use(after: &str) -> bool {
    let rest = after.trim_start_matches(SPACE);
    if rest.starts_with("==") {
        return true;
    }
    !(rest.starts_with('=')
        || WRITES_AFTER
            .iter()
            .any(|operator| rest.starts_with(operator))
        || rest
            .strip_prefix("in")
            .is_some_and(|tail| !tail.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')))
}

#[cfg(test)]
mod tests {
    use super::reads_only;

    #[test]
    fn reading_the_input_list_is_a_value_use() {
        for code in [
            "FILENAME==ARGV[3]{print}",
            "FILENAME == ARGV[2] { now[$1] = 1 }",
            "NR==FNR{was[$1]=1; next} ($1 in was)==0 && FILENAME==ARGV[3]{print \" \" $0} FILENAME==ARGV[2]{now[$1]=1} END{}",
            "BEGIN { for (i = 1; i < ARGC; i++) print ARGV[i] }",
            "FILENAME != ARGV[1] { print }",
            "{ print ARGV[ARGC - 1] }",
            "{ print ARGV[a[1]] }",
            "{ n = (ARGC == 3) }",
            "{ print }",
            "BEGIN { print ARGV[1] \" \" ARGV[2] }",
        ] {
            assert!(reads_only(code), "{code}");
        }
    }

    #[test]
    fn writing_the_input_list_is_refused() {
        for code in [
            "BEGIN { ARGV[1] = \" \" } {print}",
            "BEGIN { ARGV[1]=\" \" } {print}",
            "BEGIN { ARGV[ARGC++] = \" \" } {print}",
            "BEGIN { ARGC = 5 } {print}",
            "BEGIN { ARGC += 1 } {print}",
            "BEGIN { ARGC++ } {print}",
            "BEGIN { ++ARGC } {print}",
            "BEGIN { --ARGC } {print}",
            "BEGIN { ARGV[1] \\\n = \" \" } {print}",
            "BEGIN { ++ \\\n ARGC } {print}",
            "BEGIN { delete \\\n ARGV[1] } {print}",
            "BEGIN { ARGV[1] ^= 1 } {print}",
            "BEGIN { ARGV[1]++ } {print}",
            "BEGIN { delete ARGV[1] } {print}",
            "BEGIN { delete ARGV } {print}",
            "BEGIN { sub(/x/, \" \", ARGV[1]) } {print}",
            "BEGIN { gsub(/x/, \" \", ARGV[1]) } {print}",
            "BEGIN { split(\" \", ARGV) } {print}",
            "function f(a) { a[1] = \" \" } BEGIN { f(ARGV) } {print}",
            "BEGIN { for (k in ARGV) print k }",
            "BEGIN { for (ARGC in seen) print }",
            "BEGIN { ARGV [1] = \" \" } {print}",
            "BEGIN { ARGV[1\n] = \" \" } {print}",
        ] {
            assert!(!reads_only(code), "{code}");
        }
    }
}
