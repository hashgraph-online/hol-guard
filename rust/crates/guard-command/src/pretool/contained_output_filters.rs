//! Output filters after a contained core: `| head -N`, `| tail -N` and a
//! `grep` that only reads its standard input, chained up to three deep.
//!
//! The execution sink (`contained_output_filters.py`) peels the same chain,
//! runs the core contained and applies the filters to its captured output.
//! A filter that names a file, reads patterns from one, recurses or writes
//! anywhere is not a filter here, so the whole command keeps its review.
use crate::CommandSegmentV1;

/// The longest chain the sink applies.
pub(super) const MAX_FILTERS: usize = 3;

/// Single-letter `grep` switches that change only which lines of standard
/// input are printed and how. Recursion (`-r`), pattern files (`-f`), file
/// listings (`-l`), and every option the sink does not apply are absent.
const GREP_SWITCHES: &str = "EFGacinosvwx";

/// `grep` options that take a line count.
const GREP_COUNTS: &[&str] = &["-A", "-B", "-C", "-m"];

fn bounded_count(value: &str) -> bool {
    !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `segment` is one filter stage whose source text is `source`.
pub(super) fn filter_stage(segment: &CommandSegmentV1, source: &str) -> bool {
    if !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || !plain_source(source)
    {
        return false;
    }
    match segment.executable.as_deref() {
        Some("head" | "tail") => head_tail_arguments(&segment.arguments),
        Some("grep" | "egrep" | "fgrep") => grep_arguments(&segment.arguments),
        _ => false,
    }
}

pub(super) fn head_tail_arguments(arguments: &[String]) -> bool {
    match arguments {
        [count] => count.strip_prefix('-').is_some_and(bounded_count),
        [flag, count] => flag == "-n" && bounded_count(count),
        _ => false,
    }
}

/// `grep` that reads only standard input: switches from `GREP_SWITCHES`,
/// counted options, `-e PATTERN`, and one pattern operand unless `-e` gave
/// the patterns. Any further operand is a file, so it is refused.
pub(super) fn grep_arguments(arguments: &[String]) -> bool {
    let mut expressions = 0usize;
    let mut operands = 0usize;
    let mut options_done = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if argument == "-" {
            return false;
        }
        if options_done || !argument.starts_with('-') {
            operands += 1;
            continue;
        }
        if argument == "--" {
            options_done = true;
            continue;
        }
        if argument == "-e" {
            if index >= arguments.len() {
                return false;
            }
            index += 1;
            expressions += 1;
            continue;
        }
        if let Some(attached) = GREP_COUNTS
            .iter()
            .find_map(|option| argument.strip_prefix(*option))
        {
            let count = if attached.is_empty() {
                index += 1;
                match arguments.get(index - 1) {
                    Some(count) => count.as_str(),
                    None => return false,
                }
            } else {
                attached
            };
            if !bounded_count(count) {
                return false;
            }
            continue;
        }
        let switches = argument.strip_prefix('-').unwrap_or_default();
        if switches.is_empty() || !switches.chars().all(|flag| GREP_SWITCHES.contains(flag)) {
            return false;
        }
    }
    if expressions > 0 {
        operands == 0
    } else {
        operands == 1
    }
}

/// Plain words the sink lexes into the same arguments: no `$` or backquote
/// anywhere, no control character but a tab, and outside quotes only word
/// characters and blanks. Globs, braces, `~`, escapes, redirects and
/// operators all leave the filter to review.
pub(super) fn plain_source(source: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut chars = source.chars();
    while let Some(current) = chars.next() {
        if matches!(current, '$' | '`') || (current.is_control() && current != '\t') {
            return false;
        }
        match quote {
            Some('\'') => {
                if current == '\'' {
                    quote = None;
                }
            }
            Some(_) => match current {
                '"' => quote = None,
                '\\' => match chars.next() {
                    Some(next) if !matches!(next, '$' | '`') && !next.is_control() => {}
                    _ => return false,
                },
                _ => {}
            },
            None => match current {
                '\'' | '"' => quote = Some(current),
                ' ' | '\t' | '-' | '_' | '.' | ',' | ':' | '/' | '=' | '+' | '@' | '%' | '^' => {}
                _ if current.is_ascii_alphanumeric() => {}
                _ => return false,
            },
        }
    }
    quote.is_none()
}

#[cfg(test)]
mod tests {
    use super::{grep_arguments, plain_source};

    fn words(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn grep_reading_standard_input_is_a_filter() {
        for arguments in [
            &["FAIL"][..],
            &["-B", "3", "at async createViteServer"],
            &["-E", "FAIL|Error"],
            &["-i", "error"],
            &["-inv", "-A2", "-m", "5", "x"],
            &["-e", "FAIL", "-e", "Error"],
            &["--", "-x"],
        ] {
            assert!(grep_arguments(&words(arguments)), "{arguments:?}");
        }
    }

    #[test]
    fn grep_naming_a_file_or_reading_patterns_is_not_a_filter() {
        for arguments in [
            &[][..],
            &["x", "notes.txt"],
            &["x", "/home/user/.aws/credentials"],
            &["-f", "/home/user/.ssh/id_rsa"],
            &["--file=/home/user/.ssh/id_rsa", "x"],
            &["-r", "x", "/etc"],
            &["-rn", "x"],
            &["-l", "x"],
            &["-P", "x"],
            &["-e", "x", "notes.txt"],
            &["-e"],
            &["-A", "x", "y"],
            &["-B"],
            &["-m", "1234567", "x"],
            &["-iA3", "x"],
            &["-", "x"],
            &["--color=always", "x"],
        ] {
            assert!(!grep_arguments(&words(arguments)), "{arguments:?}");
        }
    }

    #[test]
    fn only_plain_quoted_words_are_lexed_alike() {
        for source in [
            "grep FAIL",
            "grep -B 3 \"at async createViteServer\"",
            "grep -E 'FAIL|Error'",
            "grep \"x\\|y\"",
            "head -8",
        ] {
            assert!(plain_source(source), "{source}");
        }
        for source in [
            "grep a[bc]",
            "grep x*",
            "grep ~/.ssh",
            "grep \"$HOME\"",
            "grep '$x'",
            "grep `id`",
            "grep x > out.txt",
            "grep x 2>&1",
            "grep x\\ y",
            "grep 'unterminated",
            "grep {a,b}",
            "grep x;",
            "grep \"a\nb\"",
        ] {
            assert!(!plain_source(source), "{source}");
        }
    }
}
