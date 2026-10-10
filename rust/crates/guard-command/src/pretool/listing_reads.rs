//! `ls` operands, including recursion, quoted literals and globs.
//!
//! The parser hands over unquoted words, so a bracket in an argument cannot
//! say whether the shell treats it as a glob. The segment text can: a word
//! whose glob characters are all inside quotes is a literal name (Next.js
//! route directories such as `[slug]`), while an unquoted `*`, `?` or `[` is
//! expanded by the proof itself and every match is checked.

use super::{safe_reads, search};

struct Word {
    value: String,
    unquoted_glob: bool,
    quoted_glob: bool,
}

/// Split segment text into shell words, tracking where glob characters sit.
/// `None` for anything beyond plain words and simple quotes, which makes the
/// caller treat every glob character as unquoted.
fn quoted_words(text: &str) -> Option<Vec<Word>> {
    let mut words = Vec::new();
    let mut current: Option<Word> = None;
    let mut quote: Option<char> = None;
    for character in text.chars() {
        match quote {
            Some(open) if character == open => quote = None,
            Some(open) => {
                if character == '\\' || (open == '"' && matches!(character, '$' | '`')) {
                    return None;
                }
                let word = current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                });
                word.quoted_glob |= matches!(character, '*' | '?' | '[');
                word.value.push(character);
            }
            None if matches!(character, '\'' | '"') => {
                quote = Some(character);
                current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                });
            }
            None if character == '\\' => return None,
            None if character.is_whitespace() => words.extend(current.take()),
            None => {
                let word = current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                });
                word.unquoted_glob |= matches!(character, '*' | '?' | '[');
                word.value.push(character);
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    words.extend(current);
    Some(words)
}

enum Operand {
    Plain,
    QuotedLiteral,
    Glob,
}

fn classify_operands(text: &str, arguments: &[String]) -> Option<Vec<Operand>> {
    let words = quoted_words(text)?;
    let (_, rest) = words.split_first()?;
    if rest.len() != arguments.len()
        || rest
            .iter()
            .zip(arguments)
            .any(|(word, argument)| word.value != *argument)
    {
        return None;
    }
    rest.iter()
        .map(|word| match (word.unquoted_glob, word.quoted_glob) {
            (false, false) => Some(Operand::Plain),
            (false, true) => Some(Operand::QuotedLiteral),
            (true, false) => Some(Operand::Glob),
            (true, true) => None,
        })
        .collect()
}

pub(super) fn safe_listing_segment(
    text: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let recursive = arguments.iter().any(|argument| is_recursive_flag(argument));
    if !recursive
        && !arguments
            .iter()
            .any(|argument| !argument.starts_with('-') && argument.contains(['*', '?', '[']))
    {
        return safe_reads::safe_listing_arguments(arguments, context);
    }
    if arguments.iter().any(|argument| follows_links(argument)) && recursive {
        return false;
    }
    // Without a trustworthy quote map every glob character counts as unquoted.
    let kinds = classify_operands(text, arguments);
    let mut operands = 0_usize;
    for (index, argument) in arguments.iter().enumerate() {
        if argument == "-" {
            return false;
        }
        if argument.starts_with('-') {
            continue;
        }
        operands += 1;
        let kind = match &kinds {
            Some(kinds) => &kinds[index],
            None if argument.contains(['*', '?', '[']) => &Operand::Glob,
            None => &Operand::Plain,
        };
        let allowed = match kind {
            Operand::Plain if recursive => search::safe_recursive_target(argument, context),
            Operand::Plain => {
                safe_reads::bounded_read_target(argument, context.home_dir, context.cwd, true)
            }
            Operand::QuotedLiteral => {
                search::safe_literal_bracket_tree(argument, context, recursive)
            }
            Operand::Glob => search::safe_glob_operand(argument, context, recursive),
        };
        if !allowed {
            return false;
        }
    }
    // A recursive listing without an operand walks the working directory.
    operands > 0 || !recursive || search::safe_recursive_target(".", context)
}

fn is_recursive_flag(argument: &str) -> bool {
    // GNU getopt accepts any unambiguous prefix (`--rec`), so treat them all as recursive.
    argument.strip_prefix("--").is_some_and(|name| {
        name.len() >= 2 && "recursive".starts_with(name.split('=').next().unwrap_or(name))
    }) || (argument.starts_with('-') && !argument.starts_with("--") && argument.contains('R'))
}

fn follows_links(argument: &str) -> bool {
    matches!(
        argument,
        "--dereference"
            | "--dereference-command-line"
            | "--dereference-command-line-symlink-to-dir"
    ) || (argument.starts_with('-') && !argument.starts_with("--") && argument.contains(['L', 'H']))
}
