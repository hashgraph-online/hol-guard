//! Small literal scanners matching the Python common-CLI helper contracts.

use crate::command_option_parsing::{python_is_alphanumeric, python_is_whitespace};

pub(super) fn basename(value: Option<&str>) -> String {
    value
        .unwrap_or_default()
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

pub(super) fn is_executable(basename: &str, executable: &str) -> bool {
    basename == executable
        || basename.strip_suffix(".cmd") == Some(executable)
        || basename.strip_suffix(".exe") == Some(executable)
}

pub(super) fn has_any(arguments: &[String], values: &[&str]) -> bool {
    arguments.iter().any(|argument| {
        let lowered = argument.to_lowercase();
        let name = lowered
            .split_once('=')
            .map_or(lowered.as_str(), |(name, _)| name);
        values.contains(&name)
    })
}

pub(super) fn option_values<'a>(
    arguments: &'a [String],
    long_name: &str,
    short_name: &str,
) -> Vec<&'a str> {
    let mut values = Vec::new();
    let mut index = 0;
    let long_assignment = format!("{long_name}=");
    let short_characters = short_name.chars().count();
    while index < arguments.len() {
        let argument = &arguments[index];
        let lowered = argument.to_lowercase();
        if (lowered == long_name || lowered == short_name) && index + 1 < arguments.len() {
            values.push(arguments[index + 1].as_str());
            index += 2;
            continue;
        }
        if lowered.starts_with(&long_assignment) {
            // Equality was established on the lowered token; slicing still
            // uses the original token, as in the Python helper.
            if let Some((_, value)) = argument.split_once('=') {
                values.push(value);
            }
        } else if lowered.starts_with(short_name) && lowered != short_name {
            let start = argument
                .char_indices()
                .nth(short_characters)
                .map_or(argument.len(), |(index, _)| index);
            let value = &argument[start..];
            let value = value.strip_prefix('=').unwrap_or(value);
            if !value.is_empty() {
                values.push(value);
            }
        }
        index += 1;
    }
    values
}

pub(super) fn normalized_words(value: &str) -> String {
    value
        .to_lowercase()
        .split(python_is_whitespace)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Exact bounded equivalent of `(?:^|;)\s*(alter|delete|drop|truncate|update)\b`
/// with Python Unicode whitespace/word categories and case-insensitive ASCII
/// keywords. This is the existing literal detector, not a SQL grammar.
pub(super) fn sql_mutation(value: &str) -> bool {
    value
        .trim_matches(python_is_whitespace)
        .split(';')
        .any(|statement| {
            let statement = statement.trim_start_matches(python_is_whitespace);
            ["alter", "delete", "drop", "truncate", "update"]
                .iter()
                .any(|keyword| {
                    if !statement
                        .get(..keyword.len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(keyword))
                    {
                        return false;
                    }
                    statement[keyword.len()..]
                        .chars()
                        .next()
                        .is_none_or(|character| {
                            character != '_' && !python_is_alphanumeric(character)
                        })
                })
        })
}
