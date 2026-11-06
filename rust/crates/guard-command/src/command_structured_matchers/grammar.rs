//! Distinct Python option grammars used by the specialized matchers.

use std::collections::BTreeSet;

use crate::command_option_parsing::{python_is_alphanumeric, python_is_whitespace};

use super::{lowercase, normalize_option_token, python_trim};

pub(crate) fn leading_flags_and_operands<'a>(
    arguments: &'a [String],
    options_with_values: &BTreeSet<String>,
) -> Result<(BTreeSet<String>, &'a [String]), &'static str> {
    let mut flags = BTreeSet::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            index += 1;
            break;
        }
        if !argument.starts_with('-') || argument == "-" {
            break;
        }
        let option_name = normalize_option_token(argument.split('=').next().unwrap_or(""))?;
        flags.insert(option_name.clone());
        let is_short = !argument.starts_with("--");
        let short_option = if is_short {
            argument.chars().take(2).collect()
        } else {
            option_name.clone()
        };
        let mut clustered_value_option = false;
        let mut clustered_value_attached = false;
        // The initial '-' is ASCII, so its byte boundary is known. Remaining
        // offsets are character boundaries, matching Python's string slicing.
        let has_cluster = is_short && argument.chars().nth(2).is_some();
        if has_cluster {
            for (offset, character) in argument.char_indices().skip(1) {
                if !python_is_alphanumeric(character) {
                    break;
                }
                let flag = format!("-{character}");
                flags.insert(flag.clone());
                if options_with_values.contains(&flag) {
                    clustered_value_option = true;
                    clustered_value_attached = offset + character.len_utf8() < argument.len();
                    break;
                }
            }
        }
        let takes_value = options_with_values.contains(&option_name)
            || options_with_values.contains(&short_option)
            || clustered_value_option;
        let has_attached_value = argument.contains('=')
            || (has_cluster && options_with_values.contains(&short_option))
            || clustered_value_attached;
        if takes_value && !has_attached_value {
            index += 1;
        }
        index += 1;
    }
    Ok((flags, &arguments[index.min(arguments.len())..]))
}

pub(super) fn option_values<'a>(
    arguments: &'a [String],
    option_names: &BTreeSet<String>,
    ordered_options: &[String],
    cluster_options_with_values: &BTreeSet<String>,
) -> Vec<&'a str> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        let matched_option = ordered_options
            .iter()
            .find(|option| argument.starts_with(option.as_str()));
        let clustered_match = clustered_short_value(argument, cluster_options_with_values);
        let Some(matched_option) = matched_option else {
            if let Some((option, value)) = clustered_match {
                if option_names.contains(&option) {
                    if !value.is_empty() {
                        values.push(value);
                    } else if let Some(value) = arguments.get(index + 1) {
                        values.push(value);
                        index += 2;
                        continue;
                    }
                }
            }
            index += 1;
            continue;
        };
        if argument == matched_option {
            if let Some(value) = arguments.get(index + 1) {
                values.push(value);
                index += 2;
                continue;
            }
        } else {
            let suffix = &argument[matched_option.len()..];
            if let Some(value) = suffix.strip_prefix('=') {
                values.push(value);
            } else if matched_option.starts_with('-') && !matched_option.starts_with("--") {
                values.push(suffix);
            }
        }
        index += 1;
    }
    values
}

pub(crate) fn operands_without_options<'a>(
    arguments: &'a [String],
    options_with_values: &BTreeSet<String>,
) -> Result<Vec<&'a str>, &'static str> {
    let mut operands = Vec::new();
    let mut index = 0;
    let mut parse_options = true;
    while index < arguments.len() {
        let argument = &arguments[index];
        if parse_options && argument == "--" {
            parse_options = false;
            index += 1;
            continue;
        }
        if parse_options && argument.starts_with('-') && argument != "-" {
            let option_name = normalize_option_token(argument.split('=').next().unwrap_or(""))?;
            let clustered_match = clustered_short_value(argument, options_with_values);
            let mut takes_separate_value =
                options_with_values.contains(&option_name) && !argument.contains('=');
            if let Some((_, attached_value)) = clustered_match {
                takes_separate_value = attached_value.is_empty();
            }
            index += if takes_separate_value { 2 } else { 1 };
            continue;
        }
        operands.push(argument.as_str());
        index += 1;
    }
    Ok(operands)
}

fn clustered_short_value<'a>(
    argument: &'a str,
    option_names: &BTreeSet<String>,
) -> Option<(String, &'a str)> {
    if !argument.starts_with('-') || argument.starts_with("--") || argument.chars().nth(2).is_none()
    {
        return None;
    }
    for (offset, character) in argument.char_indices().skip(1) {
        if !python_is_alphanumeric(character) {
            return None;
        }
        let option = format!("-{character}");
        if option_names.contains(&option) {
            return Some((option, &argument[offset + character.len_utf8()..]));
        }
    }
    None
}

pub(super) fn split_option_setting(value: &str) -> Result<(String, String), &'static str> {
    let normalized = python_trim(value);
    let (key, setting) = if let Some(parts) = normalized.split_once('=') {
        parts
    } else if let Some((index, character)) = normalized
        .char_indices()
        .find(|(_, character)| python_is_whitespace(*character))
    {
        (
            &normalized[..index],
            &normalized[index + character.len_utf8()..],
        )
    } else {
        (normalized, "")
    };
    Ok((lowercase(key)?, lowercase(python_trim(setting))?))
}

pub(crate) fn present_flags(
    arguments: &[String],
    options_with_values: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            break;
        }
        flags.insert(argument.clone());
        let option_name = argument.split('=').next().unwrap_or("");
        if argument.starts_with('-') && argument.contains('=') {
            flags.insert(option_name.to_owned());
        }
        if argument.starts_with('-')
            && !argument.starts_with("--")
            && argument.chars().nth(2).is_some()
        {
            for character in argument.chars().skip(1) {
                if !python_is_alphanumeric(character) {
                    continue;
                }
                let flag = format!("-{character}");
                flags.insert(flag.clone());
                if options_with_values.contains(&flag) {
                    break;
                }
            }
        }
        index += if options_with_values.contains(option_name) && !argument.contains('=') {
            2
        } else {
            1
        };
    }
    flags
}
