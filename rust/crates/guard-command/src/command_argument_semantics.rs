//! Ordered effective flags and value assignments for one bounded argument list.

use std::collections::{BTreeMap, BTreeSet};

use super::unicode::python_is_alphanumeric;

struct EffectiveOption {
    name: String,
    token: String,
    value: Option<String>,
    is_value_option: bool,
    inverse_pair: Option<(String, String, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArgumentSemantics {
    pub(crate) present_flags: BTreeSet<String>,
    /// First occurrence determines order; a later assignment replaces its value.
    pub(crate) effective_options: Vec<(String, String, Option<String>)>,
}

impl ArgumentSemantics {
    pub(crate) fn option_value(&self, option: &str) -> Option<&str> {
        self.effective_options
            .iter()
            .find(|(name, _, _)| name == option)
            .and_then(|(_, _, value)| value.as_deref())
    }

    pub(crate) fn option_token(&self, option: &str) -> Option<&str> {
        self.effective_options
            .iter()
            .find(|(name, _, _)| name == option)
            .map(|(_, token, _)| token.as_str())
    }
}

pub(crate) fn argument_semantics(
    arguments: &[String],
    options_with_values: &BTreeSet<String>,
    inverse_flag_pairs: &BTreeSet<(String, String)>,
) -> ArgumentSemantics {
    let mut flags = BTreeSet::new();
    let mut inverse_aliases = BTreeMap::new();
    for (positive, negative) in inverse_flag_pairs {
        inverse_aliases.insert(positive.as_str(), (positive, negative, true));
        inverse_aliases.insert(negative.as_str(), (positive, negative, false));
    }
    let mut effective_options = Vec::new();
    let mut effective_indices = BTreeMap::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            break;
        }
        let (option_name, inline_value) = partition_assignment(argument);
        let is_value_option = options_with_values.contains(option_name);
        let inverse_alias = inverse_aliases.get(option_name);
        if argument.starts_with("--") || inverse_alias.is_some() {
            let value = match inline_value {
                Some(value) => Some(value.to_owned()),
                None if is_value_option => {
                    Some(arguments.get(index + 1).cloned().unwrap_or_default())
                }
                None => None,
            };
            let name = inverse_alias
                .map(|(positive, _, _)| positive.as_str())
                .unwrap_or(option_name);
            let option = EffectiveOption {
                name: name.to_owned(),
                token: argument.clone(),
                value,
                is_value_option,
                inverse_pair: inverse_alias.map(|(positive, negative, polarity)| {
                    ((*positive).clone(), (*negative).clone(), *polarity)
                }),
            };
            assign_effective_option(&mut effective_options, &mut effective_indices, option);
        } else {
            flags.insert(argument.clone());
            if argument.starts_with('-') && inline_value.is_some() {
                flags.insert(option_name.to_owned());
            }
        }
        if inverse_alias.is_none() && option_name.starts_with('-') && !option_name.starts_with("--")
        {
            for character in option_name[1..].chars() {
                if !python_is_alphanumeric(character) {
                    continue;
                }
                let short_flag = format!("-{character}");
                if let Some((positive, negative, polarity)) =
                    inverse_aliases.get(short_flag.as_str())
                {
                    assign_effective_option(
                        &mut effective_options,
                        &mut effective_indices,
                        EffectiveOption {
                            name: (*positive).clone(),
                            token: short_flag.clone(),
                            value: None,
                            is_value_option: false,
                            inverse_pair: Some((
                                (*positive).clone(),
                                (*negative).clone(),
                                *polarity,
                            )),
                        },
                    );
                } else {
                    flags.insert(short_flag.clone());
                }
                if options_with_values.contains(&short_flag) {
                    break;
                }
            }
        }
        index += if is_value_option && inline_value.is_none() {
            2
        } else {
            1
        };
    }
    for option in &effective_options {
        flags.insert(option.token.clone());
        if let Some((positive, negative, polarity)) = &option.inverse_pair {
            if let Some(assigned) = boolean_flag_value(option.value.as_deref()) {
                flags.insert(
                    if assigned == *polarity {
                        positive
                    } else {
                        negative
                    }
                    .clone(),
                );
            }
        } else if option.is_value_option
            || option.value.is_none()
            || option.value.as_deref().is_some_and(is_truthy)
        {
            flags.insert(option.name.clone());
        }
    }
    ArgumentSemantics {
        present_flags: flags,
        effective_options: effective_options
            .into_iter()
            .map(|option| (option.name, option.token, option.value))
            .collect(),
    }
}

fn assign_effective_option(
    options: &mut Vec<EffectiveOption>,
    indices: &mut BTreeMap<String, usize>,
    option: EffectiveOption,
) {
    if let Some(index) = indices.get(&option.name) {
        options[*index] = option;
    } else {
        indices.insert(option.name.clone(), options.len());
        options.push(option);
    }
}

pub(super) fn partition_assignment(argument: &str) -> (&str, Option<&str>) {
    match argument.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (argument, None),
    }
}

pub(super) fn is_truthy(value: &str) -> bool {
    matches!(value, "1" | "on" | "true" | "yes")
}

fn boolean_flag_value(value: Option<&str>) -> Option<bool> {
    match value {
        None => Some(true),
        Some(value) if is_truthy(value) => Some(true),
        Some("0" | "false" | "no" | "off") => Some(false),
        _ => None,
    }
}
