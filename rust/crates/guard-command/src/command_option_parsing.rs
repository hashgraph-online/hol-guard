//! Conservative option semantics shared by native command matchers.
//!
//! Mirrors `guard/runtime/command_option_parsing.py`. Inputs come from the
//! bounded canonical command and a validated matcher contract. Unknown options
//! branch into both possible arities; exhausting the explicit state budget is
//! uncertainty, never proof that a safety flag is present.

use std::collections::BTreeSet;
use std::time::Instant;

#[path = "command_argument_semantics.rs"]
mod argument_assignments;
#[path = "command_option_unicode.rs"]
mod unicode;

pub(crate) use argument_assignments::ArgumentSemantics;
use argument_assignments::{is_truthy, partition_assignment};
pub(crate) use unicode::{python_is_alphabetic, python_is_alphanumeric, python_is_whitespace};

pub(crate) const MAX_OPTION_PARSE_STATES: usize = 16_384;

pub(crate) fn argument_semantics(
    arguments: &[String],
    options_with_values: &BTreeSet<String>,
    inverse_flag_pairs: &BTreeSet<(String, String)>,
) -> ArgumentSemantics {
    argument_assignments::argument_semantics(arguments, options_with_values, inverse_flag_pairs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseOutcome {
    Match,
    NoMatch,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OptionTransition {
    advance: usize,
    flag_assignments: BTreeSet<(String, bool)>,
}

impl OptionTransition {
    fn empty(advance: usize) -> Self {
        Self {
            advance,
            flag_assignments: BTreeSet::new(),
        }
    }

    fn with_flags(advance: usize, flags: &BTreeSet<String>) -> Self {
        Self {
            advance,
            flag_assignments: flags.iter().map(|flag| (flag.clone(), true)).collect(),
        }
    }
}

struct OptionShape {
    transitions: Vec<OptionTransition>,
    fully_known: bool,
}

#[cfg(test)]
pub(crate) fn matches_subcommands_conservatively(
    arguments: &[String],
    subcommands: &[String],
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
) -> bool {
    matches_subcommands_conservatively_with_deadline(
        arguments,
        subcommands,
        options_with_values,
        known_flags,
        None,
    )
}

/// Reuses the caller's absolute deadline; no parsing stage starts a new budget.
pub(crate) fn matches_subcommands_conservatively_with_deadline(
    arguments: &[String],
    subcommands: &[String],
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
    deadline: Option<Instant>,
) -> bool {
    subcommand_parse_outcome(
        arguments,
        subcommands,
        options_with_values,
        known_flags,
        MAX_OPTION_PARSE_STATES,
        deadline,
    ) != ParseOutcome::NoMatch
}

#[cfg(test)]
pub(crate) fn flags_present_in_all_option_parses(
    arguments: &[String],
    required_flags: &BTreeSet<String>,
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
) -> bool {
    flags_present_in_all_option_parses_with_deadline(
        arguments,
        required_flags,
        options_with_values,
        known_flags,
        None,
    )
}

/// An expired caller deadline is uncertainty and cannot establish safety.
pub(crate) fn flags_present_in_all_option_parses_with_deadline(
    arguments: &[String],
    required_flags: &BTreeSet<String>,
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
    deadline: Option<Instant>,
) -> bool {
    required_flags.iter().all(|required| {
        flag_parse_outcome(
            arguments,
            required,
            options_with_values,
            known_flags,
            MAX_OPTION_PARSE_STATES,
            deadline,
        ) == ParseOutcome::Match
    })
}

pub(crate) fn known_option_advance(
    argument: &str,
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
) -> Option<usize> {
    if !is_option(argument) {
        return None;
    }
    let shape = option_shape(argument, options_with_values, known_flags);
    let first = shape.transitions.first()?.advance;
    (shape.fully_known
        && shape
            .transitions
            .iter()
            .all(|transition| transition.advance == first))
    .then_some(first)
}

pub(crate) fn long_flag_assignment_is_enabled(argument: &str) -> bool {
    let (_, value) = partition_assignment(argument);
    value.is_none_or(|value| is_truthy(&value.to_lowercase()))
}

fn subcommand_parse_outcome(
    arguments: &[String],
    subcommands: &[String],
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
    state_limit: usize,
    deadline: Option<Instant>,
) -> ParseOutcome {
    let mut pending = vec![(0, 0)];
    let mut visited = BTreeSet::new();
    while let Some(state) = pending.pop() {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return ParseOutcome::Uncertain;
        }
        if visited.contains(&state) {
            continue;
        }
        if visited.len() >= state_limit {
            return ParseOutcome::Uncertain;
        }
        visited.insert(state);
        let (argument_index, subcommand_index) = state;
        if subcommand_index == subcommands.len() {
            return ParseOutcome::Match;
        }
        let Some(argument) = arguments.get(argument_index) else {
            continue;
        };
        if argument == "--" {
            let remaining = &subcommands[subcommand_index..];
            if arguments[argument_index + 1..].starts_with(remaining) {
                return ParseOutcome::Match;
            }
        } else if is_option(argument) {
            let shape = option_shape(argument, options_with_values, known_flags);
            pending.extend(
                shape
                    .transitions
                    .into_iter()
                    .map(|transition| (argument_index + transition.advance, subcommand_index)),
            );
        } else if argument == &subcommands[subcommand_index] {
            pending.push((argument_index + 1, subcommand_index + 1));
        }
    }
    ParseOutcome::NoMatch
}

fn flag_parse_outcome(
    arguments: &[String],
    required_flag: &str,
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
    state_limit: usize,
    deadline: Option<Instant>,
) -> ParseOutcome {
    let mut pending = vec![(0, None)];
    let mut visited = BTreeSet::new();
    let mut found_terminal = false;
    while let Some(state) = pending.pop() {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return ParseOutcome::Uncertain;
        }
        if visited.contains(&state) {
            continue;
        }
        if visited.len() >= state_limit {
            return ParseOutcome::Uncertain;
        }
        visited.insert(state);
        let (argument_index, final_assignment) = state;
        let argument = arguments.get(argument_index);
        if argument.is_none_or(|argument| argument == "--") {
            if final_assignment != Some(true) {
                return ParseOutcome::NoMatch;
            }
            found_terminal = true;
            continue;
        }
        let argument = &arguments[argument_index];
        if !is_option(argument) {
            pending.push((argument_index + 1, final_assignment));
            continue;
        }
        let shape = option_shape(argument, options_with_values, known_flags);
        for transition in shape.transitions {
            let assignment = transition
                .flag_assignments
                .iter()
                .find(|(flag, _)| flag == required_flag)
                .map(|(_, enabled)| *enabled)
                .or(final_assignment);
            pending.push((argument_index + transition.advance, assignment));
        }
    }
    if found_terminal {
        ParseOutcome::Match
    } else {
        ParseOutcome::NoMatch
    }
}

fn option_shape(
    argument: &str,
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
) -> OptionShape {
    if !argument.starts_with("--") {
        return short_option_shape(argument, options_with_values, known_flags);
    }
    let (option_name, value) = partition_assignment(argument);
    if options_with_values.contains(option_name) || known_flags.contains(option_name) {
        let is_value = options_with_values.contains(option_name);
        return OptionShape {
            transitions: vec![OptionTransition {
                advance: if is_value && value.is_none() { 2 } else { 1 },
                flag_assignments: BTreeSet::from([
                    (argument.to_owned(), true),
                    (
                        option_name.to_owned(),
                        is_value || long_flag_assignment_is_enabled(argument),
                    ),
                ]),
            }],
            fully_known: true,
        };
    }
    if value.is_some() {
        OptionShape {
            transitions: vec![OptionTransition::empty(1)],
            fully_known: true,
        }
    } else {
        OptionShape {
            transitions: vec![OptionTransition::empty(1), OptionTransition::empty(2)],
            fully_known: false,
        }
    }
}

fn short_option_shape(
    argument: &str,
    options_with_values: &BTreeSet<String>,
    known_flags: &BTreeSet<String>,
) -> OptionShape {
    let mut transitions = BTreeSet::new();
    let mut flags = BTreeSet::new();
    let mut fully_known = true;
    let mut characters = argument[1..].chars().peekable();
    while let Some(character) = characters.next() {
        let short_option = format!("-{character}");
        let last = characters.peek().is_none();
        if options_with_values.contains(&short_option) {
            transitions.insert(OptionTransition::with_flags(
                if last { 2 } else { 1 },
                &flags,
            ));
            return OptionShape {
                transitions: transitions.into_iter().collect(),
                fully_known,
            };
        }
        if known_flags.contains(&short_option) {
            flags.insert(short_option);
            continue;
        }
        fully_known = false;
        transitions.insert(OptionTransition::with_flags(1, &flags));
        if last {
            transitions.insert(OptionTransition::with_flags(2, &flags));
        }
    }
    transitions.insert(OptionTransition::with_flags(1, &flags));
    OptionShape {
        transitions: transitions.into_iter().collect(),
        fully_known,
    }
}

fn is_option(argument: &str) -> bool {
    argument.len() > 1 && argument.starts_with('-')
}

#[cfg(test)]
#[path = "command_option_parsing_tests.rs"]
mod tests;
