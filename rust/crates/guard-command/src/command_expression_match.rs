//! The portable command-expression dialect: normalize a command, then match it
//! against one condition or a whole expression.
//!
//! Policy validation and runtime enforcement used to compile these patterns in
//! two places with two regex engines. They now meet here, so a document that
//! matches during `policy check` matches the same way when the hook runs.
//!
//! The dialect is bounded on purpose: globs translate to anchored patterns,
//! regexes are full matches, and backtracking is capped so a pattern an author
//! pastes in cannot stall a request.

use caseless::default_case_fold_str;
use fancy_regex::{Regex, RegexBuilder};
use guard_contracts::{
    CommandConditionV1, CommandExpressionV1, MAX_COMMAND_CONDITIONS, MAX_COMMAND_PATTERN_LENGTH,
    MAX_NORMALIZED_COMMAND_LENGTH,
};

#[cfg(test)]
#[path = "command_expression_match_tests.rs"]
mod tests;

/// Backtracking steps one pattern may take before it is refused. The Python
/// dialect bounded the same risk with a 50 ms deadline; a step count decides
/// the same way on every machine instead of with the load of the moment.
const BACKTRACK_LIMIT: usize = 100_000;

const OPERATORS: [&str; 6] = [
    "exact",
    "startsWith",
    "contains",
    "endsWith",
    "glob",
    "regex",
];

/// `normalize_command_text` - collapse command whitespace without touching
/// quoting or token spelling, the way the document compiler already does.
pub fn normalize_command_text(value: &str) -> Result<String, String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err("command_value_required".to_owned());
    }
    if normalized.chars().count() > MAX_NORMALIZED_COMMAND_LENGTH {
        return Err("command_value_too_long".to_owned());
    }
    Ok(normalized)
}

/// `glob_pattern` - translate the portable glob dialect: `*`, `?`, classes and
/// backslash escapes, anchored at both ends.
fn glob_pattern(value: &str) -> Result<String, String> {
    let characters: Vec<char> = value.chars().collect();
    let mut pieces = String::from("\\A");
    let mut index = 0;
    while index < characters.len() {
        match characters[index] {
            '\\' => {
                index += 1;
                if index >= characters.len() {
                    return Err("glob_escape_incomplete".to_owned());
                }
                pieces.push_str(&escape(characters[index]));
            }
            '*' => pieces.push_str(".*"),
            '?' => pieces.push('.'),
            '[' => {
                let closing = characters[index + 1..]
                    .iter()
                    .position(|character| *character == ']')
                    .map(|offset| index + 1 + offset)
                    .ok_or_else(|| "glob_class_unclosed".to_owned())?;
                let content: String = characters[index + 1..closing].iter().collect();
                if content.is_empty() {
                    return Err("glob_class_empty".to_owned());
                }
                pieces.push('[');
                if let Some(rest) = content.strip_prefix('!') {
                    pieces.push('^');
                    pieces.push_str(rest);
                } else {
                    pieces.push_str(&content);
                }
                pieces.push(']');
                index = closing;
            }
            character => pieces.push_str(&escape(character)),
        }
        index += 1;
    }
    pieces.push_str("\\z");
    Ok(pieces)
}

fn escape(character: char) -> String {
    fancy_regex::escape(&character.to_string()).into_owned()
}

/// `compile` - the pattern one glob or regex condition matches with.
fn compile(condition: &CommandConditionV1) -> Result<Regex, String> {
    let source = match condition.operator.as_str() {
        "glob" => glob_pattern(&condition.value)?,
        // Anchored, because the dialect matches a whole command and a
        // leftmost match of an alternation would answer a smaller question.
        "regex" => {
            // The author's pattern has to be a whole regex on its own first.
            // `git status)|(.*` wrapped unchecked becomes an alternation whose
            // second branch is anchored only at the end, so a search would
            // match every command the rule never named.
            Regex::new(&condition.value)
                .map_err(|_| format!("invalid_command_{}", condition.operator))?;
            format!("\\A(?:{})\\z", condition.value)
        }
        _ => fancy_regex::escape(&condition.value).into_owned(),
    };
    let source = if condition.case_sensitive {
        source
    } else {
        format!("(?i){source}")
    };
    RegexBuilder::new(&source)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map_err(|_| format!("invalid_command_{}", condition.operator))
}

/// `check_condition` - the bounds a condition must satisfy before it matches
/// anything. The document compiler applies the same ones when it parses.
fn check_condition(condition: &CommandConditionV1) -> Result<String, String> {
    if !OPERATORS.contains(&condition.operator.as_str()) {
        return Err("unsupported_command_pattern_operator".to_owned());
    }
    let value = normalize_command_text(&condition.value)?;
    if value.chars().count() > MAX_COMMAND_PATTERN_LENGTH {
        return Err("command_pattern_too_long".to_owned());
    }
    Ok(value)
}

/// `matches_condition` - whether `command` satisfies one condition.
pub fn matches_condition(condition: &CommandConditionV1, command: &str) -> Result<bool, String> {
    let pattern = check_condition(condition)?;
    let normalized = normalize_command_text(command)?;
    let (haystack, needle) = if condition.case_sensitive {
        (normalized.clone(), pattern.clone())
    } else {
        (
            default_case_fold_str(&normalized),
            default_case_fold_str(&pattern),
        )
    };
    match condition.operator.as_str() {
        "exact" => Ok(haystack == needle),
        "startsWith" => Ok(haystack.starts_with(&needle)),
        "contains" => Ok(haystack.contains(&needle)),
        "endsWith" => Ok(haystack.ends_with(&needle)),
        _ => {
            let compiled = compile(&CommandConditionV1 {
                operator: condition.operator.clone(),
                value: pattern,
                case_sensitive: condition.case_sensitive,
            })?;
            // Both sources are anchored, so this is a full match of the
            // whole command, not of any run of characters inside it.
            compiled
                .is_match(&normalized)
                .map_err(|_| "command_pattern_timeout".to_owned())
        }
    }
}

/// `check_expression` - the shape an expression must have before any of its
/// conditions is compiled or matched.
fn check_expression(expression: &CommandExpressionV1) -> Result<(), String> {
    match expression.combinator.as_str() {
        "all" | "any" => {}
        _ => return Err("unsupported_command_expression_combinator".to_owned()),
    }
    if expression.conditions.is_empty() {
        return Err("command_expression_conditions_required".to_owned());
    }
    if expression.conditions.len() > MAX_COMMAND_CONDITIONS {
        return Err("command_expression_conditions_limit".to_owned());
    }
    Ok(())
}

/// `validate_expression` - compile every pattern the expression carries once,
/// without a command to match. Policy validation used to do this with a second
/// regex engine in Python, so a document could be accepted at authoring time
/// and refused at decide time by the engine that actually matches it.
pub fn validate_expression(expression: &CommandExpressionV1) -> Result<(), String> {
    check_expression(expression)?;
    for condition in &expression.conditions {
        let pattern = check_condition(condition)?;
        if matches!(condition.operator.as_str(), "glob" | "regex") {
            compile(&CommandConditionV1 {
                operator: condition.operator.clone(),
                value: pattern,
                case_sensitive: condition.case_sensitive,
            })?;
        }
    }
    Ok(())
}

/// `matches_expression` - whether `command` satisfies the whole expression.
pub fn matches_expression(expression: &CommandExpressionV1, command: &str) -> Result<bool, String> {
    check_expression(expression)?;
    let all = expression.combinator == "all";
    // Every condition is evaluated, even once the outcome is settled: a rule
    // the dialect rejects is refused rather than skipped because an earlier
    // condition happened to decide the combinator.
    let mut matched = all;
    for condition in &expression.conditions {
        let outcome = matches_condition(condition, command)?;
        if all {
            matched &= outcome;
        } else {
            matched |= outcome;
        }
    }
    Ok(matched)
}
