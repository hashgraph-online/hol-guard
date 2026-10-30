//! The package-test alias: the local `test` script a package manager runs.
//!
//! `npm test` names a script rather than a runner, so the words that actually
//! run are the ones the manifest declares. The manifest read stays with the
//! sink; the words it finds come back here to be read as the run they spell,
//! so the alias and the runner behind it are gated the same way.
#[cfg(test)]
#[path = "contained_package_test_tests.rs"]
mod tests;

use crate::contained_argv::{jest_contained_call, program_name};
use crate::restricted_command::{normalized_command, RestrictedPytestError};
use crate::sfrs_shlex::{split_with, SCRIPT_LEXER};
use serde_json::{Map, Value};

const INVALID: &str = "package_test_invalid_command";

fn invalid(message: &str) -> RestrictedPytestError {
    RestrictedPytestError::new(INVALID, message)
}

/// Python truthiness of a manifest value.
pub(crate) fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
    }
}

/// True when the manifest declares a `pre` or `post` action for the task. Such
/// an action runs its own words, which this reading never saw.
pub(crate) fn lifecycle(scripts: &Map<String, Value>, task: &str) -> bool {
    ["pre", "post"]
        .iter()
        .any(|phase| truthy(scripts.get(&format!("{phase}{task}"))))
}

/// True when the command is a package manager running its project's own
/// `test` script. `bun test` is Bun's own runner rather than the script, so
/// for Bun only the explicit `run test` spelling names the script.
pub(crate) fn is_package_test(command: &[String]) -> bool {
    let Some(manager) = command.first().map(|value| program_name(value)) else {
        return false;
    };
    if !matches!(manager, "npm" | "pnpm" | "bun" | "yarn") {
        return false;
    }
    (command.len() >= 2 && command[1] == "test" && manager != "bun")
        || (command.len() >= 3 && command[1] == "run" && command[2] == "test")
}

/// The words the declared `test` script runs, read from the manager's own
/// arguments (its words after the manager name) and the manifest's scripts.
///
/// Only a script that finishes on its own and reads its own workspace is
/// resolved: shell expansion, shell effects, a lifecycle action and any runner
/// outside the supported set keep the alias unresolved, because the narrow
/// receipt the sink holds is for the run this reading spells and nothing else.
pub(crate) fn script_tokens(
    arguments: &[String],
    scripts: Option<&Map<String, Value>>,
) -> Result<Vec<String>, RestrictedPytestError> {
    let trailing = match arguments {
        [task, rest @ ..] if task == "test" => rest,
        [_, _, rest @ ..] => rest,
        _ => return Err(invalid("Only local package test scripts are supported.")),
    };
    if trailing.first().is_some_and(|word| word != "--") {
        return Err(invalid("Test arguments must follow an explicit --."));
    }
    let Some(script) = scripts
        .and_then(|scripts| scripts.get("test"))
        .and_then(Value::as_str)
    else {
        return Err(invalid("The local test script is unavailable."));
    };
    if scripts.is_some_and(|scripts| lifecycle(scripts, "test")) {
        return Err(invalid(
            "Test lifecycle actions need separate evaluation; none were skipped.",
        ));
    }
    if script.contains(['$', '`', '\n', '\r']) {
        return Err(invalid("Test shell expansion needs separate evaluation."));
    }
    let Ok(tokens) = split_with(SCRIPT_LEXER, script) else {
        return Err(invalid("The local test script could not be parsed."));
    };
    if tokens.is_empty() {
        return Err(invalid("The test script is empty."));
    }
    if tokens
        .iter()
        .any(|token| !token.is_empty() && token.chars().all(|value| ";&|<>".contains(value)))
    {
        return Err(invalid("Test shell effects need separate evaluation."));
    }
    let passthrough = trailing.get(1..).unwrap_or_default();
    let runner = tokens[0].as_str();
    let rest = &tokens[1..];
    let flag = rest.first();
    let node = matches!(program_name(runner), "node" | "nodejs")
        && flag.is_some_and(|flag| flag == "--test");
    let vitest = program_name(runner) == "vitest" && flag.is_some_and(|flag| flag == "run");
    let jest = program_name(runner) == "jest" && {
        let call: Vec<String> = rest.iter().chain(passthrough.iter()).cloned().collect();
        jest_contained_call(&call)
    };
    if !node && !vitest && !jest {
        return Err(invalid("The test script is not a supported local runner."));
    }
    Ok(tokens.iter().chain(passthrough.iter()).cloned().collect())
}

/// The whole alias: the manager's command and the manifest's scripts in, the
/// words the run spells out.
pub(crate) fn resolve(
    command: &[String],
    scripts: Option<&Map<String, Value>>,
) -> Result<Vec<String>, RestrictedPytestError> {
    let argv = normalized_command(command)?;
    if !is_package_test(&argv) {
        return Err(invalid("Only local package test scripts are supported."));
    }
    script_tokens(&argv[1..], scripts)
}
