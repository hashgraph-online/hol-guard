//! The package-test alias: the local `test` script a package manager runs.
//!
//! `npm test` names a script rather than a runner, so the words that actually
//! run are the ones the manifest declares. The manifest read stays with the
//! sink; the words it finds come back here to be read as the run they spell,
//! so the alias and the runner behind it are gated the same way.
#[cfg(test)]
#[path = "contained_package_test_tests.rs"]
mod tests;

use crate::contained_argv::{jest_contained_call, mocha_contained_call, program_name};
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

/// A manifest entry named for tests: `test` itself, or one of the `test:`
/// family a project splits its suites across, such as `test:unit` and
/// `test:e2e`. The name only says which entry to read; the body behind it
/// still has to spell a run this module admits.
pub(crate) fn test_task(name: &str) -> bool {
    name == "test" || name.starts_with("test:")
}

/// True when the command is a package manager running one of its project's
/// own test scripts. `bun test` is Bun's own runner rather than the script,
/// so for Bun only the explicit `run` spelling names a script.
pub(crate) fn is_package_test(command: &[String]) -> bool {
    let Some(manager) = command.first().map(|value| program_name(value)) else {
        return false;
    };
    if !matches!(manager, "npm" | "pnpm" | "bun" | "yarn") {
        return false;
    }
    let arguments = reporting_options_peeled(manager, &command[1..]);
    match arguments {
        [task, ..]
            if manager != "bun"
                && (test_task(task)
                    || crate::contained_argv::aliased_test_script_name(manager, task)
                        .is_some()) =>
        {
            true
        }
        [run, tail @ ..] if crate::contained_argv::names_script_run_verb(manager, run) => {
            matches!(reporting_options_peeled(manager, tail), [task, ..] if test_task(task))
        }
        _ => false,
    }
}

/// The manager's words with its reporting options peeled off, before the
/// `run` verb or after it.
///
/// `npm --silent test` and `npm run --silent test` are the run `npm test`
/// names; the admission reads them the same way, so the sink has to resolve
/// the same script rather than refusing the quiet spelling.
fn reporting_options_peeled<'a>(manager: &str, arguments: &'a [String]) -> &'a [String] {
    crate::contained_argv::manager_reporting_options_peeled(manager, arguments)
}

/// The words the declared `test` script runs, read from the manager's own
/// arguments (its words after the manager name) and the manifest's scripts.
///
/// Only a script that finishes on its own and reads its own workspace is
/// resolved: shell expansion, shell effects, a lifecycle action and any runner
/// outside the supported set keep the alias unresolved, because the narrow
/// receipt the sink holds is for the run this reading spells and nothing else.
pub(crate) fn script_tokens(
    manager: &str,
    arguments: &[String],
    scripts: Option<&Map<String, Value>>,
) -> Result<Vec<String>, RestrictedPytestError> {
    let arguments = reporting_options_peeled(manager, arguments);
    let run_tail = match arguments {
        [run, tail @ ..] if crate::contained_argv::names_script_run_verb(manager, run) => {
            Some(reporting_options_peeled(manager, tail))
        }
        _ => None,
    };
    let (task, trailing) = match (run_tail, arguments) {
        (Some([task, rest @ ..]), _) if test_task(task) => (task.as_str(), rest),
        (Some(_), _) => return Err(invalid("Only local package test scripts are supported.")),
        (None, [task, rest @ ..]) if test_task(task) => (task.as_str(), rest),
        (None, [task, rest @ ..])
            if crate::contained_argv::aliased_test_script_name(manager, task).is_some() =>
        {
            ("test", rest)
        }
        _ => return Err(invalid("Only local package test scripts are supported.")),
    };
    if trailing.first().is_some_and(|word| word != "--") {
        return Err(invalid("Test arguments must follow an explicit --."));
    }
    let Some(script) = scripts
        .and_then(|scripts| scripts.get(task))
        .and_then(Value::as_str)
    else {
        return Err(invalid("The local test script is unavailable."));
    };
    if scripts.is_some_and(|scripts| lifecycle(scripts, task)) {
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
    let mocha = program_name(runner) == "mocha" && {
        let call: Vec<String> = rest.iter().chain(passthrough.iter()).cloned().collect();
        mocha_contained_call(&call)
    };
    if !node && !vitest && !jest && !mocha {
        // A project may name a read-only tool run for the suite it checks,
        // such as a `test:types` entry holding `tsc --noEmit`. The words the
        // manifest declares are the run either way, so the body goes back as
        // the tool call it spells and is gated as that tool, not as a runner.
        // Only the declared words travel: an argument the caller appended was
        // never read against this tool's own rules.
        if passthrough.is_empty()
            && !crate::contained_node_tool::writes_or_chains(rest)
            && crate::contained_node_tool::supported_tool(runner, rest)
                .is_some_and(|(_, _, mode)| mode != crate::contained_node_tool::ToolMode::Build)
        {
            return Ok(tokens);
        }
        return Err(invalid("The test script is not a supported local runner."));
    }
    Ok(tokens.iter().chain(passthrough.iter()).cloned().collect())
}

/// The tool call a test-named script body spells, when the body is a
/// read-only tool run rather than one of the runners read above.
///
/// `script_tokens` admits such a body on the tool's own name and arguments
/// alone. Whether that tool is installed where the sink resolves it is a
/// question about a directory this module never sees, so the body comes back
/// out for the route to answer.
pub(crate) fn script_tool_body(
    manager: &str,
    arguments: &[String],
    scripts: Option<&Map<String, Value>>,
) -> Option<(String, Vec<String>)> {
    let tokens = script_tokens(manager, arguments, scripts).ok()?;
    let (runner, rest) = tokens.split_first()?;
    crate::contained_node_tool::supported_tool(runner, rest)?;
    Some((runner.clone(), rest.to_vec()))
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
    script_tokens(program_name(&argv[0]), &argv[1..], scripts)
}
