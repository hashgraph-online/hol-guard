//! Native preparation for a contained local lint, typecheck or build tool.
//!
//! The classifier already reads which tool a command names and in which
//! mode; this joins that reading to the project the run stands in. A
//! package script is read from the nearest manifest and its words go back
//! to the classifier, the tool's entrypoint is found in the nearest
//! `node_modules` that installs it, and a build is granted the one output
//! directory native authority reads for it. The plan is the Node test
//! plan's runtime and grants with the tool's entrypoint in place of
//! `--test`.
use super::*;
use serde_json::{json, Map, Value};

const READ_ONLY_PROFILE: &str = "node-tool-readonly-v1";
const BUILD_PROFILE: &str = "node-build-output-v1";

/// The route the classifier reads, with a script already read into its words.
struct Tool {
    arguments: Vec<String>,
    runtime_arguments: Vec<String>,
    expected_entry: Option<String>,
    entries: Vec<String>,
    build: bool,
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    let result = match operation {
        "prepare_node_tool" => prepare(input),
        "package_test_command" => package_test_command(input),
        _ => return None,
    };
    Some(match result {
        Ok(value) => json!({ "value": value }),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}

/// The words a package manager's own test script runs, read from the
/// nearest project's manifest: the same reading the run's tool route takes.
fn package_test_command(input: &Value) -> Result<Value, RestrictedPytestError> {
    let request = input.as_object().ok_or_else(invalid_request)?;
    let command = request.get("command").cloned().unwrap_or(Value::Null);
    let command = serde_json::from_value::<Vec<String>>(command).map_err(|_| invalid_request())?;
    let place = |field: &str| {
        request
            .get(field)
            .and_then(Value::as_str)
            .map(PathBuf::from)
    };
    let workspace = place("workspace").ok_or_else(invalid_request)?;
    let cwd = place("cwd").unwrap_or_else(|| workspace.clone());
    let manifest = manifest(&workspace, &cwd)?;
    let scripts = manifest
        .as_ref()
        .and_then(|manifest| manifest.get("scripts"))
        .and_then(Value::as_object);
    crate::contained_package_test::resolve(&command, scripts).map(|words| json!(words))
}

/// The nearest project's manifest, read through a verified descriptor.
fn manifest(
    workspace: &Path,
    cwd: &Path,
) -> Result<Option<Map<String, Value>>, RestrictedPytestError> {
    let package = ask(
        "nearest_project_root",
        json!({ "cwd": cwd, "workspace": workspace, "value": "package.json" }),
    )?;
    let package = PathBuf::from(package.as_str().ok_or_else(invalid_request)?);
    Ok(crate::contained_runner::pkg_json::read_json_with_integrity(
        &package.join("package.json"),
        false,
    )
    .0)
}

fn invalid_request() -> RestrictedPytestError {
    RestrictedPytestError::new(
        PYTEST_INVALID_COMMAND_REASON_CODE,
        "Invalid restricted execution request.",
    )
}

fn invalid_command(message: &str) -> RestrictedPytestError {
    RestrictedPytestError::new("node_tool_invalid_command", message)
}

/// One native answer, with a refusal kept as the refusal it names.
fn ask(operation: &str, input: Value) -> Result<Value, RestrictedPytestError> {
    let mut reply = super::evaluate(operation, &input);
    if let Some(value) = reply.get_mut("value") {
        return Ok(value.take());
    }
    let text = |field: &str| reply.get(field).and_then(Value::as_str).map(str::to_owned);
    match (text("reason_code"), text("message")) {
        (Some(code), Some(message)) => Err(RestrictedPytestError::new(&code, message)),
        _ => Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            format!(
                "Native restricted execution preparation is unavailable ({operation}); execution was not started."
            ),
        )),
    }
}

fn prepare(input: &Value) -> Result<Value, RestrictedPytestError> {
    let request = input.as_object().ok_or_else(invalid_request)?;
    let command = request.get("command").cloned().unwrap_or(Value::Null);
    let argv = normalized_command(
        &serde_json::from_value::<Vec<String>>(command).map_err(|_| invalid_request())?,
    )?;
    let requested = |field: &str| {
        request
            .get(field)
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(invalid_request)
    };
    // The route is read before the runtime is resolved, so a command Guard
    // does not run as a tool is refused as that, whatever Node the host has.
    let tool = route(&argv, &requested("workspace")?, &requested("cwd")?)?;
    let mut node = request.clone();
    node.insert("command".to_owned(), json!(["node", "--test"]));
    let Value::Object(mut plan) = ask("prepare_node", Value::Object(node))? else {
        return Err(invalid_request());
    };
    let text = |plan: &Map<String, Value>, field: &str| {
        plan.get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(invalid_request)
    };
    let workspace = PathBuf::from(text(&plan, "workspace")?);
    let cwd = PathBuf::from(text(&plan, "cwd")?);
    let executable = text(&plan, "executable")?;
    let mut arguments = tool.arguments.clone();
    let mut output_roots = Vec::new();
    if tool.build {
        output_roots.push(ask(
            "node_build_output_root",
            json!({ "arguments": arguments, "workspace": workspace, "cwd": cwd }),
        )?);
    }
    let (modules, entry) = tool_entry(&tool, &workspace, &cwd).ok_or_else(|| {
        RestrictedPytestError::new(
            "node_tool_dependency_unavailable",
            "The local lint/typecheck tool is unavailable; no replacement was downloaded.",
        )
    })?;
    if tool.build && !names_config_loader(&arguments) {
        let explicit = arguments
            .iter()
            .any(|value| value == "-c" || value == "--config" || value.starts_with("--config="));
        let bundle = if explicit {
            Value::Null
        } else {
            ask(
                "vite_bundle_directory",
                json!({ "cwd": cwd, "workspace": workspace, "modules": modules }),
            )?
        };
        match bundle {
            Value::Null => arguments.extend(["--configLoader".to_owned(), "runner".to_owned()]),
            bundle => output_roots.push(bundle),
        }
    }
    let mut command = vec![executable];
    command.extend(tool.runtime_arguments);
    command.push(entry.to_string_lossy().into_owned());
    command.extend(arguments);
    let denied = plan
        .get("denied_capabilities")
        .and_then(Value::as_array)
        .ok_or_else(invalid_request)?
        .iter()
        .map(|value| match value.as_str() {
            Some("workspace-write") if tool.build => json!("workspace-source-write"),
            _ => value.clone(),
        })
        .collect::<Vec<_>>();
    let profile = if tool.build {
        BUILD_PROFILE
    } else {
        READ_ONLY_PROFILE
    };
    plan.insert("profile_version".to_owned(), json!(profile));
    plan.insert("command".to_owned(), json!(command));
    plan.insert("denied_capabilities".to_owned(), json!(denied));
    if tool.build {
        plan.insert("output_roots".to_owned(), json!(output_roots));
    }
    Ok(Value::Object(plan))
}

fn names_config_loader(arguments: &[String]) -> bool {
    arguments
        .iter()
        .any(|value| value == "--configLoader" || value.starts_with("--configLoader="))
}

/// The tool route for `argv`, reading a named package script into the words
/// it runs. Only the manifest read is this side's work: the script's words go
/// back to the classifier, which gates them as the run they spell.
fn route(argv: &[String], workspace: &Path, cwd: &Path) -> Result<Tool, RestrictedPytestError> {
    // The run directory travels with the request: a `tsc` run reads its
    // no-emit mode from the project it names, and the route has to see the
    // same project the run will.
    let first = ask(
        "node_tool_route",
        json!({ "command": argv, "script_body": null, "windows": false, "cwd": cwd }),
    )?;
    let reply = match script_task(&first) {
        Some(task) => {
            let body = script_body(task, workspace, cwd)?;
            let second = ask(
                "node_tool_route",
                json!({ "command": argv, "script_body": body, "windows": false, "cwd": cwd }),
            )?;
            if script_task(&second).is_some() {
                return Err(invalid_command(
                    "Only a single named package script is supported.",
                ));
            }
            second
        }
        None => first,
    };
    tool(&reply).ok_or_else(|| {
        RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "Native restricted execution preparation is unavailable (node_tool_route); execution was not started.",
        )
    })
}

fn script_task(reply: &Value) -> Option<&str> {
    (reply.get("kind")? == "script")
        .then(|| reply.get("task")?.as_str())
        .flatten()
        .filter(|task| !task.is_empty())
}

fn words(value: Option<&Value>) -> Option<Vec<String>> {
    serde_json::from_value(value?.clone()).ok()
}

fn tool(reply: &Value) -> Option<Tool> {
    let build = match reply.get("mode")?.as_str()? {
        "report" => false,
        "build" => true,
        _ => return None,
    };
    let expected_entry = match reply.get("expected_entry")? {
        Value::Null => None,
        Value::String(entry) => Some(entry.clone()),
        _ => return None,
    };
    let entries = words(reply.get("entries"))?;
    if reply.get("kind")? != "tool" || !reply.get("name")?.is_string() || entries.is_empty() {
        return None;
    }
    Some(Tool {
        arguments: words(reply.get("arguments"))?,
        runtime_arguments: words(reply.get("runtime_arguments"))?,
        expected_entry,
        entries,
        build,
    })
}

/// The words of the named script, read from the nearest project's manifest.
fn script_body(
    task: &str,
    workspace: &Path,
    cwd: &Path,
) -> Result<Vec<String>, RestrictedPytestError> {
    let manifest = manifest(workspace, cwd)?;
    let scripts = manifest
        .as_ref()
        .and_then(|manifest| manifest.get("scripts"))
        .and_then(Value::as_object);
    let lifecycle = |phase: &str| {
        scripts
            .and_then(|scripts| scripts.get(&format!("{phase}{task}")))
            .is_some_and(truthy)
    };
    if lifecycle("pre") || lifecycle("post") {
        return Err(invalid_command(
            "This script has lifecycle actions that need separate evaluation.",
        ));
    }
    let Some(script) = scripts
        .and_then(|scripts| scripts.get(task))
        .and_then(Value::as_str)
    else {
        return Err(invalid_command(
            "The requested local script is unavailable.",
        ));
    };
    // Reading a script into the words a run will execute is a reading of a
    // command, so it asks the same lexer the classifier reads it with.
    let words = ask("script_words", json!({ "script": script }))?;
    serde_json::from_value(words).map_err(|_| invalid_request())
}

/// Whether a manifest value counts as present, as the package manager reads
/// a lifecycle script: anything but an empty or false-like value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

/// The `node_modules` directory holding the tool, and the tool's own file.
///
/// A tool may publish its executable under more than one name across major
/// versions, so this looks for every spelling and keeps the one the nearest
/// project installs: a package that pins its own major is what the command
/// would run, not a copy hoisted further up a monorepo. A tie keeps the order
/// the spellings are declared in.
fn tool_entry(tool: &Tool, workspace: &Path, cwd: &Path) -> Option<(PathBuf, PathBuf)> {
    let nearest = |relative: &str| -> Option<PathBuf> {
        let root = ask(
            "nearest_project_root",
            json!({ "cwd": cwd, "workspace": workspace, "value": format!("node_modules/{relative}") }),
        )
        .ok()?;
        Some(PathBuf::from(root.as_str()?).join("node_modules"))
    };
    let mut found: Option<(usize, PathBuf, &str)> = None;
    for relative in &tool.entries {
        let modules = nearest(relative)?;
        let depth = modules.components().count();
        if modules.join(relative).is_file()
            && found.as_ref().is_none_or(|(deepest, ..)| depth > *deepest)
        {
            found = Some((depth, modules, relative.as_str()));
        }
    }
    let (modules, relative) = match found {
        Some((_, modules, relative)) => (modules, relative),
        None => (nearest(&tool.entries[0])?, tool.entries[0].as_str()),
    };
    let entry = modules.join(relative).canonicalize().ok()?;
    if !entry.is_file() || !entry.starts_with(modules.canonicalize().ok()?) {
        return None;
    }
    // A relative entrypoint names a file below the command's directory.
    if let Some(expected) = &tool.expected_entry {
        if cwd.join(expected).canonicalize().ok()? != entry {
            return None;
        }
    }
    Some((modules, entry))
}

#[cfg(test)]
#[path = "node_tool_plan_tests.rs"]
mod tests;
