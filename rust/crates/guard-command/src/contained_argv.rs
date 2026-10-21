//! Portable bounded argv admission for contained Node, Vitest and inline runs.
#[cfg(test)]
#[path = "contained_argv_tests.rs"]
mod tests;
use crate::restricted_command::{normalized_command, RestrictedPytestError};
use regex::Regex;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::LazyLock;

const NODE_INVALID: &str = "node_test_restricted_invalid_command";
const VITEST_INVALID: &str = "vitest_restricted_invalid_command";

/// `node_modules/<entry>`, `./node_modules/<entry>`, or `<dir>/node_modules/<entry>`.
fn local_package_entry(argument: &str, package_entry: &str) -> bool {
    argument
        .strip_suffix(package_entry)
        .and_then(|prefix| prefix.strip_suffix("node_modules/"))
        .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('/'))
}

/// The program name; on Windows without `.exe`, as the pre-tool parser reads
/// it, so `node.exe` and a resolved `C:\...\python.exe` plan like `node` and
/// `python`.
fn basename(command: &[String]) -> &str {
    let name = command
        .first()
        .and_then(|v| Path::new(v).file_name())
        .and_then(|v| v.to_str())
        .unwrap_or("");
    match name.len().checked_sub(4) {
        Some(stem)
            if cfg!(windows)
                && stem > 0
                && name.is_char_boundary(stem)
                && name[stem..].eq_ignore_ascii_case(".exe") =>
        {
            &name[..stem]
        }
        _ => name,
    }
}

pub fn node_runtime_args(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    let argv = normalized_command(command)?;
    if argv.len() >= 2 && matches!(basename(&argv), "node" | "nodejs") {
        if let Some(value) = argv[1].strip_prefix("--max-old-space-size=") {
            // Python accepts arbitrarily many leading zeroes; bound the wire,
            // not numeric parsing, without rejecting that lexical form.
            let digits = value.trim_start_matches('0');
            let number = digits.parse::<u32>().ok();
            if value.is_empty()
                || !value.bytes().all(|v| v.is_ascii_digit())
                || !number.is_some_and(|v| (16..=131072).contains(&v))
            {
                return Err(RestrictedPytestError::new(
                    NODE_INVALID,
                    "Invalid bounded Node memory option.",
                ));
            }
            return Ok(vec![argv[1].clone()]);
        }
    }
    Ok(vec![])
}

pub fn test_script(script: &str) -> bool {
    named_test_script(script, false)
}

/// A workspace script under any plain name. Windows has no workspace sandbox,
/// so there the read-only boundary also runs an ordinary script that the
/// pre-tool check found reads no network, credential store or write; it
/// authorizes the resolved launch again before running it.
fn windows_plain_script(script: &str, node: bool) -> bool {
    static NAME: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.py$").unwrap());
    static NODE_NAME: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:js|mjs|cjs)$").unwrap());
    let name = if node { &NODE_NAME } else { &NAME };
    cfg!(windows)
        && workspace_script_path(script)
        && name.is_match(script.rsplit('/').next().unwrap_or(""))
}

fn workspace_script_path(script: &str) -> bool {
    !script.is_empty()
        && !script.starts_with(['-', '/', '~', '$'])
        && !script.contains(['\\', '$', '`'])
        && script
            .trim_end_matches('/')
            .split('/')
            .all(|v| !v.is_empty() && v != "..")
}

fn named_test_script(script: &str, node: bool) -> bool {
    static NAME: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?:test_[A-Za-z0-9_-]*|[A-Za-z0-9_-]*_test|test|tests|runtests|run_tests)\.py$",
        )
        .unwrap()
    });
    workspace_script_path(script)
        && if node {
            static NODE_NAME: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(r"^(?:[A-Za-z0-9_.-]*(?:\.test|\.spec|_test)|test_[A-Za-z0-9_.-]*|tests?)\.(?:js|mjs|cjs|jsx|ts|mts|cts|tsx)$").unwrap()
            });
            NODE_NAME.is_match(script.rsplit('/').next().unwrap_or(""))
        } else {
            NAME.is_match(script.rsplit('/').next().unwrap_or(""))
        }
}

pub fn node_script_index(command: &[String], start: usize) -> Option<usize> {
    static FLAGS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:--experimental-strip-types|--experimental-transform-types|--no-warnings|--disable-warning=[A-Za-z0-9_]{1,64})$").unwrap()
    });
    let mut index = start;
    while command
        .get(index)
        .is_some_and(|value| FLAGS.is_match(value))
    {
        index += 1;
    }
    command
        .get(index)
        .filter(|value| named_test_script(value, true) || windows_plain_script(value, true))
        .map(|_| index)
}

pub fn tsx_test_invocation(
    command: &[String],
) -> Result<Option<(String, Vec<String>)>, RestrictedPytestError> {
    let name = basename(command);
    let Some(mut args) = command.get(1..) else {
        return Ok(None);
    };
    if name == "npx" && args.first().is_some_and(|value| value == "--no-install") {
        args = &args[1..];
    }
    if name == "npx" && args.first().is_some_and(|value| value == "tsx") {
        args = &args[1..];
    } else if matches!(name, "node" | "nodejs") {
        args = &args[node_runtime_args(command)?.len()..];
        if !args.first().is_some_and(|value| {
            value
                .replace('\\', "/")
                .ends_with("/node_modules/tsx/dist/cli.mjs")
        }) {
            return Ok(None);
        }
        args = &args[1..];
    } else if name != "tsx" {
        return Ok(None);
    }
    Ok(args
        .first()
        .filter(|value| named_test_script(value, true))
        .map(|script| (script.clone(), args[1..].to_vec())))
}

pub fn python_runtime_args(command: &[String]) -> Option<Vec<String>> {
    let mut flags = 0;
    let mut index = 1;
    while let Some(arg) = command.get(index) {
        let bits = match arg.as_str() {
            "-I" => 1,
            "-S" => 2,
            "-IS" | "-SI" => 3,
            _ => break,
        };
        if flags & bits != 0 {
            return None;
        }
        flags |= bits;
        index += 1;
    }
    let inline = command.len() == index + 2 && command[index] == "-c";
    let unittest = command.get(index).is_some_and(|value| value == "-m")
        && command
            .get(index + 1)
            .is_some_and(|value| value == "unittest")
        && command[index + 2..]
            .iter()
            .all(|value| !value.contains(['<', '>', '|', '&', ';', '`', '$']));
    if !inline
        && !unittest
        && !command
            .get(index)
            .is_some_and(|v| test_script(v) || windows_plain_script(v, false))
    {
        return None;
    }
    Some(command[1..index].to_vec())
}

pub fn inline_eval(command: &[String]) -> Result<bool, RestrictedPytestError> {
    static PYTHON: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^python(?:\d+(?:\.\d+)*)?$").unwrap());
    if command.is_empty() {
        return Ok(false);
    }
    if PYTHON.is_match(basename(command)) {
        return Ok(python_runtime_args(command).is_some());
    }
    if basename(command) == "bun" {
        return Ok(
            command.len() == 3 && matches!(command[1].as_str(), "-e" | "--eval" | "-p" | "--print")
        );
    }
    if !matches!(basename(command), "node" | "nodejs") {
        return Ok(false);
    }
    let index = 1 + node_runtime_args(command)?.len();
    Ok(
        (command.len() == index + 2 && matches!(command[index].as_str(), "-e" | "--eval"))
            || node_script_index(command, index).is_some(),
    )
}

pub fn bun_vitest_invocation(command: &[String]) -> Option<(Option<String>, Vec<String>)> {
    let name = basename(command);
    if !matches!(name, "bun" | "bunx") {
        return None;
    }
    let mut args = &command[1..];
    let mut directory = None;
    if args.first().is_some_and(|v| v == "--cwd") {
        let value = args.get(1)?;
        if value.is_empty() || value.starts_with('-') {
            return None;
        }
        directory = Some(value.clone());
        args = &args[2..];
    } else if let Some(value) = args.first().and_then(|v| v.strip_prefix("--cwd=")) {
        if value.is_empty() {
            return None;
        }
        directory = Some(value.to_owned());
        args = &args[1..];
    }
    if name == "bunx" {
        directory.as_ref()?;
    } else {
        if args.first()?.as_str() != "x" {
            return None;
        }
        args = &args[1..];
    }
    if args.first().is_some_and(|v| v == "--no-install") {
        args = &args[1..];
    }
    if args.len() < 2 || args[0] != "vitest" || args[1] != "run" {
        return None;
    }
    Some((directory, args[1..].to_vec()))
}

/// `pnpm exec vitest ...`. The sink runs the project's own Vitest, never pnpm,
/// so only the bare form is read; a pnpm option before the tool (`-c` runs a
/// shell, `-r`/`--filter` fan out) is not Vitest.
fn pnpm_exec_vitest(command: &[String]) -> bool {
    basename(command) == "pnpm"
        && matches!(command.get(1..3), Some([exec, tool]) if exec == "exec" && tool == "vitest")
}

pub fn vitest_arguments(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    let argv = normalized_command(command)?;
    let name = basename(&argv);
    let runtime = node_runtime_args(&argv)?;
    let invocation = bun_vitest_invocation(&argv);
    let args = if let Some((_, args)) = invocation.filter(|_| matches!(name, "bun" | "bunx")) {
        args
    } else if matches!(name, "bunx" | "npx") {
        let mut args = &argv[1..];
        if args.first().is_some_and(|v| v == "--no-install") {
            args = &args[1..];
        }
        if args.first().is_none_or(|v| v != "vitest") {
            return invalid_vitest();
        }
        args[1..].to_vec()
    } else if pnpm_exec_vitest(&argv) {
        argv[3..].to_vec()
    } else if name == "vitest" {
        argv[1..].to_vec()
    } else if matches!(name, "node" | "nodejs") {
        let args = &argv[1 + runtime.len()..];
        if args.len() < 2 || !args[0].ends_with("/node_modules/vitest/vitest.mjs") {
            return invalid_vitest();
        }
        args[1..].to_vec()
    } else {
        return invalid_vitest();
    };
    if args.first().is_none_or(|v| v != "run")
        || args
            .iter()
            .any(|v| matches!(v.as_str(), ";" | "&&" | "||" | "|" | "|&" | "&"))
    {
        return Err(RestrictedPytestError::new(
            VITEST_INVALID,
            "Protected Vitest requires direct run argv.",
        ));
    }
    Ok(args)
}

fn invalid_vitest<T>() -> Result<T, RestrictedPytestError> {
    Err(RestrictedPytestError::new(
        VITEST_INVALID,
        "Only local Vitest run is supported.",
    ))
}

/// The command a virtualenv activation hands its verdict to, or null when
/// the activation is not one the scan can read through. A sink that plans the
/// call again has to plan the text the pre-tool pass answered for, or it
/// refuses the work that answer already admitted.
fn venv_activation_target(input: &Value) -> Value {
    let text = input
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let context = crate::pretool::PathContext {
        home_dir: input.get("home").and_then(Value::as_str),
        cwd: input.get("cwd").and_then(Value::as_str),
        ..Default::default()
    };
    crate::pretool::generic::venv_activation_target(text, context)
        .map_or(Value::Null, Value::String)
}

pub fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if operation == "venv_activation_target" {
        return Some(json!({ "value": venv_activation_target(input) }));
    }
    if !matches!(
        operation,
        "node_runtime_args"
            | "python_runtime_args"
            | "inline_eval"
            | "test_script"
            | "bun_vitest_invocation"
            | "tsx_test_invocation"
            | "vitest_arguments"
            | "contained_kind"
    ) {
        return None;
    }
    let command = input.get("command").cloned().unwrap_or_else(|| json!([]));
    let Ok(command) = serde_json::from_value::<Vec<String>>(command) else {
        return Some(crate::restricted_command::error_reply(
            RestrictedPytestError::new(
                "pytest_restricted_invalid_command",
                "Invalid restricted execution request.",
            ),
        ));
    };
    let result = match operation {
        "node_runtime_args" => node_runtime_args(&command).map(|v| json!(v)),
        "python_runtime_args" => Ok(json!(python_runtime_args(&command))),
        "inline_eval" => inline_eval(&command).map(|v| json!(v)),
        "test_script" => Ok(json!(named_test_script(
            input.get("value").and_then(Value::as_str).unwrap_or(""),
            input.get("node").and_then(Value::as_bool).unwrap_or(false)
        ))),
        "bun_vitest_invocation" => Ok(json!(bun_vitest_invocation(&command))),
        "tsx_test_invocation" => tsx_test_invocation(&command).map(|value| json!(value)),
        "vitest_arguments" => vitest_arguments(&command).map(|v| json!(v)),
        "contained_kind" => contained_kind(&command),
        _ => unreachable!(),
    };
    Some(match result {
        Ok(value) => json!({"value":value}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}

fn contained_kind(command: &[String]) -> Result<Value, RestrictedPytestError> {
    let inline = inline_eval(command)?;
    let name = basename(command);
    let runtime = if matches!(name, "node" | "nodejs") {
        node_runtime_args(command)?
    } else {
        vec![]
    };
    let index = 1 + runtime.len();
    let node_test =
        command.get(index).is_some_and(|v| v == "--test") && matches!(name, "node" | "nodejs");
    let bun = bun_vitest_invocation(command);
    let entries = command.iter().skip(1).take(2);
    let vitest = !command.is_empty()
        && (matches!(name, "bunx" | "npx" | "vitest")
            || pnpm_exec_vitest(command)
            || bun.is_some()
            || tsx_test_invocation(command)?.is_some()
            || (matches!(name, "node" | "nodejs")
                && entries
                    .clone()
                    .any(|v| v.ends_with("/node_modules/vitest/vitest.mjs"))));
    let node_tool = bun.is_none()
        && !pnpm_exec_vitest(command)
        && !command.is_empty()
        && (matches!(
            name,
            "eslint" | "tsc" | "vite" | "prettier" | "bun" | "npm" | "pnpm" | "yarn"
        ) || (matches!(name, "bunx" | "npx")
            && entries
                .clone()
                .any(|v| matches!(v.as_str(), "eslint" | "tsc" | "vite" | "prettier")))
            || (matches!(name, "node" | "nodejs")
                && entries.clone().any(|v| {
                    [
                        "eslint/bin/eslint.js",
                        "typescript/bin/tsc",
                        "vite/bin/vite.js",
                        "prettier/bin/prettier.cjs",
                        "prettier/bin-prettier.js",
                    ]
                    .iter()
                    .any(|entry| local_package_entry(v, entry))
                })));
    Ok(
        json!({"inline_eval":inline,"node_test":node_test,"vitest":vitest,"git":name=="git","node_tool":node_tool}),
    )
}
