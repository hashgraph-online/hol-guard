//! Offline compiler front end. Reads bounded stdin, never executes or imports sources.

use guard_command::native_command_program::packaged_command_program_bytes;
use guard_command::native_command_program::source::{
    compare_programs, compile_build_request, descriptor_schema, evaluate_batch, run_fixtures,
    source_schema, MAX_SOURCE_INPUT_BYTES,
};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};

/// Offline GitHub CLI classification for test harnesses that evaluate commands
/// without a resident. Reads `{"args": [...]}` and returns the assessment.
fn github_classify() -> Result<Value, &'static str> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_SOURCE_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "github_classify_input_read_failed")?;
    if bytes.len() > MAX_SOURCE_INPUT_BYTES {
        return Err("github_classify_input_too_large");
    }
    let request: Value =
        serde_json::from_slice(&bytes).map_err(|_| "github_classify_input_invalid")?;
    classify_request(&request)
}

fn classify_request(request: &Value) -> Result<Value, &'static str> {
    let args = request
        .get("args")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or("github_classify_input_invalid")?;
    let assessment = guard_command::github_command_capabilities::classify_github_cli(&args);
    let operand =
        guard_command::github_command_capabilities::static_markdown_pr_body_file_operand(&args);
    Ok(json!({
        "capability": assessment.capability.as_str(),
        "reason_code": assessment.reason_code,
        "detail": assessment.detail,
        "capabilities": assessment.capabilities.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
        "pr_body_file_operand": operand,
    }))
}

/// Line-delimited variant of `github-classify` so a harness classifies many
/// commands through one long-lived process instead of one spawn per command.
fn github_classify_serve() -> i32 {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return 2 };
        if line.len() > MAX_SOURCE_INPUT_BYTES {
            return 2;
        }
        let value = serde_json::from_str::<Value>(&line)
            .map_err(|_| "github_classify_input_invalid")
            .and_then(|request| classify_request(&request))
            .unwrap_or_else(|code| json!({"ok":false,"code":code}));
        if serde_json::to_writer(&mut stdout, &value).is_err()
            || stdout.write_all(b"\n").is_err()
            || stdout.flush().is_err()
        {
            return 2;
        }
    }
    0
}

fn run(arguments: &[String]) -> Result<Value, &'static str> {
    if arguments == ["export-trust"] {
        return serde_json::from_slice(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/trust-class-map.v1.json"
        )))
        .map_err(|_| "command_source_trust_output_invalid");
    }
    if arguments == ["export-built"] {
        let mut output: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/native-command-build.v1.json"
        )))
        .map_err(|_| "command_source_build_output_invalid")?;
        output["program"] = serde_json::from_slice(packaged_command_program_bytes())
            .map_err(|_| "command_source_build_output_invalid")?;
        return Ok(output);
    }
    if arguments == ["schema"] {
        return Ok(source_schema());
    }
    if arguments == ["descriptor-schema"] {
        return Ok(descriptor_schema());
    }
    if arguments == ["github-classify"] {
        return github_classify();
    }
    let Some(operation) = arguments.first().map(String::as_str) else {
        return Err("command_source_usage_expected_schema_validate_compile_check_or_test");
    };
    if !matches!(
        operation,
        "validate" | "compile" | "check" | "test" | "compare" | "evaluate-batch"
    ) || arguments.len() != if operation == "check" { 2 } else { 1 }
    {
        return Err("command_source_usage_expected_schema_validate_compile_check_or_test");
    }
    if operation == "check"
        && (arguments[1].len() != 64
            || !arguments[1]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err("command_source_expected_digest_invalid");
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_SOURCE_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "command_source_input_read_failed")?;
    if bytes.len() > MAX_SOURCE_INPUT_BYTES {
        return Err("command_source_bytes_invalid");
    }
    if operation == "test" {
        return run_fixtures(&bytes);
    }
    if operation == "compare" {
        return compare_programs(&bytes);
    }
    if operation == "evaluate-batch" {
        return evaluate_batch(&bytes);
    }
    let output = compile_build_request(&bytes)?;
    if operation == "check"
        && output.program["program_digest"].as_str() != Some(arguments[1].as_str())
    {
        return Err("command_source_generated_program_stale");
    }
    if operation == "compile" {
        serde_json::to_value(output).map_err(|_| "command_source_encoding_failed")
    } else {
        Ok(
            json!({"ok":true,"program_digest":output.program["program_digest"],
            "source_digest":output.source_digest,"implementation_digest":output.implementation_digest,
            "extensions":output.program["extensions"].as_array().map(Vec::len),
            "rules":output.program["rules"].as_array().map(Vec::len)}),
        )
    }
}

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments == ["github-classify-serve"] {
        std::process::exit(github_classify_serve());
    }
    let (value, code) = match run(&arguments) {
        Ok(value) => {
            let code = if value.get("ok") == Some(&Value::Bool(false)) {
                1
            } else {
                0
            };
            (value, code)
        }
        Err(error) => (json!({"ok":false,"code":error,"pointer":""}), 2),
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &value).is_err() || stdout.write_all(b"\n").is_err() {
        std::process::exit(2);
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_build_preserves_program_and_catalog_binding() {
        let output = run(&["export-built".to_owned()]).unwrap();
        let program: Value = serde_json::from_slice(packaged_command_program_bytes()).unwrap();
        assert_eq!(output["program"], program);
        let ids = |rows: &Value| {
            rows.as_array()
                .unwrap()
                .iter()
                .map(|row| row["extension_id"].as_str().unwrap().to_owned())
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(ids(&output["catalog"]), ids(&program["extensions"]));
        assert_eq!(output["catalog_projection_kind"], "complete");
        assert!(!output["descriptors"].as_array().unwrap().is_empty());
    }
}
