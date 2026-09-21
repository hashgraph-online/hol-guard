//! Offline compiler front end. Reads bounded stdin, never executes or imports sources.

use guard_command::native_command_program::source::{
    compare_programs, compile_build_request, descriptor_schema, evaluate_batch, run_fixtures,
    source_schema,
};
use serde_json::{json, Value};
use std::io::{Read, Write};

fn run(arguments: &[String]) -> Result<Value, &'static str> {
    if arguments == ["schema"] {
        return Ok(source_schema());
    }
    if arguments == ["descriptor-schema"] {
        return Ok(descriptor_schema());
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
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "command_source_input_read_failed")?;
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
