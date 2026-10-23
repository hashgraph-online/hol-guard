//! Offline compiler front end. Reads bounded stdin, never executes or imports sources.
//! Hosts the `guard-command-source` CLI so the runtime binary can answer the
//! same operations with byte-identical output.

use crate::native_command_program::packaged_command_program_bytes;
use crate::native_command_program::source::{
    compare_programs, compile_build_request, compile_pack_stream, compile_source_stream,
    descriptor_schema, evaluate_batch, run_fixtures, source_schema, MAX_SOURCE_INPUT_BYTES,
};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};

#[cfg(guard_source_bootstrap)]
#[path = "source_compiler_receipt.rs"]
mod receipt;

pub fn compiler_info() -> Value {
    json!({"schema":"guard.source-compiler-capabilities.v1",
        "implementation_digest":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"),
        "embedded_catalog":!cfg!(guard_source_bootstrap)})
}

#[cfg(not(guard_source_bootstrap))]
static EXPORTED_TRUST_MAP: &[u8] = guard_command_catalog_data::TRUST_MAP_JSON;
// The bootstrap shadow lib produces no packaged output; the empty slice keeps
// `include_bytes!` valid and `export-trust` fails closed like the embedded
// program and catalog bootstrap paths.
#[cfg(guard_source_bootstrap)]
static EXPORTED_TRUST_MAP: &[u8] = &[];

#[cfg(not(guard_source_bootstrap))]
static EXPORTED_BUILD: &[u8] = guard_command_catalog_data::BUILD_JSON_ZST;

fn exported_build_bytes() -> &'static [u8] {
    #[cfg(not(guard_source_bootstrap))]
    {
        static DECODED: std::sync::OnceLock<Box<[u8]>> = std::sync::OnceLock::new();
        DECODED
            .get_or_init(|| {
                crate::packaged_blob::decode(
                    EXPORTED_BUILD,
                    guard_command_catalog_data::BUILD_JSON_LEN,
                    guard_command_catalog_data::BUILD_JSON_SHA256,
                )
            })
            .as_ref()
    }
    #[cfg(guard_source_bootstrap)]
    {
        &[]
    }
}

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
    let assessment = crate::github_command_capabilities::classify_github_cli(&args);
    let operand = crate::github_command_capabilities::static_markdown_pr_body_file_operand(&args);
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

/// True exactly for the argument shapes this front end accepts, so a host
/// (standalone bin or the runtime) can route them without colliding with the
/// host's own commands. `check` routes even with a malformed digest so the
/// caller gets the compiler's digest error instead of a host usage error.
pub fn is_command(arguments: &[String]) -> bool {
    let Some(operation) = arguments.first().map(String::as_str) else {
        return false;
    };
    match operation {
        "compiler-info"
        | "compile-bootstrap-stream"
        | "export-trust"
        | "export-built"
        | "authoring-context"
        | "authoring-index"
        | "authoring-admission"
        | "bundle-metadata"
        | "bundle-compatibility"
        | "schema"
        | "descriptor-schema"
        | "github-classify"
        | "github-classify-serve"
        | "validate"
        | "compile"
        | "compile-stream"
        | "compile-packs"
        | "test"
        | "compare"
        | "evaluate-batch" => arguments.len() == 1,
        "check" => arguments.len() == 2,
        "check-pack-cache" => arguments.len() == 3,
        _ => false,
    }
}

fn run(arguments: &[String]) -> Result<Value, &'static str> {
    if arguments == ["bundle-compatibility"] {
        return crate::bundle_metadata::compatibility_stream();
    }
    if arguments == ["authoring-index"] {
        return crate::native_command_program::source::authoring_index();
    }
    if arguments == ["authoring-context"] {
        return crate::native_command_program::source::authoring_context();
    }
    if arguments == ["compiler-info"] {
        return Ok(compiler_info());
    }
    if arguments == ["export-trust"] {
        return serde_json::from_slice(EXPORTED_TRUST_MAP)
            .map_err(|_| "command_source_trust_output_invalid");
    }
    if arguments == ["export-built"] {
        let mut output: Value = serde_json::from_slice(exported_build_bytes())
            .map_err(|_| "command_source_build_output_invalid")?;
        output["program"] = serde_json::from_slice(packaged_command_program_bytes())
            .map_err(|_| "command_source_build_output_invalid")?;
        // The catalog ships inside command-catalog.v1.json; reinsert the same
        // projection here instead of storing a second copy in the envelope.
        output["catalog"] = serde_json::from_slice::<Value>(
            crate::native_command_catalog::embedded_catalog_bytes(),
        )
        .map_err(|_| "command_source_build_output_invalid")?
        .get("catalog")
        .cloned()
        .ok_or("command_source_build_output_invalid")?;
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
    if operation == "check-pack-cache" {
        if arguments.len() != 3 {
            return Err("command_pack_cache_usage_invalid");
        }
        let program = crate::native_command_program::NativeCommandProgram::from_pack_cache(
            std::path::Path::new(&arguments[1]),
            &arguments[2],
            crate::native_command_program::PackAdmissionBudget::resident(),
        )?;
        return Ok(
            json!({"schema":"guard.command-pack-cache-check.v1", "engine":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"),
            "program_digest":program.program_digest,"catalog_digest":program.catalog_digest,"trust_digest":program.trust_digest,
            "extensions":program.extensions.len(),"rules":program.rules.len()}),
        );
    }
    if !matches!(
        operation,
        "validate"
            | "compile"
            | "check"
            | "test"
            | "compare"
            | "evaluate-batch"
            | "authoring-admission"
            | "bundle-metadata"
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
    if operation == "bundle-metadata" {
        return crate::bundle_metadata::evaluate(&bytes);
    }
    if operation == "authoring-admission" {
        return crate::native_command_program::source::authoring_admission(&bytes);
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

/// Run one accepted argument vector to completion, returning the process exit
/// code. Stdout bytes and error JSON match the standalone compiler exactly.
pub fn main(arguments: Vec<String>) -> i32 {
    if arguments == ["github-classify-serve"] {
        return github_classify_serve();
    }
    let result = if arguments == ["compile-bootstrap-stream"] {
        #[cfg(guard_source_bootstrap)]
        {
            receipt::compile(std::io::stdin().lock())
        }
        #[cfg(not(guard_source_bootstrap))]
        {
            Err((
                "command_source_bootstrap_operation_unsupported",
                String::new(),
            ))
        }
    } else if arguments == ["compile-packs"] {
        compile_pack_stream(std::io::stdin().lock(), std::io::stdout().lock())
            .map_err(|code| (code, String::new()))
    } else if arguments == ["compile-stream"] {
        compile_source_stream(std::io::stdin().lock())
            .and_then(|output| {
                serde_json::to_value(output).map_err(|_| "command_source_encoding_failed".into())
            })
            .map_err(|error| {
                (
                    error.code,
                    error
                        .record
                        .map(|index| format!("/records/{index}"))
                        .unwrap_or_default(),
                )
            })
    } else {
        run(&arguments).map_err(|code| (code, String::new()))
    };
    let (value, code) = match result {
        Ok(value) => {
            let code = if value.get("ok") == Some(&Value::Bool(false)) {
                1
            } else {
                0
            };
            (value, code)
        }
        Err((error, pointer)) => (json!({"ok":false,"code":error,"pointer":pointer}), 2),
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &value).is_err() || stdout.write_all(b"\n").is_err() {
        return 2;
    }
    code
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
        let catalog: Value =
            serde_json::from_slice(crate::native_command_catalog::embedded_catalog_bytes())
                .unwrap();
        assert_eq!(output["catalog"], catalog["catalog"]);
        assert_eq!(output["catalog_projection_kind"], "complete");
        assert!(!output["descriptors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn is_command_matches_only_the_accepted_argument_shapes() {
        for accepted in [
            vec!["export-trust"],
            vec!["export-built"],
            vec!["schema"],
            vec!["descriptor-schema"],
            vec!["github-classify"],
            vec!["github-classify-serve"],
            vec!["validate"],
            vec!["compile"],
            vec!["compile-stream"],
            vec!["test"],
            vec!["compare"],
            vec!["evaluate-batch"],
            vec!["check", "not-a-digest"],
            vec!["check", &"f".repeat(64)],
        ] {
            let owned: Vec<String> = accepted.iter().map(|item| item.to_string()).collect();
            assert!(is_command(&owned), "{owned:?}");
        }
        for rejected in [
            vec![] as Vec<&str>,
            vec!["check"],
            vec!["check", "f".repeat(64).as_str(), "extra"],
            vec!["compile", "extra"],
            vec!["export-trust", "extra"],
            vec!["unknown-op"],
            vec!["self-test"],
        ] {
            let owned: Vec<String> = rejected.iter().map(|item| item.to_string()).collect();
            assert!(!is_command(&owned), "{owned:?}");
        }
    }
}
