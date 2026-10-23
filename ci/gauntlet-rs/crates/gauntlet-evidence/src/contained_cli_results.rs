//! Data-only parity for the contained CLI result checks at the end of Python's
//! `verify_private_cell_runtime`. The caller still owns signatures and kernel
//! custody; this reducer never grants execution eligibility.

use crate::crypto::{is_sha256, sha256};
use crate::{EvidenceError, Result};
use serde_json::{json, Value};

const SWITCHES: [&str; 7] = [
    "--harness",
    "--guard-home",
    "--home",
    "--workspace",
    "--request-file",
    "--request-sha256",
    "--timeout-seconds",
];
const NAMESPACES: [&str; 3] = ["mount_namespace", "pid_namespace", "network_namespace"];

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .ok_or(EvidenceError::Invalid("contained result field missing"))
}

fn request_path(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    parts.len() == 5
        && parts[0].is_empty()
        && parts[1] == "product"
        && parts[2] == "home"
        && !matches!(parts[3], "" | "." | "..")
        && parts[4] == "request.json"
}

fn lower_hex_16(value: &str) -> bool {
    value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sample_matches(
    sample: &Value,
    controller: &Value,
    agent: &Value,
    product_user_namespace: &str,
) -> Result<bool> {
    let identity = &sample["identity"];
    if identity["effective_uid"].as_i64() != Some(10004)
        || identity["effective_gid"].as_i64() != Some(10004)
        || identity["no_new_privileges"].as_i64() != Some(1)
        || field(identity, "boot_id")? != field(controller, "boot_id")?
    {
        return Ok(false);
    }
    let capabilities = field(identity, "effective_capabilities")?;
    if !lower_hex_16(capabilities) {
        return Ok(false);
    }
    for name in NAMESPACES {
        let observed = field(identity, name)?;
        if observed == field(controller, name)? || observed == field(agent, name)? {
            return Ok(false);
        }
    }
    let allowed_capabilities = if capabilities == "0000000000000000" {
        true
    } else {
        let user_namespace = field(sample, "user_namespace")?;
        user_namespace != product_user_namespace
            && user_namespace.starts_with("user:[")
            && user_namespace.ends_with(']')
            && user_namespace[6..user_namespace.len() - 1]
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            && user_namespace.len() > 7
    };
    Ok(allowed_capabilities)
}

/// Check supplied result rows against Python's fixed installed CLI form,
/// output digests and reported outside process samples. No producer is read or
/// authenticated by this function.
pub fn verify_contained_cli_results(
    plane: &Value,
    expected_settings: &Value,
    agent_identity: &Value,
) -> Result<Value> {
    let executions = plane["executions"]
        .as_array()
        .filter(|rows| rows.len() <= 128)
        .ok_or(EvidenceError::Invalid("contained result inventory invalid"))?;
    let runtime_prefix = field(plane, "runtime_prefix")?;
    let workspace = field(plane, "workspace_path")?;
    let controller = &plane["controller_identity"];
    let product_user_namespace = field(plane, "product_user_namespace")?;
    let home = if matches!(
        expected_settings["package_version"].as_str(),
        Some("3.48.0" | "3.49.0" | "3.50.0a5")
    ) {
        "/runtime/home"
    } else {
        "/product/home"
    };
    for result in executions {
        let command = result["native_command"]
            .as_array()
            .filter(|parts| parts.len() == 21)
            .ok_or(EvidenceError::Invalid(
                "contained result lacks the normal installed CLI",
            ))?;
        let command: Vec<_> = command
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or(EvidenceError::Invalid(
                "contained result lacks the normal installed CLI",
            ))?;
        if command.iter().any(|part| part.len() > 4096)
            || command[..7]
                != [
                    format!("{runtime_prefix}/bin/python").as_str(),
                    "-I",
                    "-B",
                    "-m",
                    "codex_plugin_scanner.cli",
                    "guard",
                    "execute-contained-test",
                ]
        {
            return Err(EvidenceError::Invalid(
                "contained result lacks the normal installed CLI",
            ));
        }
        for (index, switch) in SWITCHES.iter().enumerate() {
            if command[7 + index * 2] != *switch {
                return Err(EvidenceError::Invalid(
                    "contained CLI argument inventory differs",
                ));
            }
        }
        let options: Vec<_> = (0..SWITCHES.len())
            .map(|index| command[8 + index * 2])
            .collect();
        let request_sha = options[5];
        let timeout = options[6];
        if options[0] != "omp"
            || options[1] != "/product/guard"
            || options[2] != home
            || options[3] != workspace
            || !request_path(options[4])
            || !is_sha256(request_sha)
            || result["request_sha256"] != request_sha
            || timeout.is_empty()
            || !timeout.bytes().all(|byte| byte.is_ascii_digit())
            || !timeout
                .parse::<u16>()
                .is_ok_and(|seconds| (1..=900).contains(&seconds))
        {
            return Err(EvidenceError::Invalid(
                "contained workspace/request/deadline binding differs",
            ));
        }
        if result["exit_code"].as_i64().is_none() {
            return Err(EvidenceError::Invalid(
                "actual contained CLI exit status required",
            ));
        }
        for name in ["stdout", "stderr"] {
            let text = field(result, name)?;
            if sha256(text.as_bytes()) != field(result, &format!("{name}_sha256"))? {
                return Err(EvidenceError::Invalid("contained output digest differs"));
            }
        }
        let samples = result["kernel_process_samples"]
            .as_array()
            .filter(|rows| !rows.is_empty() && rows.len() <= 1000)
            .ok_or(EvidenceError::Invalid(
                "contained result lacks outside samples or promotes claims",
            ))?;
        if result["product_claims_authenticated"] != false
            || result["containment_conformance_established"] != false
        {
            return Err(EvidenceError::Invalid(
                "contained result lacks outside samples or promotes claims",
            ));
        }
        let mut raw_command = Vec::new();
        for part in &command {
            raw_command.extend_from_slice(part.as_bytes());
            raw_command.push(0);
        }
        let command_sha256 = sha256(&raw_command);
        if !samples
            .iter()
            .any(|row| row["command_sha256"] == command_sha256)
        {
            return Err(EvidenceError::Invalid(
                "actual contained CLI was not independently sampled",
            ));
        }
        for sample in samples {
            if !sample_matches(sample, controller, agent_identity, product_user_namespace)? {
                return Err(EvidenceError::Invalid(
                    "contained descendant escaped privilege/namespace boundary",
                ));
            }
        }
    }
    Ok(json!({"checked_executions": executions.len(), "execution_eligible": false}))
}
