//! Native command/effect-composition evaluator.
//!
//! `command_effect_decide` resident op (RTM-008). The contract lives in
//! `guard-contracts::command_effect`; this module owns the evaluator. The
//! factor/lattice/decision plane is ported verbatim in
//! `guard-command::command_evaluation::evaluate_command` (36/36 oracle
//! parity); the shell-read model (`shell_read_floor_factors` →
//! `assess_shell_reads`) is ported in `guard-command`. This op wires the
//! request fields into the typed evaluator:
//!   - `canonical_command` → `CanonicalCommandV1` → `CanonicalCommand`
//!   - `control_layers`    → wire layer dicts → `ExtensionControlLayer`
//!   - `control_snapshot`  → `NativeCommandControlBindingV1`
//!   - `workflow_authorization` → `GitHubWorkflowAuthorizationV1`
//!   - `read_factors`      → `shell_read_floor_factors(command_text, …)`
//!   - `write_redirect`    → any `>`/`>>`/`>|` redirect on the rich model

use std::path::PathBuf;

use super::context_digest_json::write_canonical_json_with_limit;
#[cfg(unix)]
use guard_command::command_shell_read_factors::shell_read_floor_factors;
use guard_command::extension_control::{
    ControlLayerKind, ControlState, ControlTarget, ControlTargetKind, ExtensionControl,
    ExtensionControlLayer,
};
use guard_command::{
    canonical_command::CanonicalCommand,
    github_workflow_authorization::GitHubWorkflowAuthorizationV1,
    native_command_catalog::packaged_command_catalog, parse_shell_command, CanonicalCommandV1,
    CommandModelRequestV1,
};
use guard_contracts::{
    CommandEffectRequestV1, CommandEffectResultV1, NativeCommandControlBindingV1,
    COMMAND_EFFECT_REQUEST_SCHEMA, COMMAND_EFFECT_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde::Deserialize;

fn request_digest(request: &CommandEffectRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_command_effect_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_command_effect_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

/// Wire `ExtensionControlLayer` (extension_control_authority `_layer_to_value`
/// :189-202): `controls` entries carry flattened `target_kind`/`target_id`/
/// `state` instead of the typed `ControlTarget`.
#[derive(Deserialize)]
struct WireControl {
    target_kind: ControlTargetKind,
    target_id: String,
    state: ControlState,
}

#[derive(Deserialize)]
struct WireControlLayer {
    schema_version: String,
    kind: ControlLayerKind,
    catalog_digest: String,
    global_lockdown: bool,
    controls: Vec<WireControl>,
}

fn control_layers_from_value(
    value: &serde_json::Value,
) -> Result<Vec<ExtensionControlLayer>, String> {
    let wire: Vec<WireControlLayer> = serde_json::from_value(value.clone())
        .map_err(|_| "native_command_effect_invalid_control_layers".to_owned())?;
    let mut layers = Vec::with_capacity(wire.len());
    for layer in wire {
        let mut controls = Vec::with_capacity(layer.controls.len());
        for control in layer.controls {
            let target = ControlTarget::new(control.target_kind, control.target_id)
                .map_err(|_| "native_command_effect_invalid_control_target".to_owned())?;
            controls.push(ExtensionControl {
                target,
                state: control.state,
            });
        }
        let layer = ExtensionControlLayer {
            schema_version: layer.schema_version,
            kind: layer.kind,
            catalog_digest: layer.catalog_digest,
            global_lockdown: layer.global_lockdown,
            controls,
        };
        layer
            .validate()
            .map_err(|_| "native_command_effect_invalid_control_layer".to_owned())?;
        layers.push(layer);
    }
    Ok(layers)
}

pub(crate) fn evaluate_command_effect_request(
    request: &CommandEffectRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let result = evaluate(request);
    let (status, code, payload) = match result {
        Ok(evaluation) => (
            "ok".to_owned(),
            "ok".to_owned(),
            Some(evaluation.to_payload()),
        ),
        Err(code) => ("error".to_owned(), code, None),
    };
    let result = CommandEffectResultV1 {
        schema: COMMAND_EFFECT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    };
    crate::encode_response(&result)
}

fn evaluate(
    request: &CommandEffectRequestV1,
) -> Result<guard_command::CompositeCommandEvaluation, String> {
    if request.schema != COMMAND_EFFECT_REQUEST_SCHEMA {
        return Err("native_command_effect_schema_mismatch".to_owned());
    }
    let cwd = PathBuf::from(&request.cwd);
    let home_dir = PathBuf::from(&request.home_dir);
    // Rich parse for redirects (write_redirect) and segment model; the eval
    // `CanonicalCommand` projects the wire `canonical_command` when present,
    // else parses on its own.
    let rich = parse_shell_command(
        &request.command_text,
        Some(&cwd),
        Some(&home_dir),
        "posix",
        "shell_string",
        "guard-shell",
        false,
    );
    let _write_redirect = rich.redirects.iter().any(|r| {
        let op = r.operator.trim_start_matches(|c: char| c.is_ascii_digit());
        op == ">" || op == ">>" || op == ">|"
    });
    let canonical_v1: CanonicalCommandV1 = match &request.canonical_command {
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|_| "native_command_effect_invalid_canonical_command".to_owned())?,
        None => {
            // Parse via the command-model op path (no request envelope here —
            // the fields the V1 needs are on the wire request).
            let model_request = CommandModelRequestV1 {
                command: request.command_text.clone(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "guard-shell".to_owned(),
            };
            guard_command::parse_command(&model_request)
                .map_err(|_| "native_command_effect_invalid_canonical_command".to_owned())?
        }
    };
    let _canonical = CanonicalCommand::from_v1(&canonical_v1);
    let _registry = packaged_command_catalog()
        .map_err(|_| "native_command_effect_catalog_unavailable".to_owned())?;
    let _control_snapshot: NativeCommandControlBindingV1 = request
        .control_snapshot
        .as_ref()
        .ok_or_else(|| "native_command_effect_missing_control_snapshot".to_owned())
        .and_then(|v| {
            serde_json::from_value(v.clone())
                .map_err(|_| "native_command_effect_invalid_control_snapshot".to_owned())
        })?;
    let _control_layers = control_layers_from_value(&request.control_layers)?;
    let _workflow_authorization: Option<GitHubWorkflowAuthorizationV1> = request
        .workflow_authorization
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|_| "native_command_effect_invalid_workflow_authorization".to_owned())?;
    // Read-floor factors are POSIX-only (shell path identity relies on stat
    // fields); fail closed on non-unix before binding `read_factors` so the
    // diverging branch never reaches `evaluate_command`'s slice coercion.
    #[cfg(not(unix))]
    return Err("native_command_effect_read_floors_unsupported".to_owned());
    #[cfg(unix)]
    let read_factors = shell_read_floor_factors(
        &request.command_text,
        &_canonical.security_identity,
        Some(&cwd),
        Some(&home_dir),
    );
    #[cfg(unix)]
    guard_command::evaluate_command(
        &_canonical,
        &request.native_extension_evidence,
        &_registry,
        &_control_snapshot,
        &_control_layers,
        request.compatibility_action_class.as_deref(),
        request.compatibility_reason.as_deref(),
        _workflow_authorization.as_ref(),
        &read_factors,
        _write_redirect,
    )
    .map_err(|code| format!("native_command_effect_{code}"))
}

/// CLI byte-path entry (`--stdin`).
#[allow(dead_code)]
pub(crate) fn evaluate_command_effect_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: CommandEffectRequestV1 = crate::strict_json::from_value(value)
        .map_err(|_| "native_command_effect_invalid_json".to_owned())?;
    evaluate_command_effect_request(&request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_contracts::{NativeCommandControlBindingV1, NativeExtensionControlLayerV1};
    use serde_json::{json, Value};

    fn digest64(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    fn valid_control_snapshot() -> NativeCommandControlBindingV1 {
        let layer = NativeExtensionControlLayerV1 {
            schema_version: "1.0.0".to_owned(),
            kind: "local-admin".to_owned(),
            catalog_digest: digest64(0xaa),
            global_lockdown: false,
            controls: Vec::new(),
        };
        let mut binding = NativeCommandControlBindingV1 {
            schema: guard_contracts::NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.to_owned(),
            program_digest: digest64(0x11),
            catalog_digest: digest64(0xaa),
            trust_digest: digest64(0x22),
            health: "protected".to_owned(),
            revision: 1,
            managed_revision: 1,
            effective_digest: String::new(),
            layers: vec![layer],
            authority: None,
        };
        binding.effective_digest = binding.compute_effective_digest().unwrap();
        binding
    }

    fn observations_digest() -> String {
        let batch = json!({
            "observations": [],
            "permission_observations": [],
            "evaluation_error": Value::Null,
        });
        guard_command::native_command_program::digest_value(
            b"hol-guard.native-command-observations.v1\0",
            &batch,
        )
        .unwrap()
    }

    fn request_json(command: &str, snapshot: &NativeCommandControlBindingV1) -> Value {
        let registry = packaged_command_catalog().unwrap();
        let command_extensions = json!({
            "schema": guard_contracts::NATIVE_COMMAND_OBSERVATIONS_SCHEMA,
            "binding": {
                "schema": guard_contracts::NATIVE_COMMAND_RECEIPT_BINDING_SCHEMA,
                "program_digest": registry.program_digest,
                "catalog_digest": registry.catalog_digest,
                "trust_digest": snapshot.trust_digest,
                "control_revision": snapshot.revision,
                "managed_control_revision": snapshot.managed_revision,
                "control_effective_digest": snapshot.effective_digest,
                "observations_digest": observations_digest(),
                "observation_count": 0,
                "uncertainty_count": 0,
            },
            "observations": [],
            "permission_observations": [],
            "evaluation_error": Value::Null,
        });
        let evidence = json!({
            "command_model": { "normalized_text": command.trim() },
            "command_extensions": command_extensions,
            "decision": "deny",
            "policy_action": "review",
            "minimum_action": "review",
            "explicitly_benign": false,
        });
        json!({
            "operation": "command_effect_decide",
            "request": {
                "schema": COMMAND_EFFECT_REQUEST_SCHEMA,
                "request_id": "req-test",
                "command_text": command,
                "canonical_command": Value::Null,
                "compatibility_action_class": Value::Null,
                "compatibility_reason": Value::Null,
                "native_extension_evidence": evidence,
                "control_snapshot": serde_json::to_value(snapshot).unwrap(),
                "control_layers": [],
                "workflow_authorization": Value::Null,
                "cwd": "/tmp",
                "home_dir": "/tmp/rtm008-home",
            }
        })
    }

    // POSIX read floors are not compiled on Windows; production fail-closes
    // before evaluate_command. Do not weaken that to satisfy this assertion.
    #[cfg(unix)]
    #[test]
    fn command_effect_op_decides_over_resident_transport() {
        std::fs::create_dir_all("/tmp/rtm008-home").ok();
        let snapshot = valid_control_snapshot();

        let out = crate::resident_protocol::evaluate_resident_bytes(
            request_json("ls -la", &snapshot).to_string().as_bytes(),
            None,
        )
        .expect("benign op should return bytes");
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["status"], "ok", "benign op errored: {}", v["code"]);
        assert_eq!(v["schema"], COMMAND_EFFECT_RESULT_SCHEMA);

        let out = crate::resident_protocol::evaluate_resident_bytes(
            request_json("cat ~/.ssh/id_rsa", &snapshot)
                .to_string()
                .as_bytes(),
            None,
        )
        .expect("secret-read op should return bytes");
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["status"], "ok", "secret-read op errored: {}", v["code"]);
        let payload = v["payload"].as_object().expect("payload object");
        let text = serde_json::to_string(payload).unwrap();
        assert!(
            text.contains("critical.local-secret-read") || text.contains("shell-read-floors"),
            "expected shell-read factor in payload: {text}"
        );
    }

    #[test]
    fn command_effect_op_rejects_bad_schema() {
        let snapshot = valid_control_snapshot();
        let mut req = request_json("ls", &snapshot);
        req["request"]["schema"] = json!("bogus");
        let out =
            crate::resident_protocol::evaluate_resident_bytes(req.to_string().as_bytes(), None)
                .expect("bad-schema op should still return bytes");
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["status"], "error");
        assert_eq!(v["code"], "native_command_effect_schema_mismatch");
    }
}
