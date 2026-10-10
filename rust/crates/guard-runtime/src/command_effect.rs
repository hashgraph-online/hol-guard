//! Native command/effect-composition evaluator.
//!
//! `command_effect_decide` resident op (RTM-008). The contract lives in
//! `guard-contracts::command_effect`; the composition, floor lattice and
//! decision plane live in `guard_command::evaluate_command`. This module wires
//! the request into the typed evaluator:
//!   - `canonical_command`  -> `CanonicalCommandV1` -> `CanonicalCommand`
//!   - `control_snapshot`   -> `NativeCommandControlBindingV1`; the control
//!     layers, authority failure and authority evidence derive from it alone
//!   - `workflow_authorization` -> `GitHubWorkflowAuthorizationV1`
//!   - read floors          -> `shell_read_floor_factors(command_text, ..)`
//!
//! The evaluator never re-parses command text on its own authority.

use super::context_digest_json::write_canonical_json_with_limit;
use guard_contracts::{
    CommandEffectBatchRequestV1, CommandEffectBatchResultV1, CommandEffectRequestV1,
    CommandEffectResultV1, COMMAND_EFFECT_BATCH_MAX_BYTES, COMMAND_EFFECT_BATCH_MAX_ITEMS,
    COMMAND_EFFECT_BATCH_REQUEST_SCHEMA, COMMAND_EFFECT_BATCH_RESULT_SCHEMA,
    COMMAND_EFFECT_MAX_BYTES, COMMAND_EFFECT_REQUEST_SCHEMA, COMMAND_EFFECT_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

/// Canonical serialization of one request: the bytes its `request_sha256`
/// binds and the size the batch bound is measured against.
fn canonical_request_bytes(request: &CommandEffectRequestV1) -> Result<Vec<u8>, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_command_effect_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_command_effect_invalid")?;
    Ok(bytes)
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", digest_bytes(bytes))
}

/// Evaluate one request into its bound result. The single and batched ops share
/// this so a batched item can never be judged by a different rule set.
fn evaluate_to_result(
    request: &CommandEffectRequestV1,
    request_sha256: String,
) -> CommandEffectResultV1 {
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    CommandEffectResultV1 {
        schema: COMMAND_EFFECT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    }
}

pub(crate) fn evaluate_command_effect_request(
    request: &CommandEffectRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = digest_of(&canonical_request_bytes(request).map_err(str::to_owned)?);
    crate::encode_response(&evaluate_to_result(request, request_sha256))
}

fn refused_batch(request_id: &str, code: &str) -> Result<Vec<u8>, String> {
    crate::encode_response(&CommandEffectBatchResultV1 {
        schema: COMMAND_EFFECT_BATCH_RESULT_SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
        status: "error".to_owned(),
        code: code.to_owned(),
        items: Vec::new(),
    })
}

/// `command_effect_decide_batch`: one resident round trip for up to
/// `COMMAND_EFFECT_BATCH_MAX_ITEMS` independent single requests.
///
/// Fail-closed rules: a wrong schema, an empty batch, too many items, an
/// aggregate size over `COMMAND_EFFECT_BATCH_MAX_BYTES`, any item over the
/// single-op size bound, or an aggregate response over the resident response
/// limit refuses the whole batch with no partial result. Per-item failures
/// (schema, canonical command, control snapshot, evaluator rejection) are
/// reported on that item exactly as the single op reports them.
pub(crate) fn evaluate_command_effect_batch_request(
    batch: &CommandEffectBatchRequestV1,
) -> Result<Vec<u8>, String> {
    if batch.schema != COMMAND_EFFECT_BATCH_REQUEST_SCHEMA {
        return refused_batch(
            &batch.request_id,
            "native_command_effect_batch_schema_mismatch",
        );
    }
    if batch.items.is_empty() {
        return refused_batch(&batch.request_id, "native_command_effect_batch_empty");
    }
    if batch.items.len() > COMMAND_EFFECT_BATCH_MAX_ITEMS {
        return refused_batch(
            &batch.request_id,
            "native_command_effect_batch_too_many_items",
        );
    }
    let mut digests = Vec::with_capacity(batch.items.len());
    let mut total_bytes = 0usize;
    for item in &batch.items {
        let Ok(bytes) = canonical_request_bytes(item) else {
            return refused_batch(&batch.request_id, "native_command_effect_invalid");
        };
        if bytes.len() > COMMAND_EFFECT_MAX_BYTES {
            return refused_batch(
                &batch.request_id,
                "native_command_effect_batch_item_too_large",
            );
        }
        total_bytes = total_bytes.saturating_add(bytes.len());
        if total_bytes > COMMAND_EFFECT_BATCH_MAX_BYTES {
            return refused_batch(&batch.request_id, "native_command_effect_batch_too_large");
        }
        digests.push(digest_of(&bytes));
    }
    let items = batch
        .items
        .iter()
        .zip(digests)
        .map(|(item, digest)| evaluate_to_result(item, digest))
        .collect();
    match crate::encode_response(&CommandEffectBatchResultV1 {
        schema: COMMAND_EFFECT_BATCH_RESULT_SCHEMA.to_owned(),
        request_id: batch.request_id.clone(),
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        items,
    }) {
        Ok(bytes) => Ok(bytes),
        // An aggregate answer the resident cannot return is a refusal, never a
        // truncated or partial batch.
        Err(_) => refused_batch(
            &batch.request_id,
            "native_command_effect_batch_response_too_large",
        ),
    }
}

fn evaluate(request: &CommandEffectRequestV1) -> Result<serde_json::Value, String> {
    if request.schema != COMMAND_EFFECT_REQUEST_SCHEMA {
        return Err("native_command_effect_schema_mismatch".to_owned());
    }
    evaluate_with_read_floors(request)
}

fn evaluate_with_read_floors(
    request: &CommandEffectRequestV1,
) -> Result<serde_json::Value, String> {
    use std::path::Path;

    use guard_command::command_evaluation_controls::to_wire_payload;
    use guard_command::command_shell_read_factors::shell_read_floor_factors;
    use guard_command::{
        canonical_command::CanonicalCommand,
        github_workflow_authorization::GitHubWorkflowAuthorizationV1,
        native_command_catalog::packaged_command_catalog, CanonicalCommandV1,
        CommandEvaluationInput,
    };
    use guard_contracts::NativeCommandControlBindingV1;

    let canonical_v1: CanonicalCommandV1 =
        serde_json::from_value(request.canonical_command.clone())
            .map_err(|_| "native_command_effect_invalid_canonical_command".to_owned())?;
    let command = CanonicalCommand::from_v1(&canonical_v1);
    let registry = packaged_command_catalog()
        .map_err(|_| "native_command_effect_catalog_unavailable".to_owned())?;
    let mut binding: NativeCommandControlBindingV1 =
        serde_json::from_value(request.control_snapshot.clone())
            .map_err(|_| "native_command_effect_invalid_control_snapshot".to_owned())?;
    // The binding is the only control authority: its layers must hash to the
    // effective digest the native evidence is bound to. A counterfactual
    // overlay, if any, is applied only after that check.
    binding.validate().map_err(str::to_owned)?;
    apply_counterfactual_permissions(&mut binding, &request.counterfactual_enabled_permission_ids)?;
    let workflow_authorization: Option<GitHubWorkflowAuthorizationV1> = request
        .workflow_authorization
        .as_ref()
        .filter(|value| !value.is_null())
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .map_err(|_| "native_command_effect_invalid_workflow_authorization".to_owned())?;
    let read_factors = shell_read_floor_factors(
        &request.command_text,
        &command.security_identity,
        request.cwd.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
    );
    guard_command::evaluate_command(CommandEvaluationInput {
        command: &command,
        native_extension_evidence: &request.native_extension_evidence,
        registry: &registry,
        binding: &binding,
        compatibility_action_class: request.compatibility_action_class.as_deref(),
        compatibility_reason: request.compatibility_reason.as_deref(),
        workflow_authorization: workflow_authorization.as_ref(),
        read_factors,
    })
    .map(|evaluation| to_wire_payload(&evaluation))
    .map_err(|code| {
        if code.starts_with("native_") {
            code.to_owned()
        } else {
            format!("native_command_effect_{code}")
        }
    })
}

/// Enable `permission_ids` in the local-admin layer of an already validated
/// binding. The effective digest is left alone: it still names the snapshot the
/// evidence is bound to, and only the layers used for control resolution change.
fn apply_counterfactual_permissions(
    binding: &mut guard_contracts::NativeCommandControlBindingV1,
    permission_ids: &[String],
) -> Result<(), String> {
    use guard_contracts::{
        NativeExtensionControlLayerV1, NativeExtensionControlV1, COMMAND_EFFECT_COUNTERFACTUAL_MAX,
    };

    if permission_ids.is_empty() {
        return Ok(());
    }
    let invalid = || "native_command_effect_invalid_counterfactual".to_owned();
    if permission_ids.len() > COMMAND_EFFECT_COUNTERFACTUAL_MAX {
        return Err(invalid());
    }
    let mut targets: Vec<&String> = permission_ids.iter().collect();
    targets.sort();
    targets.dedup();
    if targets.iter().any(|id| {
        guard_command::extension_control::ControlTarget::new(
            guard_command::extension_control::ControlTargetKind::Permission,
            (*id).clone(),
        )
        .is_err()
    }) {
        return Err(invalid());
    }
    let position = binding
        .layers
        .iter()
        .position(|layer| layer.kind == "local-admin");
    let index = position.unwrap_or_else(|| {
        binding.layers.push(NativeExtensionControlLayerV1 {
            schema_version: "1.0.0".to_owned(),
            kind: "local-admin".to_owned(),
            catalog_digest: binding.catalog_digest.clone(),
            global_lockdown: false,
            controls: Vec::new(),
        });
        binding.layers.len() - 1
    });
    let layer = &mut binding.layers[index];
    layer.controls.retain(|control| {
        !(control.target_kind == "permission" && targets.contains(&&control.target_id))
    });
    layer
        .controls
        .extend(targets.into_iter().map(|id| NativeExtensionControlV1 {
            target_kind: "permission".to_owned(),
            target_id: id.clone(),
            state: "enabled".to_owned(),
        }));
    Ok(())
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
    use guard_command::native_command_catalog::packaged_command_catalog;
    use guard_command::{parse_command, CommandModelRequestV1};
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

    fn canonical_command(command: &str) -> Value {
        let model = parse_command(&CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .expect("command parses");
        serde_json::to_value(model).expect("command model serializes")
    }

    /// A real home directory for the private-scope fence, on any host.
    fn test_home() -> std::path::PathBuf {
        let home = std::env::temp_dir().join("rtm008-home");
        std::fs::create_dir_all(&home).ok();
        home
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
                "canonical_command": canonical_command(command),
                "compatibility_action_class": Value::Null,
                "compatibility_reason": Value::Null,
                "native_extension_evidence": evidence,
                "control_snapshot": serde_json::to_value(snapshot).unwrap(),
                "workflow_authorization": Value::Null,
                "cwd": std::env::temp_dir(),
                "home_dir": test_home(),
            }
        })
    }

    #[test]
    fn command_effect_op_decides_over_resident_transport() {
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

    fn decide(request: &Value) -> Value {
        let out =
            crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
                .expect("op returns bytes");
        serde_json::from_slice(&out).unwrap()
    }

    #[test]
    fn forged_control_layers_are_refused_before_evaluation() {
        let snapshot = valid_control_snapshot();
        let mut request = request_json("ls -la", &snapshot);
        // Enable a permission while keeping the digest the evidence names.
        request["request"]["control_snapshot"]["layers"][0]["controls"] = json!([{
            "target_kind": "permission",
            "target_id": "command.git.permission.add",
            "state": "enabled",
        }]);
        let result = decide(&request);
        assert_eq!(result["status"], "error");
        assert_eq!(result["code"], "native_command_control_digest_mismatch");
    }

    #[test]
    fn counterfactual_permissions_apply_after_the_binding_is_validated() {
        let snapshot = valid_control_snapshot();
        let mut request = request_json("ls -la", &snapshot);
        request["request"]["counterfactual_enabled_permission_ids"] =
            json!(["command.git.permission.add"]);
        let result = decide(&request);
        assert_eq!(result["status"], "ok", "{}", result["code"]);
        let enabled = &result["payload"]["control_resolution"]["composed"]["controls"];
        assert!(
            enabled.to_string().contains("command.git.permission.add"),
            "overlay not applied: {enabled}"
        );

        for ids in [
            json!(["not-a-permission"]),
            json!([
                "command.a.permission.b",
                "command.a.permission.c",
                "command.a.permission.d",
                "command.a.permission.e"
            ]),
        ] {
            request["request"]["counterfactual_enabled_permission_ids"] = ids;
            let result = decide(&request);
            assert_eq!(result["status"], "error");
            assert_eq!(
                result["code"],
                "native_command_effect_invalid_counterfactual"
            );
        }
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

    fn batch_json(commands: &[&str], snapshot: &NativeCommandControlBindingV1) -> Value {
        let items: Vec<Value> = commands
            .iter()
            .enumerate()
            .map(|(index, command)| {
                let mut item = request_json(command, snapshot)["request"].clone();
                item["request_id"] = json!(format!("item-{index}"));
                item
            })
            .collect();
        json!({
            "operation": "command_effect_decide_batch",
            "request": {
                "schema": COMMAND_EFFECT_BATCH_REQUEST_SCHEMA,
                "request_id": "batch-test",
                "items": items,
            }
        })
    }

    fn run_batch(request: &Value) -> Value {
        let out =
            crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
                .expect("batch op should return bytes");
        serde_json::from_slice(&out).unwrap()
    }

    #[test]
    fn batch_matches_single_op_per_item_with_bound_hashes() {
        let snapshot = valid_control_snapshot();
        let commands = ["ls -la", "cat ~/.ssh/id_rsa", "echo hi"];
        let batch = run_batch(&batch_json(&commands, &snapshot));
        assert_eq!(batch["status"], "ok");
        assert_eq!(batch["schema"], COMMAND_EFFECT_BATCH_RESULT_SCHEMA);
        let items = batch["items"].as_array().expect("items");
        assert_eq!(items.len(), commands.len());
        for (index, command) in commands.iter().enumerate() {
            let mut single = request_json(command, &snapshot);
            single["request"]["request_id"] = json!(format!("item-{index}"));
            let out = crate::resident_protocol::evaluate_resident_bytes(
                single.to_string().as_bytes(),
                None,
            )
            .unwrap();
            let single: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(
                items[index], single,
                "batch item {index} diverged from single op"
            );
            assert!(items[index]["request_sha256"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"));
        }
    }

    #[test]
    fn batch_reports_item_errors_without_failing_siblings() {
        let snapshot = valid_control_snapshot();
        let mut request = batch_json(&["ls", "ls"], &snapshot);
        request["request"]["items"][0]["schema"] = json!("bogus");
        let batch = run_batch(&request);
        assert_eq!(batch["status"], "ok");
        let items = batch["items"].as_array().unwrap();
        assert_eq!(items[0]["status"], "error");
        assert_eq!(items[0]["code"], "native_command_effect_schema_mismatch");
        assert_eq!(items[0]["request_id"], "item-0");
        assert_eq!(items[1]["request_id"], "item-1");
    }

    #[test]
    fn batch_refuses_bad_schema_empty_and_oversized() {
        let snapshot = valid_control_snapshot();

        let mut request = batch_json(&["ls"], &snapshot);
        request["request"]["schema"] = json!("bogus");
        let batch = run_batch(&request);
        assert_eq!(batch["status"], "error");
        assert_eq!(batch["code"], "native_command_effect_batch_schema_mismatch");
        assert_eq!(batch["items"].as_array().unwrap().len(), 0);

        let batch = run_batch(&batch_json(&[], &snapshot));
        assert_eq!(batch["code"], "native_command_effect_batch_empty");

        let many = vec!["ls"; COMMAND_EFFECT_BATCH_MAX_ITEMS + 1];
        let batch = run_batch(&batch_json(&many, &snapshot));
        assert_eq!(batch["status"], "error");
        assert_eq!(batch["code"], "native_command_effect_batch_too_many_items");
        assert_eq!(batch["items"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn batch_refuses_when_aggregate_bytes_exceed_bound() {
        let snapshot = valid_control_snapshot();
        let mut request = batch_json(&["ls"; 8], &snapshot);
        let filler = "x".repeat(COMMAND_EFFECT_BATCH_MAX_BYTES / 4);
        for item in request["request"]["items"].as_array_mut().unwrap() {
            item["command_text"] = json!(filler);
        }
        let batch = run_batch(&request);
        assert_eq!(batch["status"], "error");
        assert!(
            batch["code"] == "native_command_effect_batch_too_large"
                || batch["code"] == "native_command_effect_batch_item_too_large",
            "unexpected code {}",
            batch["code"]
        );
        assert_eq!(batch["items"].as_array().unwrap().len(), 0);
    }
}
