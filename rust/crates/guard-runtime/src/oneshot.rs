#![forbid(unsafe_code)]

use guard_command::pretool::{evaluate_pre_tool, PreToolDecisionV1};
use guard_command::{parse_command, CommandModelRequestV1};
use guard_contracts::{NativeHookRequestV1, NATIVE_PROTOCOL_VERSION};
use guard_hook_core::review_post_tool;
use guard_policy_snapshot::{validate as validate_policy_snapshot, PolicySnapshotV1};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

static MIN_POLICY_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(crate) fn validate_request_policy_snapshot(value: &Value) -> Result<(), String> {
    let Some(snapshot_value) = value.get("policy_snapshot") else {
        return Ok(());
    };
    if snapshot_value.is_null() {
        return Err("native_policy_snapshot_missing".to_owned());
    }
    let snapshot: PolicySnapshotV1 = serde_json::from_value(snapshot_value.clone())
        .map_err(|_| "native_policy_snapshot_invalid".to_owned())?;
    let minimum = MIN_POLICY_GENERATION.load(Ordering::Acquire);
    validate_policy_snapshot(&snapshot, minimum).map_err(|error| error.to_string())?;
    if snapshot.rule_digest != guard_rule_contract::rule_digest() {
        return Err("native_policy_snapshot_rule_mismatch".to_owned());
    }
    ratchet_min_policy_generation(snapshot.generation)
}

fn ratchet_min_policy_generation(generation: u64) -> Result<(), String> {
    let mut current = MIN_POLICY_GENERATION.load(Ordering::Acquire);
    loop {
        if generation < current {
            return Err("native_policy_snapshot_stale".to_owned());
        }
        if generation == current {
            return Ok(());
        }
        match MIN_POLICY_GENERATION.compare_exchange_weak(
            current,
            generation,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(actual) => current = actual,
        }
    }
}

fn mapping_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn extract_pre_tool_command(value: &Value) -> Result<String, String> {
    if let Some(event_name) = mapping_string(value, "event_name") {
        if event_name != "PreToolUse" {
            return Err("native_pre_tool_unsupported_event".to_owned());
        }
    }
    if let Some(version) = value.get("protocol_version") {
        let protocol_version = version
            .as_u64()
            .ok_or_else(|| "native_pre_tool_invalid_protocol".to_owned())?;
        if protocol_version != u64::from(NATIVE_PROTOCOL_VERSION) {
            return Err("native_pre_tool_invalid_protocol".to_owned());
        }
    }
    let command_holders = [
        value,
        value.get("payload").unwrap_or(&Value::Null),
        value
            .get("payload")
            .and_then(|payload| payload.get("tool_input"))
            .unwrap_or(&Value::Null),
        value
            .get("payload")
            .and_then(|payload| payload.get("arguments"))
            .unwrap_or(&Value::Null),
        value.get("tool_input").unwrap_or(&Value::Null),
    ];
    for holder in command_holders {
        for key in ["command", "cmd", "shell_command", "shellCommand"] {
            if let Some(command) = mapping_string(holder, key) {
                return Ok(command.to_owned());
            }
        }
    }
    Err("native_pre_tool_command_missing".to_owned())
}

pub(crate) fn pre_tool_response(request_id: Option<&str>, decision: PreToolDecisionV1) -> Value {
    serde_json::json!({
        "authority": "rust",
        "request_id": request_id.unwrap_or(""),
        "decision": &decision.decision,
        "policy_action": &decision.minimum_action,
        "minimum_action": &decision.minimum_action,
        "reason_code": &decision.reason_code,
        "reason": &decision.reason,
        "explicitly_benign": decision.explicitly_benign,
        "command_model": &decision.command_model,
    })
}

pub(crate) fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    validate_request_policy_snapshot(&value)?;
    let request: NativeHookRequestV1 =
        serde_json::from_value(value).map_err(|_| "native_request_invalid_json".to_owned())?;
    crate::encode_response(&review_post_tool(&request))
}

pub(crate) fn evaluate_command_model_request(
    request: &CommandModelRequestV1,
) -> Result<Vec<u8>, String> {
    crate::encode_response(&parse_command(request)?)
}

pub(crate) fn evaluate_command_model_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: CommandModelRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_command_model_invalid_json".to_owned())?;
    evaluate_command_model_request(&request)
}

pub(crate) fn evaluate_pre_tool_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let command = extract_pre_tool_command(&value)?;
    let dialect = mapping_string(&value, "dialect").unwrap_or("posix");
    let transport = mapping_string(&value, "transport").unwrap_or("shell_string");
    let extraction_provenance =
        mapping_string(&value, "extraction_provenance").unwrap_or("guard-shell");
    let request = CommandModelRequestV1 {
        command,
        dialect: dialect.to_owned(),
        transport: transport.to_owned(),
        extraction_provenance: extraction_provenance.to_owned(),
    };
    let decision = evaluate_pre_tool(&request)?;
    let request_id = mapping_string(&value, "request_id");
    crate::encode_response(&pre_tool_response(request_id, decision))
}

pub(crate) fn evaluate_pre_tool_request(
    request: &CommandModelRequestV1,
) -> Result<Vec<u8>, String> {
    crate::encode_response(&pre_tool_response(None, evaluate_pre_tool(request)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_generation() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn snapshot_value(generation: u64) -> Value {
        let digest = "a".repeat(64);
        json!({
            "policy_snapshot": {
                "schema": "hol-guard-native-policy.v1",
                "generation": generation,
                "policy_digest": digest,
                "config_digest": digest,
                "rule_digest": guard_rule_contract::rule_digest(),
                "mode": "enforce",
            }
        })
    }

    #[test]
    fn rejects_stale_generation_after_newer_snapshot() {
        let _guard = lock_generation();
        MIN_POLICY_GENERATION.store(0, Ordering::SeqCst);
        assert!(validate_request_policy_snapshot(&snapshot_value(10)).is_ok());
        let error = validate_request_policy_snapshot(&snapshot_value(5)).unwrap_err();
        assert_eq!(error, "snapshot_generation_downgrade");
        MIN_POLICY_GENERATION.store(0, Ordering::SeqCst);
    }

    #[test]
    fn ratchet_rejects_stale_generation_when_floor_already_moved() {
        let _guard = lock_generation();
        MIN_POLICY_GENERATION.store(10, Ordering::SeqCst);
        let error = ratchet_min_policy_generation(5).unwrap_err();
        assert_eq!(error, "native_policy_snapshot_stale");
        MIN_POLICY_GENERATION.store(0, Ordering::SeqCst);
    }

    #[test]
    fn concurrent_stale_snapshot_cannot_succeed_after_newer_floor() {
        let _guard = lock_generation();
        MIN_POLICY_GENERATION.store(0, Ordering::SeqCst);
        let start = Arc::new(Barrier::new(2));
        let high_start = start.clone();
        let high = thread::spawn(move || {
            high_start.wait();
            ratchet_min_policy_generation(20)
        });
        start.wait();
        assert!(high.join().expect("high generation thread").is_ok());
        let low = ratchet_min_policy_generation(5);
        assert_eq!(low.unwrap_err(), "native_policy_snapshot_stale");
        MIN_POLICY_GENERATION.store(0, Ordering::SeqCst);
    }
}
