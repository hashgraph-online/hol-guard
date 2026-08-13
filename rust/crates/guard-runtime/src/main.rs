#![forbid(unsafe_code)]

mod resident;

use guard_command::{parse_command, CommandModelRequestV1};
use guard_contracts::{
    NativeHookRequestV1, RuntimeCapabilitiesV1, MAX_NATIVE_REQUEST_BYTES,
    MAX_NATIVE_RESPONSE_BYTES, NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool;
use resident::ResidentOperation;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use std::collections::HashSet;
use std::env;
use std::fmt;
use std::io::{self, Read, Write};

const BUILD_SHA: &str = match option_env!("HOL_GUARD_BUILD_SHA") {
    Some(value) => value,
    None => "unknown",
};
const PACKAGE_VERSION: &str = match option_env!("HOL_GUARD_PACKAGE_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_COLLECTION_ITEMS: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 256;
const MAX_DEADLINE_MILLISECONDS: u64 = 10_000;

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "snake_case")]
enum ResidentOperationV1 {
    CommandModel(CommandModelRequestV1),
    Health(Value),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResidentRequestV1 {
    Operation(ResidentOperationV1),
    Hook(Box<NativeHookRequestV1>),
}

#[derive(Clone, Copy)]
struct StrictJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(serde::de::Error::custom("native_json_depth_exceeded"));
        }
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("native_json_number_invalid"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom("native_json_string_too_large"));
        }
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            depth: self.depth + 1,
        })? {
            if output.len() >= MAX_JSON_COLLECTION_ITEMS {
                return Err(serde::de::Error::custom("native_json_array_too_wide"));
            }
            output.push(value);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if key.len() > MAX_JSON_STRING_BYTES {
                return Err(serde::de::Error::custom("native_json_key_too_large"));
            }
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("native_json_duplicate_key"));
            }
            if output.len() >= MAX_JSON_COLLECTION_ITEMS {
                return Err(serde::de::Error::custom("native_json_object_too_wide"));
            }
            let value = object.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
            })?;
            output.insert(key, value);
        }
        Ok(Value::Object(output))
    }
}

fn capabilities() -> RuntimeCapabilitiesV1 {
    let mut features = vec![
        "post-tool-inline-v1".into(),
        "post-tool-source-read-v1".into(),
        "oneshot-v1".into(),
        "framed-serve-v1".into(),
        "resident-protocol-v2".into(),
        "bounded-admission-v2".into(),
        "overload-signal-v1".into(),
        "panic-containment-v1".into(),
        "rule-contract-v2".into(),
        "pre-tool-command-model-shadow-v1".into(),
        "resident-command-model-shadow-v1".into(),
        "generation-bound-response-v1".into(),
        "lifecycle-reservation-v1".into(),
        "operation-bounded-frame-v1".into(),
        "audited-hmac-v1".into(),
        "identity-bound-envelope-v1".into(),
    ];
    if cfg!(windows) {
        features.push("authenticated-loopback-resident-v1".into());
    }
    if cfg!(unix) {
        features.push("authenticated-unix-resident-v1".into());
    }
    RuntimeCapabilitiesV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        runtime_version: PACKAGE_VERSION.to_owned(),
        rule_digest: guard_rule_contract::rule_digest(),
        build_sha: BUILD_SHA.to_owned(),
        target: format!("{}-{}", env::consts::ARCH, env::consts::OS),
        features,
    }
}

fn read_stdin_bounded() -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_NATIVE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "native_request_read_failed".to_owned())?;
    if bytes.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".to_owned());
    }
    Ok(bytes)
}

fn strict_json_value(bytes: &[u8]) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| "native_request_invalid_json".to_owned())?;
    deserializer
        .end()
        .map_err(|_| "native_request_trailing_json".to_owned())?;
    Ok(value)
}

fn sha256_hex_shape(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_hook_request(request: &NativeHookRequestV1) -> Result<(), String> {
    if request.protocol_version != NATIVE_PROTOCOL_VERSION {
        return Err("native_protocol_mismatch".to_owned());
    }
    if let Some(request_id) = request.request_id.as_deref() {
        if request_id.is_empty() || request_id.len() > MAX_REQUEST_ID_BYTES {
            return Err("native_request_id_invalid".to_owned());
        }
    }
    if let Some(operation) = request.operation.as_deref() {
        if operation != "post_tool_review" {
            return Err("native_operation_mismatch".to_owned());
        }
    }
    if let Some(payload_size_bytes) = request.payload_size_bytes {
        let encoded = serde_json::to_vec(&request.payload)
            .map_err(|_| "native_request_invalid_json".to_owned())?;
        if encoded.len() != payload_size_bytes {
            return Err("native_payload_size_mismatch".to_owned());
        }
    }
    if let Some(identity) = request.runtime_identity.as_ref() {
        if !sha256_hex_shape(&identity.binary_sha256)
            || identity.runtime_version != PACKAGE_VERSION
            || identity.build_sha != BUILD_SHA
            || identity.rule_digest != guard_rule_contract::rule_digest()
        {
            return Err("native_runtime_identity_mismatch".to_owned());
        }
    }
    if let Some(snapshot) = request.policy_snapshot.as_ref() {
        if snapshot.schema_version != 1
            || snapshot.generation == 0
            || snapshot.rule_set_digest != guard_rule_contract::rule_digest()
            || !sha256_hex_shape(&snapshot.strict_config_digest)
            || !sha256_hex_shape(&snapshot.never_allow_digest)
            || !sha256_hex_shape(&snapshot.source_policy_digest)
        {
            return Err("native_policy_identity_mismatch".to_owned());
        }
    }
    if let Some(deadline_budget_ms) = request.deadline_budget_ms {
        if deadline_budget_ms == 0 || deadline_budget_ms > MAX_DEADLINE_MILLISECONDS {
            return Err("native_deadline_invalid".to_owned());
        }
    }
    Ok(())
}

fn review_hook_request(request: &NativeHookRequestV1) -> Result<Vec<u8>, String> {
    validate_hook_request(request)?;
    encode_response(&review_post_tool(request))
}

fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: NativeHookRequestV1 =
        serde_json::from_value(value).map_err(|_| "native_request_invalid_json".to_owned())?;
    review_hook_request(&request)
}

fn evaluate_command_model_request(request: &CommandModelRequestV1) -> Result<Vec<u8>, String> {
    let response = parse_command(request)?;
    encode_response(&response)
}

fn evaluate_command_model_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: CommandModelRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_command_model_invalid_json".to_owned())?;
    evaluate_command_model_request(&request)
}

fn evaluate_resident_bytes(
    bytes: &[u8],
    transport_operation: ResidentOperation,
) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: ResidentRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_resident_request_invalid_json".to_owned())?;
    match (transport_operation, request) {
        (
            ResidentOperation::Evaluate,
            ResidentRequestV1::Operation(ResidentOperationV1::CommandModel(request)),
        ) => evaluate_command_model_request(&request),
        (ResidentOperation::Evaluate, ResidentRequestV1::Hook(request)) => {
            review_hook_request(&request)
        }
        (
            ResidentOperation::Health,
            ResidentRequestV1::Operation(ResidentOperationV1::Health(request)),
        ) if request == serde_json::json!({}) => encode_response(&serde_json::json!({
            "status": "ready",
            "protocol_version": resident::RESIDENT_PROTOCOL_VERSION,
        })),
        _ => Err("native_operation_mismatch".to_owned()),
    }
}

fn encode_response<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| "native_response_encode_failed".to_owned())?;
    if encoded.len() > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".to_owned());
    }
    Ok(encoded)
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    serde_json::to_writer(io::stdout().lock(), value)
        .map_err(|_| "native_response_encode_failed".to_owned())?;
    println!();
    Ok(())
}

fn write_bytes_response(response: &[u8]) -> Result<(), String> {
    io::stdout()
        .write_all(response)
        .map_err(|_| "native_response_write_failed".to_owned())?;
    io::stdout()
        .write_all(b"\n")
        .map_err(|_| "native_response_write_failed".to_owned())?;
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "capabilities" => write_json(&capabilities()),
        [command, flag] if command == "capabilities" && flag == "--json" => {
            write_json(&capabilities())
        }
        [command] if command == "rule-contract" => write_json(&guard_rule_contract::rule_contract()),
        [command, flag] if command == "rule-contract" && flag == "--json" => {
            write_json(&guard_rule_contract::rule_contract())
        }
        [command] if command == "self-test" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "self-test" && flag == "--json" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "hook" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = evaluate_hook_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "command-model" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = evaluate_command_model_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag, path] if command == "serve" && flag == "--socket" => {
            resident::serve(path, evaluate_resident_bytes)
        }
        [command, flag, address] if command == "serve" && flag == "--tcp-loopback" => {
            resident::serve_loopback(address, evaluate_resident_bytes)
        }
        _ => Err(
            "usage: hol-guard-runtime capabilities --json | rule-contract --json | self-test --json | hook --stdin | command-model --stdin | serve --socket PATH | serve --tcp-loopback 127.0.0.1:PORT"
                .to_owned(),
        ),
    }
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("native_runtime_panicked")));
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_rejects_duplicate_keys_and_trailing_values() {
        assert!(strict_json_value(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json_value(br#"{"a":1} {}"#).is_err());
    }

    #[test]
    fn strict_json_rejects_deep_and_wide_values() {
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 2),
            "]".repeat(MAX_JSON_DEPTH + 2)
        );
        assert!(strict_json_value(deep.as_bytes()).is_err());
        let wide = format!(
            "[{}]",
            std::iter::repeat_n("0", MAX_JSON_COLLECTION_ITEMS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(strict_json_value(wide.as_bytes()).is_err());
    }

    #[test]
    fn resident_transport_operation_cannot_be_smuggled_in_json() {
        let health = br#"{"operation":"health","request":{}}"#;
        assert!(evaluate_resident_bytes(health, ResidentOperation::Evaluate).is_err());
        assert!(evaluate_resident_bytes(health, ResidentOperation::Health).is_ok());
    }

    #[test]
    fn identity_bound_hook_request_is_validated() {
        let payload = serde_json::json!({"hook_event_name":"PostToolUse","tool_response":"clean"});
        let payload_size = serde_json::to_vec(&payload).unwrap().len();
        let value = serde_json::json!({
            "protocol_version": NATIVE_PROTOCOL_VERSION,
            "request_id": "request-1",
            "operation": "post_tool_review",
            "payload_size_bytes": payload_size,
            "runtime_identity": {
                "binary_sha256": "a".repeat(64),
                "runtime_version": PACKAGE_VERSION,
                "build_sha": BUILD_SHA,
                "rule_digest": guard_rule_contract::rule_digest(),
            },
            "policy_snapshot": {
                "schema_version": 1,
                "generation": 1,
                "rule_set_digest": guard_rule_contract::rule_digest(),
                "strict_config_digest": "b".repeat(64),
                "never_allow_digest": "c".repeat(64),
                "source_policy_digest": "d".repeat(64),
            },
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": payload,
            "home_dir": "/home/test",
            "guard_home": "/home/test/.guard",
            "deadline_budget_ms": 500,
        });
        let request: NativeHookRequestV1 = serde_json::from_value(value).unwrap();
        assert!(validate_hook_request(&request).is_ok());

        let mut mismatched = request;
        mismatched.payload_size_bytes = Some(payload_size + 1);
        assert_eq!(
            validate_hook_request(&mismatched),
            Err("native_payload_size_mismatch".to_owned())
        );
    }
}
