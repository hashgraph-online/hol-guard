//! Structured values shared across the Python/Rust native-runtime boundary.
//!
//! Port of `native_runtime_values.py` — the manifest/capabilities admission
//! contract and the output-digest/parity oracles. These decoders are the
//! boundary between an untrusted runtime artifact and an admitted
//! `NativeRuntimeManifest`/`NativeRuntimeCapabilities`: every field is
//! validated before it is trusted. Malformed payloads decode to `None`
//! (fail-closed), never panic.
//!
//! Everything here is pure: no IO, no spawn, no env. FS/launch admission
//! lives in `guard-runtime::native_runtime_admission`; process-local health
//! lives in `guard-runtime::native_runtime_resilience`.
//! `_python_package_version` stays Python-side (importlib introspection);
//! the Rust side takes the version as a string input and owns only the
//! comparison.

use serde::{Deserialize, Serialize};

/// `NativeRuntimeManifest` (`native_runtime_values.py:76-85`). The validated
/// admission contract for a bundled/discovered runtime artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeRuntimeManifestV1 {
    pub schema: String,
    pub protocol_version: i64,
    pub package_version: String,
    pub target: String,
    pub platform_tag: String,
    pub source_sha: String,
    pub rule_digest: String,
    pub runtime_sha256: String,
    pub runtime_size: i64,
}

/// `NativeRuntimeCapabilities` (`native_runtime_values.py:66-72`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeRuntimeCapabilitiesV1 {
    pub protocol_version: i64,
    pub runtime_version: String,
    pub rule_digest: String,
    pub build_sha: String,
    pub target: String,
    pub features: Vec<String>,
}

/// `_is_lower_hex` (`native_runtime_values.py:106-107`) folded in — the Python
/// def is generic over an injectable validator; in Rust the lowercase-hex
/// check is fixed at the call site (do not preserve the injection seam).
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `decode_runtime_manifest` (`native_runtime_values.py:110-160`).
///
/// Returns `None` on any malformed/short/blank/non-hex/non-positive field so
/// a bad manifest can never reach admission. `runtime_size` rejects bools in
/// Python because `bool` subclasses `int`; the typed `i64` decode makes that
/// check structural.
pub fn decode_runtime_manifest(
    payload: &serde_json::Value,
    schema: &str,
    protocol_version: i64,
) -> Option<NativeRuntimeManifestV1> {
    let obj = payload.as_object()?;
    let get = |k: &str| obj.get(k);
    let get_str = |k: &str| obj.get(k).and_then(|v| v.as_str());
    let get_i64 = |k: &str| obj.get(k).and_then(|v| v.as_i64());

    let manifest_schema = get_str("schema")?;
    let manifest_protocol_version = get_i64("protocol_version")?;
    let package_version = get_str("package_version")?;
    let target = get_str("target")?;
    let platform_tag = get_str("platform_tag")?;
    let source_sha = get_str("source_sha")?;
    let rule_digest = get_str("rule_digest")?;
    let runtime_sha256 = get_str("runtime_sha256")?;
    let runtime_size = get_i64("runtime_size")?;

    if manifest_schema != schema
        || manifest_protocol_version != protocol_version
        || package_version.trim().is_empty()
        || target.trim().is_empty()
        || platform_tag.trim().is_empty()
        || !is_lower_hex(source_sha, 40)
        || !is_lower_hex(rule_digest, 64)
        || !is_lower_hex(runtime_sha256, 64)
        || runtime_size <= 0
    {
        return None;
    }
    let _ = get; // helper retained for future fields
    Some(NativeRuntimeManifestV1 {
        schema: manifest_schema.to_string(),
        protocol_version: manifest_protocol_version,
        package_version: package_version.to_string(),
        target: target.to_string(),
        platform_tag: platform_tag.to_string(),
        source_sha: source_sha.to_string(),
        rule_digest: rule_digest.to_string(),
        runtime_sha256: runtime_sha256.to_string(),
        runtime_size,
    })
}

/// `_decode_capabilities` (`native_runtime_values.py:163-189`).
///
/// `features` must be a list of strings; a single non-string element rejects
/// the whole payload.
pub fn decode_native_capabilities(
    payload: &serde_json::Value,
) -> Option<NativeRuntimeCapabilitiesV1> {
    let obj = payload.as_object()?;
    let get_str = |k: &str| obj.get(k).and_then(|v| v.as_str());
    let get_i64 = |k: &str| obj.get(k).and_then(|v| v.as_i64());
    let features_val = obj.get("features")?;
    let features_arr = features_val.as_array()?;
    let mut features = Vec::with_capacity(features_arr.len());
    for f in features_arr {
        features.push(f.as_str()?.to_string());
    }

    let protocol_version = get_i64("protocol_version")?;
    let runtime_version = get_str("runtime_version")?;
    let rule_digest = get_str("rule_digest")?;
    let build_sha = get_str("build_sha")?;
    let target = get_str("target")?;

    Some(NativeRuntimeCapabilitiesV1 {
        protocol_version,
        runtime_version: runtime_version.to_string(),
        rule_digest: rule_digest.to_string(),
        build_sha: build_sha.to_string(),
        target: target.to_string(),
        features,
    })
}

/// `native_output_sha256` (`native_runtime_values.py:213-216`).
/// Canonical sha256-of-utf8 output digest. Byte-parity with the Python helper.
pub fn native_output_sha256(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    format!("{:x}", h.finalize())
}

/// `HookReviewResponse` subset consumed by `parity_signature`
/// (`native_runtime_values.py:199-210`). Only the fields the parity tuple
/// reads are carried; call sites construct this from the full response.
#[derive(Debug, Clone, PartialEq)]
pub struct ParityInputV1 {
    pub decision: String,
    pub model_output_action: Option<String>,
    pub reason_code: Option<String>,
    pub notice: Option<String>,
    pub policy_action: Option<String>,
    pub observed_policy_action: Option<String>,
    pub reviewed_output_sha256: Option<String>,
    pub reviewed_excerpt: Option<String>,
}

/// `parity_signature` (`native_runtime_values.py:199-210`) — the local↔native
/// parity tuple. `reviewed_excerpt` is hashed via `native_output_sha256` before
/// entering the tuple; `None` excerpt → `None` in the tuple.
///
/// Returns a `serde_json::Value` array in the Python field order so a Python
/// caller can compare element-wise (tuples serialize as arrays on the wire).
pub fn parity_signature(input: &ParityInputV1) -> serde_json::Value {
    let excerpt_hash = input.reviewed_excerpt.as_deref().map(native_output_sha256);
    let opt = |o: &Option<String>| match o {
        Some(s) => serde_json::Value::String(s.clone()),
        None => serde_json::Value::Null,
    };
    serde_json::json!([
        input.decision,
        opt(&input.model_output_action),
        opt(&input.reason_code),
        opt(&input.notice),
        opt(&input.policy_action),
        opt(&input.observed_policy_action),
        opt(&input.reviewed_output_sha256),
        opt(&excerpt_hash),
    ])
}

/// `NativeMode` (`native_runtime_values.py:18`) —
/// `Literal["off","shadow","auto","force"]`. Serde snake_case matches the
/// wire strings byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeMode {
    Off,
    Shadow,
    Auto,
    Force,
}

/// `_resolve_native_mode` (`native_runtime_values.py:48-54`): strip/lower the
/// raw env value; anything outside the four-mode set falls back to the
/// caller's default (fail-to-default, never panic).
pub fn resolve_native_mode(raw_value: Option<&str>, default: NativeMode) -> NativeMode {
    match raw_value {
        None => default,
        Some(v) => match v.trim().to_lowercase().as_str() {
            "off" => NativeMode::Off,
            "shadow" => NativeMode::Shadow,
            "auto" => NativeMode::Auto,
            "force" => NativeMode::Force,
            _ => default,
        },
    }
}

/// `_INTEGRITY_FAILURE_REASONS` (`native_runtime_values.py:20-30`): every
/// manifest-admission failure class that permanently quarantines the
/// identity. Includes the protocol/rule/build mismatches surfaced by the
/// capabilities compatibility leg (admission emits only the 4 manifest
/// variants).
pub const INTEGRITY_FAILURE_REASONS: [&str; 7] = [
    "native_manifest_invalid",
    "native_manifest_missing",
    "native_manifest_runtime_mismatch",
    "native_manifest_version_mismatch",
    "native_manifest_protocol_mismatch",
    "native_manifest_rule_mismatch",
    "native_manifest_build_mismatch",
];

/// `_identity_key` (`native_runtime_values.py:102-103`): the runtime's
/// content key is its sha256; a missing identity collapses to the 64-zero
/// sentinel so cache/state maps never carry a null key.
pub fn identity_key(identity_sha256: Option<&str>) -> String {
    match identity_sha256 {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => "0".repeat(64),
    }
}

/// `NativeRuntimeStatus` (`native_runtime_values.py:89-99`): the status
/// object surfaced to `native_runtime_status()`. `identity`/`capabilities`/
/// `manifest` are `Option`s mirroring the Python `| None = None` defaults.
/// `identity` carries the validated identity's path (as a string — the wire
/// keeps Path types host-side) + size + mtime_ns + sha256.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeRuntimeStatusV1 {
    pub mode: NativeMode,
    pub available: bool,
    pub compatible: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<RuntimeIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<NativeRuntimeCapabilitiesV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<NativeRuntimeManifestV1>,
}

/// Wire-shape of `NativeRuntimeIdentity` for status/report surfaces —
/// `path` is the platform-path string, not a `Path`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeIdentityV1 {
    pub path: String,
    pub size: i64,
    pub mtime_ns: u64,
    pub sha256: String,
}

/// `_identity_key(status)` — the status's content key when an identity is
/// present, else the 64-zero sentinel. Same contract as `identity_key` but
/// on the status object (Python takes `NativeRuntimeStatus`).
pub fn status_identity_key(status: &NativeRuntimeStatusV1) -> String {
    match &status.identity {
        Some(id) => id.sha256.clone(),
        None => "0".repeat(64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SCHEMA: &str = "guard-native-manifest.v1";

    fn good_manifest() -> serde_json::Value {
        json!({
            "schema": SCHEMA,
            "protocol_version": 1,
            "package_version": "3.16.5",
            "target": "aarch64-apple-darwin",
            "platform_tag": "macosx_14_0_arm64",
            "source_sha": "a".repeat(40),
            "rule_digest": "b".repeat(64),
            "runtime_sha256": "c".repeat(64),
            "runtime_size": 12345,
        })
    }

    #[test]
    fn manifest_decode_accepts_valid() {
        let m = decode_runtime_manifest(&good_manifest(), SCHEMA, 1).unwrap();
        assert_eq!(m.package_version, "3.16.5");
        assert_eq!(m.runtime_size, 12345);
        assert_eq!(m.schema, SCHEMA);
    }

    #[test]
    fn manifest_decode_rejects_schema_mismatch() {
        // fail-closed: wrong schema or protocol -> None, never a manifest
        assert!(decode_runtime_manifest(&good_manifest(), "other.v9", 1).is_none());
        assert!(decode_runtime_manifest(&good_manifest(), SCHEMA, 2).is_none());
    }

    #[test]
    fn manifest_decode_rejects_bad_hex_and_blank() {
        for (key, val) in [
            ("source_sha", "Z".repeat(40)),         // uppercase
            ("rule_digest", "x".repeat(64)),        // non-hex
            ("runtime_sha256", "d".repeat(63)),     // wrong len
            ("package_version", "   ".to_string()), // blank
        ] {
            let mut m = good_manifest();
            m[key] = serde_json::Value::String(val);
            assert!(
                decode_runtime_manifest(&m, SCHEMA, 1).is_none(),
                "must reject {key}"
            );
        }
    }

    #[test]
    fn manifest_decode_rejects_nonpositive_size_and_nonobj() {
        let mut m = good_manifest();
        m["runtime_size"] = json!(0);
        assert!(decode_runtime_manifest(&m, SCHEMA, 1).is_none());
        let mut m = good_manifest();
        m["runtime_size"] = json!(-5);
        assert!(decode_runtime_manifest(&m, SCHEMA, 1).is_none());
        assert!(decode_runtime_manifest(&json!("notanobj"), SCHEMA, 1).is_none());
        // bool is not i64 -> structural rejection
        let mut m = good_manifest();
        m["runtime_size"] = json!(true);
        assert!(decode_runtime_manifest(&m, SCHEMA, 1).is_none());
    }

    #[test]
    fn capabilities_decode_accepts_and_rejects() {
        let good = json!({
            "protocol_version": 1, "runtime_version": "1.0", "rule_digest": "r".repeat(64),
            "build_sha": "s".repeat(40), "target": "t", "features": ["a", "b"],
        });
        let c = decode_native_capabilities(&good).unwrap();
        assert_eq!(c.features, vec!["a", "b"]);
        // non-string feature rejects the whole payload
        let bad = json!({"protocol_version":1,"runtime_version":"1","rule_digest":"r".repeat(64),
            "build_sha":"s".repeat(40),"target":"t","features":["a",1]});
        assert!(decode_native_capabilities(&bad).is_none());
        // non-array features
        let bad2 = json!({"protocol_version":1,"runtime_version":"1","rule_digest":"r".repeat(64),
            "build_sha":"s".repeat(40),"target":"t","features":"a"});
        assert!(decode_native_capabilities(&bad2).is_none());
    }

    #[test]
    fn native_output_sha256_matches_python() {
        // sha256(b"").hexdigest() and sha256("hello")
        assert_eq!(
            native_output_sha256(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            native_output_sha256("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn parity_signature_field_order_and_excerpt_hash() {
        let input = ParityInputV1 {
            decision: "allow".into(),
            model_output_action: Some("allow".into()),
            reason_code: None,
            notice: None,
            policy_action: Some("allow".into()),
            observed_policy_action: None,
            reviewed_output_sha256: Some("out".into()),
            reviewed_excerpt: Some("hello".into()),
        };
        let sig = parity_signature(&input);
        let arr = sig.as_array().unwrap();
        assert_eq!(arr.len(), 8);
        assert_eq!(arr[0], json!("allow"));
        assert_eq!(arr[2], serde_json::Value::Null);
        // excerpt replaced by its sha256
        assert_eq!(
            arr[7],
            json!("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
        // None excerpt -> null
        let mut no = input.clone();
        no.reviewed_excerpt = None;
        assert_eq!(
            parity_signature(&no).as_array().unwrap()[7],
            serde_json::Value::Null
        );
    }

    #[test]
    fn resolve_native_mode_defaults_and_parses() {
        assert_eq!(
            resolve_native_mode(None, NativeMode::Auto),
            NativeMode::Auto
        );
        assert_eq!(
            resolve_native_mode(Some(" FORCE "), NativeMode::Auto),
            NativeMode::Force
        );
        assert_eq!(
            resolve_native_mode(Some("shadow"), NativeMode::Force),
            NativeMode::Shadow
        );
        assert_eq!(
            resolve_native_mode(Some("bogus"), NativeMode::Off),
            NativeMode::Off
        );
        assert_eq!(
            resolve_native_mode(Some(""), NativeMode::Shadow),
            NativeMode::Shadow
        );
    }

    #[test]
    fn native_mode_serde_lowercase() {
        assert_eq!(
            serde_json::to_string(&NativeMode::Force).unwrap(),
            "\"force\""
        );
        assert_eq!(
            serde_json::from_str::<NativeMode>("\"shadow\"").unwrap(),
            NativeMode::Shadow
        );
    }

    #[test]
    fn identity_key_zero_sentinel() {
        assert_eq!(identity_key(None), "0".repeat(64));
        assert_eq!(identity_key(Some("")), "0".repeat(64));
        assert_eq!(identity_key(Some("abc")), "abc");
    }

    #[test]
    fn integrity_reasons_cover_manifest_and_compat() {
        assert_eq!(INTEGRITY_FAILURE_REASONS.len(), 7);
        assert!(INTEGRITY_FAILURE_REASONS.contains(&"native_manifest_protocol_mismatch"));
        assert!(INTEGRITY_FAILURE_REASONS.contains(&"native_manifest_missing"));
    }
}
