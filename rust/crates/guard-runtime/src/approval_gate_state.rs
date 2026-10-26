#![forbid(unsafe_code)]
//! `approval_gate_state.py` — state helpers for the local approval-password
//! gate: `approval-gate.json` IO, lockout counters, ISO↔epoch conversion, and
//! the `optional_*` coercion helpers. State is a `serde_json::Value` object
//! (Python `dict[str, object]`).
//!
//! Time semantics: `epoch`/`iso_from_epoch`/`is_future` reuse
//! `guard_contracts::utc_timestamp` (`utc_timestamp_micros` /
//! `canonical_utc_timestamp`) so wire format (`...T...+00:00`, microsecond
//! precision) byte-matches Python's `datetime.isoformat()`.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

pub const APPROVAL_GATE_STATE_FILE: &str = "approval-gate.json";
pub const APPROVAL_GATE_MAX_COOLDOWN_SECONDS: u64 = 3600;
/// `(0, 900, 3600)` — the only cooldowns `unlock_cooldown` accepts.
pub const APPROVAL_GATE_ALLOWED_COOLDOWNS: [u64; 3] = [0, 900, APPROVAL_GATE_MAX_COOLDOWN_SECONDS];
pub const APPROVAL_GATE_LOCKOUT_FAILURES: i64 = 5;
pub const APPROVAL_GATE_LOCKOUT_SECONDS: i64 = 300;
pub const APPROVAL_GATE_COMBINED_LOCKOUT_FAILURES: i64 = 5;

/// `ApprovalGateFactor` literal — `password` | `totp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalGateFactor {
    Password,
    Totp,
}

impl ApprovalGateFactor {
    fn attempt_key(self) -> &'static str {
        match self {
            ApprovalGateFactor::Password => "password_failed_attempts",
            ApprovalGateFactor::Totp => "totp_failed_attempts",
        }
    }
}

/// `ApprovalGatePublicConfig` (`approval_gate_state.py:25-52`) — public gate
/// state safe for settings/dashboard responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGatePublicConfig {
    pub enabled: bool,
    pub configured: bool,
    pub cooldown_seconds: i64,
    pub cooldown_active: bool,
    pub cooldown_expires_at: Option<String>,
    pub locked_until: Option<String>,
    pub fail_closed: bool,
    pub strict_all_decisions: bool,
    pub totp_enabled: bool,
    pub totp_pending: bool,
    pub totp_recent_satisfied: bool,
}

impl ApprovalGatePublicConfig {
    /// `to_dict` — 11-key payload, insertion order preserved.
    pub fn to_dict(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "configured": self.configured,
            "cooldown_seconds": self.cooldown_seconds,
            "cooldown_active": self.cooldown_active,
            "cooldown_expires_at": self.cooldown_expires_at,
            "locked_until": self.locked_until,
            "fail_closed": self.fail_closed,
            "strict_all_decisions": self.strict_all_decisions,
            "totp_enabled": self.totp_enabled,
            "totp_pending": self.totp_pending,
            "totp_recent_satisfied": self.totp_recent_satisfied,
        })
    }
}

fn state_path(guard_home: &Path) -> PathBuf {
    guard_home.join(APPROVAL_GATE_STATE_FILE)
}

/// `_load_state` (`approval_gate.py:1349-1366`) — absent file → `default_state()`;
/// unreadable/invalid JSON/non-object → `_fail_closed_state()`; else
/// `default_state()` merged with the payload and `cooldown_seconds` coerced to a
/// valid value (invalid → `0` rather than raising, per the try/except).
pub fn load_state(guard_home: &Path) -> Value {
    let path = state_path(guard_home);
    if !path.is_file() {
        return default_state();
    }
    let payload = fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok());
    let payload = match payload {
        Some(v) if v.is_object() => v,
        _ => return fail_closed_state(),
    };
    let mut state = default_state();
    // `state.update(payload)` — overlay keys.
    if let (Some(base), Some(over)) = (state.as_object_mut(), payload.as_object()) {
        for (k, v) in over {
            base.insert(k.clone(), v.clone());
        }
    }
    // `cooldown_seconds = _coerce_cooldown_seconds(...)` with except→0.
    let coerced = coerce_cooldown_seconds(state.get("cooldown_seconds")).unwrap_or(0);
    state
        .as_object_mut()
        .unwrap()
        .insert("cooldown_seconds".to_owned(), json!(coerced));
    state
}

/// `_fail_closed_state` (`approval_gate.py:1369-1372`) — default + forced on.
pub fn fail_closed_state() -> Value {
    let mut state = default_state();
    if let Some(o) = state.as_object_mut() {
        o.insert("enabled".to_owned(), json!(true));
        o.insert("fail_closed".to_owned(), json!(true));
    }
    state
}

/// `_coerce_cooldown_seconds` (`approval_gate.py:1377-1391`) — int/str→int,
/// not in `ALLOWED_COOLDOWNS` → `Err` (Python raises `ApprovalGateError`).
pub fn coerce_cooldown_seconds(value: Option<&Value>) -> Result<i64, String> {
    let seconds = match value {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0
            } else {
                t.parse::<i64>().unwrap_or(0)
            }
        }
        _ => 0,
    };
    if APPROVAL_GATE_ALLOWED_COOLDOWNS.contains(&(seconds as u64)) {
        Ok(seconds)
    } else {
        Err("approval_gate_invalid_cooldown".to_owned())
    }
}

/// `default_state` (`approval_gate_state.py:67-77`).
pub fn default_state() -> Value {
    json!({
        "enabled": false,
        "cooldown_seconds": 0,
        "strict_all_decisions": false,
        "failed_attempts": 0,
        "password_failed_attempts": 0,
        "totp_failed_attempts": 0,
        "factor_generation": 0,
        "totp_enabled": false,
    })
}

/// `write_state` (`approval_gate_state.py:55-65`) — mkdir parents, set
/// `updated_at = now || iso_from_epoch(time.time())`, write
/// `json.dumps(payload, indent=2, sort_keys=True) + "\n"` to
/// `approval-gate.json.tmp`, chmod 0o600, rename → `approval-gate.json`.
pub fn write_state(guard_home: &Path, state: &Value, now: Option<&str>) -> std::io::Result<()> {
    fs::create_dir_all(guard_home)?;
    let mut payload = state.clone();
    if !payload.is_object() {
        payload = json!({});
    }
    let updated_at = match now {
        Some(n) => n.to_owned(),
        None => iso_from_epoch(now_epoch_seconds()),
    };
    payload
        .as_object_mut()
        .expect("object")
        .insert("updated_at".to_owned(), Value::String(updated_at));

    // `json.dumps(payload, indent=2, sort_keys=True)` — sort keys, 2-space indent.
    let body = json_dumps_sorted_indent2(&payload);
    let path = state_path(guard_home);
    let tmp = path.with_extension("json.tmp"); // `with_suffix(".json.tmp")`
    fs::write(&tmp, format!("{body}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// `json.dumps(payload, indent=2, sort_keys=True)` — recursively sort object
/// keys, indent 2, `": "`/`,` separators, `ensure_ascii=False` is the Python
/// default ONLY when `ensure_ascii` omitted? No: Python default is
/// `ensure_ascii=True` → non-ASCII escapes as `\uXXXX`. We match that.
fn json_dumps_sorted_indent2(value: &Value) -> String {
    let mut out = String::new();
    dumps_sorted(value, 0, &mut out);
    out
}

fn dumps_sorted(value: &Value, depth: usize, out: &mut String) {
    const INDENT: &str = "  ";
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            let pad: String = INDENT.repeat(depth + 1);
            let mut first = true;
            for k in keys {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push('\n');
                out.push_str(&pad);
                out.push_str(&dumps_string(k));
                out.push_str(": ");
                dumps_sorted(&map[k], depth + 1, out);
            }
            out.push('\n');
            out.push_str(&INDENT.repeat(depth));
            out.push('}');
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            let pad: String = INDENT.repeat(depth + 1);
            let mut first = true;
            for item in arr {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push('\n');
                out.push_str(&pad);
                dumps_sorted(item, depth + 1, out);
            }
            out.push('\n');
            out.push_str(&INDENT.repeat(depth));
            out.push(']');
        }
        Value::String(s) => out.push_str(&dumps_string(s)),
        _ => {
            // numbers/bools/null: serde_json's compact formatting matches
            // Python's `json.dumps` scalar rendering for these types.
            out.push_str(&serde_json::to_string(value).unwrap_or_else(|_| "null".into()));
        }
    }
}

/// Python `json.dumps` string escaping with `ensure_ascii=True`: escapes
/// `"` `\` control chars, and every non-ASCII char as `\uXXXX` (or a surrogate
/// pair for astral planes).
fn dumps_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                // ensure_ascii=True → BMP as \uXXXX, astral as surrogate pair.
                let cp = c as u32;
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let v = cp - 0x1_0000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

fn now_epoch_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// `verifier` (`approval_gate_state.py:80-83`) — `state["verifier"]` if object.
pub fn verifier(state: &Value) -> Option<&Map<String, Value>> {
    state.get("verifier").and_then(|v| v.as_object())
}

/// `verify_password` (`approval_gate_state.py:85-96`) — PBKDF2-HMAC-SHA256,
/// **base64** salt + hash (NOT hex), `hmac.compare_digest`. `None`/malformed
/// verifier → `false`.
pub fn verify_password(password: &str, verifier_payload: Option<&Map<String, Value>>) -> bool {
    let verifier = match verifier_payload {
        Some(v) => v,
        None => return false,
    };
    let iterations = match optional_int(verifier.get("iterations")) {
        Some(i) if i > 0 => i as u32,
        _ => return false,
    };
    let (salt_b64, hash_b64) = match (
        verifier.get("salt").and_then(|v| v.as_str()),
        verifier.get("hash").and_then(|v| v.as_str()),
    ) {
        (Some(s), Some(h)) => (s, h),
        _ => return false,
    };
    let salt = match b64_std_decode(salt_b64) {
        Some(s) => s,
        None => return false,
    };
    let expected = match b64_std_decode(hash_b64) {
        Some(e) => e,
        None => return false,
    };
    if expected.is_empty() {
        return false;
    }
    let mut digest = vec![0u8; expected.len()];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, iterations, &mut digest);
    constant_time_eq(&digest, &expected)
}

/// `enabled` (`approval_gate_state.py:99-100`) — `enabled or fail_closed`.
pub fn enabled(state: &Value) -> bool {
    state.get("enabled").and_then(|v| v.as_bool()) == Some(true)
        || state.get("fail_closed").and_then(|v| v.as_bool()) == Some(true)
}

/// `record_failed_attempt` (`approval_gate_state.py:105-126`) — bump the
/// factor + combined counters; on reaching a lockout threshold set
/// `locked_until = now+300` and reset all counters. Persists via `write_state`.
pub fn record_failed_attempt(
    guard_home: &Path,
    state: &mut Value,
    factor: ApprovalGateFactor,
    now: Option<&str>,
) {
    let now_epoch = epoch(now);
    let factor_key = factor.attempt_key();
    let factor_attempts = optional_int(state.get(factor_key)).unwrap_or(0) + 1;
    let combined_attempts = optional_int(state.get("failed_attempts")).unwrap_or(0) + 1;
    let obj = state.as_object_mut().expect("state object");
    obj.insert(factor_key.to_owned(), json!(factor_attempts));
    obj.insert("failed_attempts".to_owned(), json!(combined_attempts));
    if factor_attempts >= APPROVAL_GATE_LOCKOUT_FAILURES
        || combined_attempts >= APPROVAL_GATE_COMBINED_LOCKOUT_FAILURES
    {
        obj.insert(
            "locked_until".to_owned(),
            json!(iso_from_epoch(
                now_epoch + APPROVAL_GATE_LOCKOUT_SECONDS as f64
            )),
        );
        obj.insert("failed_attempts".to_owned(), json!(0));
        obj.insert("password_failed_attempts".to_owned(), json!(0));
        obj.insert("totp_failed_attempts".to_owned(), json!(0));
    }
    let _ = write_state(guard_home, state, now);
}

/// `reset_failed_attempts` (`approval_gate_state.py:129-135`) — reset every
/// factor budget only after the required factor set succeeds.
pub fn reset_failed_attempts(state: &mut Value) {
    let obj = match state.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    obj.insert("failed_attempts".to_owned(), json!(0));
    obj.insert("password_failed_attempts".to_owned(), json!(0));
    obj.insert("totp_failed_attempts".to_owned(), json!(0));
    obj.remove("locked_until");
}

/// `cooldown_active` (`approval_gate_state.py:138-139`).
pub fn cooldown_active(state: &Value, now_epoch: f64) -> bool {
    is_future(
        optional_string(state.get("cooldown_expires_at")).as_deref(),
        now_epoch,
    )
}

/// `is_future` (`approval_gate_state.py:142-145`) — `epoch(value) > now_epoch`.
pub fn is_future(value: Option<&str>, now_epoch: f64) -> bool {
    match value {
        None => false,
        Some(v) => epoch(Some(v)) > now_epoch,
    }
}

/// `epoch` (`approval_gate_state.py:148-155`) — `None` → `time.time()`;
/// `...Z` → `+00:00`; parse → unix seconds; `ValueError` → `0.0`.
///
/// `utc_timestamp_micros` returns `Option<i64>` micros; on parse failure we
/// return `0.0`, matching Python's `except ValueError: return 0.0`.
pub fn epoch(value: Option<&str>) -> f64 {
    match value {
        None => now_epoch_seconds(),
        Some(v) => {
            let normalized = if let Some(stripped) = v.strip_suffix('Z') {
                format!("{stripped}+00:00")
            } else {
                v.to_owned()
            };
            guard_contracts::utc_timestamp_micros(&normalized)
                .map(|m| m as f64 / 1_000_000.0)
                .unwrap_or(0.0)
        }
    }
}

/// `iso_from_epoch` (`approval_gate_state.py:158-159`) —
/// `datetime.fromtimestamp(v, utc).isoformat()`. Reuses the canonical emitter:
/// micros → `...T...+00:00`. Python emits `isoformat()` default timespec
/// (`auto`) which trims trailing microsecond zeros — but the stored values in
/// this module are whole-second epochs, so `.000000` collapses to omitted
/// fraction. To match Python exactly we use `canonical_utc_timestamp`, which
/// emits fixed `.ffffff`; Python's `isoformat()` on a whole-second timestamp
/// emits NO fraction. Divergence is only cosmetic (parse-equivalent), but for
/// byte parity we emit Python's `auto` form: fraction only when non-zero.
pub fn iso_from_epoch(value: f64) -> String {
    let micros = (value * 1_000_000.0).round() as i64;
    epoch_micros_to_iso(micros)
}

/// micros → `YYYY-MM-DDTHH:MM:SS[.ffffff]+00:00` with `isoformat` `auto`
/// fraction (omitted when `us == 0`). Mirrors `canonical_utc_timestamp`'s math.
fn epoch_micros_to_iso(micros: i64) -> String {
    // Convert micros back through the contract parser's inverse by formatting
    // a seconds-precision value then re-canonicalizing is lossy; instead emit
    // directly using days/civil math via canonical on a probe string is not
    // available. Reuse guard_contracts' canonical path is seconds-in → we
    // instead emit from micros using the same civil algorithm.
    let days = micros.div_euclid(86_400_000_000);
    let within = micros.rem_euclid(86_400_000_000);
    let (year, month, day) = civil_from_days(days);
    let hour = (within / 3_600_000_000) as u32;
    let minute = ((within % 3_600_000_000) / 60_000_000) as u32;
    let second = ((within % 60_000_000) / 1_000_000) as u32;
    let us = (within % 1_000_000) as u32;
    if us == 0 {
        // Python isoformat(timespec='auto') omits an all-zero fraction.
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{us:06}+00:00")
    }
}

// Howard Hinnant civil-from-days (same algorithm as utc_timestamp.rs).
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let day_of_era = z - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_p = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_p + 2) / 5 + 1) as u32;
    let month = if month_p < 10 {
        month_p + 3
    } else {
        month_p - 9
    } as u32;
    let year = year + i64::from(month <= 2);
    (year, month, day)
}

/// `optional_string` (`approval_gate_state.py:162-165`) — non-empty str.
pub fn optional_string(value: Option<&Value>) -> Option<String> {
    match value.and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Some(s.to_owned()),
        _ => None,
    }
}

/// `optional_bool` (`approval_gate_state.py:168-172`) — bool, else bool fallback.
pub fn optional_bool(value: Option<&Value>, fallback: Option<bool>) -> Option<bool> {
    if let Some(b) = value.and_then(|v| v.as_bool()) {
        return Some(b);
    }
    fallback
}

/// `optional_int` (`approval_gate_state.py:175-184`) — bool→int, int, or
/// numeric str (Python `int()`). Floats are NOT ints (Python `isinstance(x,int)`
/// is false for float).
pub fn optional_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Bool(b)) => Some(*b as i64),
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                t.parse::<i64>().ok()
            }
        }
        _ => None,
    }
}

/// `optional_float` (`approval_gate_state.py:187-196`) — bool→float, int/float,
/// or numeric str.
#[allow(dead_code)]
pub fn optional_float(value: Option<&Value>) -> Option<f64> {
    match value {
        Some(Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                t.parse::<f64>().ok()
            }
        }
        _ => None,
    }
}

/// `prune_grants` (`approval_gate_state.py:202-208`) — in-place drop of grants
/// whose `expires_epoch <= now`. Operates on the `_ACTIVE_GRANTS` dict shape
/// (`{grant_id: {expires_epoch, ...}}`); the Rust grant table manages its own
/// pruning, so this is provided for parity with callers that pass a plain map.
#[allow(dead_code)]
pub fn prune_grants(grants: &mut Map<String, Value>, now_epoch: f64) {
    grants.retain(|_, metadata| {
        optional_float(metadata.get("expires_epoch")).unwrap_or(0.0) > now_epoch
    });
}

fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s).ok()
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verifier for password "correct horse battery" generated by the Python
    // `verify_password` reference: salt b64 of 0x01..0x10, iterations 310000.
    const VERIFIER: &str = r#"{"salt":"AQIDBAUGBwgJCgsMDQ4PEA==","hash":"LnzsqzF1RwckQbo6EfZW6OXVxlmuKxwnvvTcPI0jdNw=","iterations":310000,"algorithm":"pbkdf2_sha256"}"#;

    fn verifier_obj() -> Map<String, Value> {
        serde_json::from_str::<Value>(VERIFIER)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn verify_password_oracle() {
        let v = verifier_obj();
        assert!(verify_password("correct horse battery", Some(&v)));
        assert!(!verify_password("nope", Some(&v)));
        assert!(!verify_password("correct horse battery", None));
        // Wrong iterations → mismatch.
        let mut bad = verifier_obj();
        bad.insert("iterations".into(), json!(1));
        assert!(!verify_password("correct horse battery", Some(&bad)));
        // Malformed b64 → fail closed.
        let mut badb64 = verifier_obj();
        badb64.insert("hash".into(), json!("!!!notb64"));
        assert!(!verify_password("correct horse battery", Some(&badb64)));
    }

    #[test]
    fn iso_epoch_round_trip_and_python_oracle() {
        assert_eq!(iso_from_epoch(0.0), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso_from_epoch(1690000000.0), "2023-07-22T04:26:40+00:00");
        assert_eq!(
            iso_from_epoch(1690000000.123456),
            "2023-07-22T04:26:40.123456+00:00"
        );
        // `...Z` normalizes; `fromisoformat` seconds.
        assert_eq!(epoch(Some("2023-07-22T02:40:00Z")), 1689993600.0);
        // Parse failure → 0.0.
        assert_eq!(epoch(Some("not-a-date")), 0.0);
    }

    #[test]
    fn is_future_and_cooldown() {
        assert!(is_future(Some("2999-01-01T00:00:00+00:00"), 1690000000.0));
        assert!(!is_future(Some("2000-01-01T00:00:00+00:00"), 1690000000.0));
        assert!(!is_future(None, 0.0));
        let active = json!({"cooldown_expires_at": "2999-01-01T00:00:00+00:00"});
        assert!(cooldown_active(&active, 1690000000.0));
        let expired = json!({"cooldown_expires_at": "2000-01-01T00:00:00+00:00"});
        assert!(!cooldown_active(&expired, 1690000000.0));
    }

    #[test]
    fn optional_coercions_match_python() {
        assert_eq!(optional_int(Some(&json!(true))), Some(1));
        assert_eq!(optional_int(Some(&json!(7))), Some(7));
        assert_eq!(optional_int(Some(&json!("42"))), Some(42));
        assert_eq!(optional_int(Some(&json!("x"))), None);
        assert_eq!(optional_int(Some(&json!(3.5))), None); // float is not int
        assert_eq!(optional_int(None), None);

        assert_eq!(optional_string(Some(&json!("a"))).as_deref(), Some("a"));
        assert_eq!(optional_string(Some(&json!(""))), None);
        assert_eq!(optional_string(None), None);

        assert_eq!(optional_float(Some(&json!(true))), Some(1.0));
        assert_eq!(optional_float(Some(&json!(2))), Some(2.0));
        assert_eq!(optional_float(Some(&json!("1.5"))), Some(1.5));
        assert_eq!(optional_float(Some(&json!("x"))), None);
    }

    #[test]
    fn default_and_enabled_and_fail_closed() {
        let d = default_state();
        assert_eq!(d["enabled"], json!(false));
        assert_eq!(d["factor_generation"], json!(0));
        assert!(!enabled(&d));
        let fc = fail_closed_state();
        assert_eq!(fc["enabled"], json!(true));
        assert_eq!(fc["fail_closed"], json!(true));
        assert!(enabled(&fc));
        // enabled via fail_closed even when enabled=false
        let fc_only = json!({"enabled": false, "fail_closed": true});
        assert!(enabled(&fc_only));
    }

    #[test]
    fn load_state_merges_and_fails_closed() {
        let home = std::env::temp_dir().join(format!("gate-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        // Absent → default.
        let absent = load_state(&home);
        assert_eq!(absent["cooldown_seconds"], json!(0));
        assert!(!enabled(&absent));
        // Corrupt → fail_closed.
        fs::write(home.join(APPROVAL_GATE_STATE_FILE), "not json{{").unwrap();
        let corrupt = load_state(&home);
        assert!(enabled(&corrupt));
        assert_eq!(corrupt["fail_closed"], json!(true));
        // Valid merge: enabled + bad cooldown coerced to 0.
        fs::write(
            home.join(APPROVAL_GATE_STATE_FILE),
            r#"{"enabled": true, "cooldown_seconds": 12345, "custom_key": "x"}"#,
        )
        .unwrap();
        let merged = load_state(&home);
        assert_eq!(merged["enabled"], json!(true));
        assert_eq!(merged["cooldown_seconds"], json!(0)); // 12345 not allowed → 0
        assert_eq!(merged["custom_key"], json!("x"));
        assert_eq!(merged["factor_generation"], json!(0)); // default preserved
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn write_state_sorts_and_stamps_updated_at() {
        let home = std::env::temp_dir().join(format!("gate-wr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let mut st = default_state();
        st.as_object_mut().unwrap().insert("zeta".into(), json!(1));
        st.as_object_mut().unwrap().insert("alpha".into(), json!(2));
        write_state(&home, &st, Some("2026-01-01T00:00:00+00:00")).unwrap();
        let text = fs::read_to_string(home.join(APPROVAL_GATE_STATE_FILE)).unwrap();
        // Sorted keys + 2-space indent + trailing newline.
        assert!(text.ends_with('\n'));
        assert!(text.contains("\n  \"alpha\": 2,"));
        assert!(text.contains("\n  \"zeta\": 1\n}"));
        assert!(text.contains("\"updated_at\": \"2026-01-01T00:00:00+00:00\""));
        // alpha before enabled before zeta (sorted).
        let a = text.find("\"alpha\"").unwrap();
        let z = text.find("\"zeta\"").unwrap();
        assert!(a < z);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn record_and_reset_failed_attempts_lockout() {
        let home = std::env::temp_dir().join(format!("gate-lk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let now = "2026-01-01T00:00:00+00:00";
        let mut st = default_state();
        // Below threshold: counters accumulate, no lock.
        for _ in 0..(APPROVAL_GATE_LOCKOUT_FAILURES - 1) {
            record_failed_attempt(&home, &mut st, ApprovalGateFactor::Password, Some(now));
        }
        assert_eq!(st["password_failed_attempts"], json!(4));
        assert!(st.get("locked_until").is_none());
        // 5th → lockout: locked_until set, counters reset.
        record_failed_attempt(&home, &mut st, ApprovalGateFactor::Password, Some(now));
        assert_eq!(st["password_failed_attempts"], json!(0));
        assert_eq!(st["failed_attempts"], json!(0));
        let locked = st["locked_until"].as_str().unwrap();
        // now + 300s
        assert_eq!(locked, "2026-01-01T00:05:00+00:00");
        // reset clears everything including locked_until.
        reset_failed_attempts(&mut st);
        assert_eq!(st["failed_attempts"], json!(0));
        assert!(st.get("locked_until").is_none());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn public_config_to_dict_keys() {
        let cfg = ApprovalGatePublicConfig {
            enabled: true,
            configured: true,
            cooldown_seconds: 900,
            cooldown_active: true,
            cooldown_expires_at: Some("2026-01-01T00:15:00+00:00".into()),
            locked_until: None,
            fail_closed: false,
            strict_all_decisions: false,
            totp_enabled: true,
            totp_pending: false,
            totp_recent_satisfied: true,
        };
        let d = cfg.to_dict();
        assert_eq!(d["cooldown_seconds"], json!(900));
        assert_eq!(d["totp_enabled"], json!(true));
        assert_eq!(d["locked_until"], Value::Null);
        assert_eq!(d.as_object().unwrap().len(), 11);
    }
}
