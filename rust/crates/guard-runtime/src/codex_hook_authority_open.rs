//! Opening the signed Codex hook records: authenticate the text against the
//! key and the expected context, then apply each kind's own checks.

use super::*;

pub(super) type Opened = Result<(Map<String, Value>, String), &'static str>;

/// Split off and verify a record's authentication under `kind`'s purpose.
pub(super) fn authenticated(
    kind: Kind,
    payload: &mut Map<String, Value>,
    secret: &Secret,
) -> Result<Option<String>, ()> {
    let Some(Value::Object(authentication)) = payload.remove("authentication") else {
        return Err(());
    };
    let verification = local_authority_integrity_op::verify(
        &Value::Object(payload.clone()),
        &authentication,
        Some(&secret.key),
        Some(&secret.key_id),
        kind.purpose(),
    );
    if verification.get("status").and_then(Value::as_str) != Some("valid") {
        return Err(());
    }
    Ok(text(authentication.get("signed_at")).map(str::to_owned))
}

pub(super) fn open_recovery(
    raw: &str,
    guard_home: &str,
    live_config_conflict: bool,
    secret: &Secret,
) -> Opened {
    let kind = Kind::Recovery;
    if raw.len() > kind.max_bytes() {
        return Err("record_invalid");
    }
    let Ok(Value::Object(mut payload)) = parse_python_json(raw) else {
        return Err("record_invalid");
    };
    let has_authentication = matches!(payload.get("authentication"), Some(Value::Object(_)));
    if !has_authentication
        || text(payload.get("schema")) != Some(kind.schema())
        || text(payload.get("guard_home")) != Some(guard_home)
        || text(payload.get("installation_id")) != Some(secret.installation_id.as_str())
    {
        return Err("authentication_invalid");
    }
    let signed_at =
        authenticated(kind, &mut payload, secret).map_err(|()| "authentication_invalid")?;
    let Some(config) =
        text(payload.get("config_path")).filter(|path| Path::new(path).is_absolute())
    else {
        return Err("target_invalid");
    };
    if text(payload.get("phase")) != Some("config_conflict")
        && !live_config_conflict
        && compound_git_paths::resolve(Path::new(config))
            .as_deref()
            .and_then(Path::to_str)
            != Some(config)
    {
        return Err("target_changed");
    }
    if !matches!(
        text(payload.get("phase")),
        Some("prepared" | "committed" | "config_conflict")
    ) {
        return Err("phase_invalid");
    }
    if (payload.contains_key("after_receipt") || payload.contains_key("before_receipt"))
        && (!payload.contains_key("before_receipt")
            || !matches!(payload.get("after_receipt"), Some(Value::String(_))))
    {
        return Err("record_invalid");
    }
    if payload.contains_key("repair_plan") {
        validate_repair_record(&payload)?;
    }
    Ok((payload, signed_at.unwrap_or_default()))
}

pub(super) fn open_receipt(raw: &str, guard_home: &str, config: &str, secret: &Secret) -> Opened {
    let kind = Kind::Receipt;
    if raw.len() > kind.max_bytes() {
        return Err("receipt_invalid");
    }
    let Ok(Value::Object(mut payload)) = parse_python_json(raw) else {
        return Err("receipt_invalid");
    };
    if !keys_are(&payload, &RECEIPT_FIELDS) {
        return Err("receipt_invalid");
    }
    if text(payload.get("schema")) != Some(kind.schema())
        || text(payload.get("guard_home")) != Some(guard_home)
        || text(payload.get("config_path")) != Some(config)
        || text(payload.get("installation_id")) != Some(secret.installation_id.as_str())
    {
        return Err("receipt_authentication_invalid");
    }
    let signed_at =
        authenticated(kind, &mut payload, secret).map_err(|()| "receipt_authentication_invalid")?;
    let manifest = match decode(payload.get("manifest")) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return Err("receipt_invalid"),
        Err(reason) => return Err(reason),
    };
    if signed_at.as_deref() != Some(sha256_hex(&manifest).as_str()) {
        return Err("receipt_invalid");
    }
    Ok((payload, signed_at.unwrap_or_default()))
}

pub(super) fn open_request(
    kind: Kind,
    raw: &str,
    guard_home: &str,
    config: &str,
    now: f64,
    secret: &Secret,
) -> Opened {
    if raw.len() > kind.max_bytes() {
        return Err("invalid");
    }
    let Ok(Value::Object(mut payload)) = parse_python_json(raw) else {
        return Err("invalid");
    };
    if !keys_are(&payload, &REQUEST_FIELDS) {
        return Err("invalid");
    }
    if text(payload.get("schema")) != Some(kind.schema())
        || text(payload.get("guard_home")) != Some(guard_home)
        || text(payload.get("config_path")) != Some(config)
    {
        return Err("context_invalid");
    }
    let complete = match payload.get("authentication") {
        Some(Value::Object(authentication)) => {
            keys_are(authentication, &AUTHENTICATION_FIELDS)
                && is_int(authentication.get("integrity_version"))
        }
        _ => false,
    };
    if !complete || text(payload.get("installation_id")) != Some(secret.installation_id.as_str()) {
        return Err("authentication_invalid");
    }
    let signed_at =
        authenticated(kind, &mut payload, secret).map_err(|()| "authentication_invalid")?;
    let created = real(payload.get("created_monotonic"));
    let expires = real(payload.get("expires_monotonic"));
    let (Some(created), Some(expires)) = (created, expires) else {
        return Err("expired");
    };
    let window = expires - created;
    let window_ok = window > 0.0 && window <= REVIEW_SECONDS + REVIEW_TIMESTAMP_SLACK_SECONDS;
    if !(window_ok && created <= now && now < expires) {
        return Err("expired");
    }
    Ok((payload, signed_at.unwrap_or_default()))
}
