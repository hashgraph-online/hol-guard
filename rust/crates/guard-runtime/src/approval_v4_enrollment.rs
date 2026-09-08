use guard_contracts::{ApprovalEnrollmentRequestV4, NATIVE_APPROVAL_ENROLLMENT_REQUEST_V4_SCHEMA};
use guard_policy_snapshot::canonical_json_bytes;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

const MAX_RP_ID_BYTES: usize = 255;
const MAX_ORIGIN_BYTES: usize = 2048;

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.chars().all(|character| {
            !character.is_control() && !character.is_whitespace() && character != '\\'
        })
}

pub(super) fn valid_rp_id(value: &str) -> bool {
    if !valid_text(value, MAX_RP_ID_BYTES) || !value.is_ascii() {
        return false;
    }
    if value.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    if value.starts_with('[') && value.ends_with(']') {
        return value[1..value.len() - 1].parse::<Ipv6Addr>().is_ok();
    }
    value.is_ascii()
        && value == value.to_ascii_lowercase()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

pub(super) fn valid_origin(value: &str) -> bool {
    if !valid_text(value, MAX_ORIGIN_BYTES) || !value.is_ascii() {
        return false;
    }
    if value == "http://localhost" {
        return true;
    }
    if let Some(rest) = value.strip_prefix("http://") {
        let Some((host, port)) = split_origin_authority(rest) else {
            return false;
        };
        if !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
            return false;
        }
        return port.is_none_or(|value| valid_port(value, 80));
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let Some((host, port)) = split_origin_authority(rest) else {
        return false;
    };
    valid_rp_id(host) && port.is_none_or(|value| valid_port(value, 443))
}

pub(super) fn origin_matches_rp_id(origin: &str, rp_id: &str) -> bool {
    let Some((host, _port)) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .and_then(split_origin_authority)
    else {
        return false;
    };
    host == rp_id
}

fn split_origin_authority(value: &str) -> Option<(&str, Option<&str>)> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('?')
        || value.contains('#')
        || value.contains('@')
    {
        return None;
    }
    if value.starts_with('[') {
        let close = value.find(']')?;
        let host = &value[..=close];
        let suffix = &value[close + 1..];
        if suffix.is_empty() {
            return Some((host, None));
        }
        return suffix
            .strip_prefix(':')
            .filter(|port| !port.is_empty())
            .map(|port| (host, Some(port)));
    }
    match value.split_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => Some((host, Some(port))),
        Some(_) => None,
        None => Some((value, None)),
    }
}

fn valid_port(value: &str, default_port: u16) -> bool {
    let canonical = value.trim_start_matches('0');
    let canonical = if canonical.is_empty() { "0" } else { canonical };
    !value.is_empty()
        && value.len() <= 5
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value == canonical
        && value
            .parse::<u16>()
            .is_ok_and(|port| port != 0 && port != default_port)
}

fn prepare_bindings(state_base: &Path) -> Result<(String, String), String> {
    super::approval_enrollment::with_transition_lock(state_base, || {
        if let Some(existing) = super::approval_enrollment::load_unlocked(state_base)? {
            return Ok((existing.device_binding, existing.installation_binding));
        }
        super::approval_enrollment::prepare_enrollment_unlocked(state_base)
    })
}

pub(crate) fn prepare_enrollment(
    state_base: &Path,
    rp_id: &str,
    origin: &str,
) -> Result<Vec<u8>, String> {
    super::validate_private_directory(state_base)?;
    if !valid_rp_id(rp_id) || !valid_origin(origin) || !origin_matches_rp_id(origin, rp_id) {
        return Err("native_approval_v4_enrollment_invalid".to_owned());
    }
    let (device_binding, installation_binding) = prepare_bindings(state_base)?;
    let request = ApprovalEnrollmentRequestV4 {
        schema: NATIVE_APPROVAL_ENROLLMENT_REQUEST_V4_SCHEMA.to_owned(),
        version: 4,
        rp_id: rp_id.to_owned(),
        origin: origin.to_owned(),
        device_binding,
        installation_binding,
        enrollment_generation: 1,
    };
    let value = serde_json::to_value(request)
        .map_err(|_| "native_approval_v4_enrollment_invalid".to_owned())?;
    canonical_json_bytes(&value).map_err(|_| "native_approval_v4_enrollment_invalid".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{origin_matches_rp_id, valid_origin, valid_rp_id};

    #[test]
    fn origins_are_canonical_and_bound_to_a_valid_rp_host() {
        assert!(valid_rp_id("example.com"));
        assert!(valid_rp_id("127.0.0.1"));
        assert!(valid_rp_id("[::1]"));
        assert!(valid_origin("https://example.com"));
        assert!(valid_origin("https://example.com:8443"));
        assert!(valid_origin("http://localhost"));
        assert!(valid_origin("http://localhost:8080"));
        assert!(valid_origin("http://127.0.0.1"));
        assert!(valid_origin("http://[::1]:8080"));
        assert!(valid_origin("https://[::1]"));
        assert!(origin_matches_rp_id("https://example.com", "example.com"));
        assert!(origin_matches_rp_id("http://127.0.0.1:8080", "127.0.0.1"));
        assert!(!origin_matches_rp_id(
            "https://example.com",
            "other.example.com"
        ));
        assert!(!origin_matches_rp_id(
            "https://example.com:8443",
            "other.example.com"
        ));
        assert!(!valid_origin("https://example.com:443"));
        assert!(!valid_origin("https://example.com:08443"));
        assert!(!valid_origin("https://user@example.com"));
        assert!(!valid_origin("https://example.com/path"));
        assert!(!valid_origin("https://example.com "));
        assert!(!valid_origin("http://example.com:8080"));
        assert!(!valid_origin("http://192.0.2.1:8080"));
    }
}
