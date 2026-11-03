//! A distribution root is accepted only when its whole shape, identity and
//! validity window are exact. Nothing here trusts the bytes: the caller still
//! verifies the signed provenance before any of this authority is used.
use super::{hex, json_failure, location_code};
use crate::pack_lifecycle::location;
use serde_json::{json, Map, Value};

const SCHEMA: &str = "guard.extension-distribution.v2";
const POLICY_SCHEMA: &str = "guard.command-pack-release.v1";
const MAX_ROOT_BYTES: usize = 64 * 1024;
const ROOT_VALIDITY_SECONDS: u64 = 7 * 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: u64 = 300;
const ROOT_FIELDS: [&str; 11] = [
    "schema",
    "source_sha",
    "engine",
    "directory",
    "policy",
    "claim_provenance",
    "legacy",
    "issued_at",
    "expires_at",
    "authority_epoch",
    "publication_id",
];
const OVERSIZE_CODES: [&str; 11] = [
    "extension-count",
    "program-bytes",
    "catalog-bytes",
    "program-rules",
    "program-nodes",
    "source-envelope",
    "manifest-bytes",
    "archive-files",
    "archive-bytes",
    "directory-entries",
    "directory-bytes",
];

type Check = Result<(), String>;

fn reject<T>(code: &str) -> Result<T, String> {
    Err(code.to_owned())
}

fn exact<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let map = value.as_object()?;
    (map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))).then_some(map)
}

fn digits(value: &str, most: usize) -> bool {
    (1..=most).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_digit())
}

fn publication(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|text| text.split_once('.'))
        .is_some_and(|(run, attempt)| digits(run, 20) && digits(attempt, 10))
}

fn decode(data: &str) -> Result<Value, String> {
    if data.is_empty() || data.len() > MAX_ROOT_BYTES {
        return reject("distribution_root_too_large");
    }
    crate::strict_json::parse(data.as_bytes()).map_err(|code| json_failure(&code).to_owned())
}

fn index_reference(value: &Value, located: bool) -> Check {
    let mut keys = vec!["sha256", "length", "expanded_length", "kind"];
    if located {
        keys.push("location");
    }
    let sha = value["sha256"].as_str().unwrap_or("");
    if exact(value, &keys).is_none()
        || !hex(sha, 64)
        || !value["length"]
            .as_u64()
            .is_some_and(|n| (1..=MAX_ROOT_BYTES as u64).contains(&n))
        || value["expanded_length"] != value["length"]
        || value["kind"] != "data"
    {
        return reject("distribution_index_reference_invalid");
    }
    if located {
        location::check(&value["location"], sha, "object")
            .map_err(|rejection| location_code(&rejection).to_owned())?;
    }
    Ok(())
}

fn publication_ready(value: &Value, source: &str) -> Check {
    if !value.is_object() {
        return reject("distribution_legacy_status_invalid");
    }
    match value["status"].as_str() {
        Some("available") => {
            let keys = ["status", "manifest_sha256", "archive_sha256", "tag"];
            let digest = |key: &str| value[key].as_str().is_some_and(|s| hex(s, 64));
            if exact(value, &keys).is_none()
                || value["tag"] != format!("extension-artifacts-{source}")
                || !digest("manifest_sha256")
                || !digest("archive_sha256")
            {
                return reject("distribution_legacy_artifact_invalid");
            }
            Ok(())
        }
        Some("unsupported-oversize") => {
            let known = value["code"]
                .as_str()
                .is_some_and(|code| OVERSIZE_CODES.contains(&code));
            if exact(value, &["status", "code"]).is_none() || !known {
                return reject("distribution_legacy_oversize_invalid");
            }
            Ok(())
        }
        _ => reject("distribution_preparation_incomplete"),
    }
}

fn security_index(policy: &Value, field: &str, directory_count: u64) -> Check {
    let value = &policy[field];
    let revocations = field == "revocations";
    let keys: &[&str] = if revocations {
        &["count", "index", "epoch"]
    } else {
        &["count", "index"]
    };
    let Some(count) = exact(value, keys).and_then(|_| value["count"].as_u64()) else {
        return reject("distribution_security_count_invalid");
    };
    if count > 0 {
        index_reference(&value["index"], true)?;
    } else if !value["index"].is_null() {
        return reject("distribution_security_index_reference");
    }
    if !revocations && count > directory_count {
        return reject("distribution_defaults_exceed");
    }
    if revocations && value["epoch"].as_u64().is_none() {
        return reject("distribution_revocation_epoch_invalid");
    }
    Ok(())
}

fn references(root: &Value) -> Result<u64, String> {
    let (directory, policy) = (&root["directory"], &root["policy"]);
    if exact(directory, &["count", "index", "claims"]).is_none()
        || exact(policy, &["root", "transport", "defaults", "revocations"]).is_none()
    {
        return reject("distribution_references_incomplete");
    }
    let native = &policy["root"];
    let count = directory["count"].as_u64().filter(|n| *n > 0);
    let Some(count) = count.filter(|n| {
        native["schema"] == POLICY_SCHEMA
            && native["engine"] == root["engine"]
            && native["extensions"].as_u64() == Some(*n)
    }) else {
        return reject("distribution_identities_differ");
    };
    index_reference(&directory["index"], true)?;
    let claims = &directory["claims"];
    let Some(claim_count) = exact(claims, &["count", "index"])
        .and_then(|_| claims["count"].as_u64())
        .filter(|n| *n <= count)
    else {
        return reject("distribution_claim_count_invalid");
    };
    if claim_count > 0 {
        index_reference(&claims["index"], true)?;
    } else if !claims["index"].is_null() {
        return reject("distribution_claim_index_reference");
    }
    index_reference(&policy["transport"], true)?;
    index_reference(&native["index"], false)?;
    security_index(policy, "defaults", count)?;
    security_index(policy, "revocations", count)?;
    Ok(count)
}

/// Shape, identity, epoch, publication and validity checks, in the order a
/// caller sees them. An expired root is rejected last so a malformed root is
/// always reported as malformed.
pub(super) fn validate(input: &Value) -> Result<Value, String> {
    let data = input["data"]
        .as_str()
        .ok_or("distribution_request_invalid")?;
    let root = decode(data)?;
    let source = input["source"].as_str().unwrap_or("");
    if !hex(source, 40) {
        return reject("distribution_source_invalid");
    }
    if exact(&root, &ROOT_FIELDS).is_none()
        || root["schema"] != SCHEMA
        || root["source_sha"] != source
        || !root["engine"].as_str().is_some_and(|e| hex(e, 64))
    {
        return reject("distribution_identity_invalid");
    }
    if root["authority_epoch"].as_u64().is_none_or(|n| n == 0) {
        return reject("distribution_epoch_invalid");
    }
    if !publication(&root["publication_id"]) {
        return reject("distribution_publication_invalid");
    }
    let times = (
        input["now"].as_u64(),
        root["issued_at"].as_u64(),
        root["expires_at"].as_u64(),
    );
    let (Some(now), Some(issued), Some(expires)) = times else {
        return reject("distribution_validity_invalid");
    };
    if expires <= issued
        || expires - issued > ROOT_VALIDITY_SECONDS
        || issued > now.saturating_add(CLOCK_SKEW_SECONDS)
    {
        return reject("distribution_validity_invalid");
    }
    if root["claim_provenance"] != "resolved" {
        return reject("distribution_preparation_incomplete");
    }
    publication_ready(&root["legacy"], source)?;
    references(&root)?;
    if now >= expires {
        return reject("distribution_expired");
    }
    Ok(json!({"expires_at": expires}))
}
