//! Bounds authority over lossless, ordered Python transport claims.

use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

const SENSITIVE: &[&str] = &[
    "apikey",
    "authorization",
    "authheader",
    "credential",
    "credentials",
    "password",
    "privatekey",
    "rawcredential",
    "secretvalue",
    "token",
    "accesstoken",
    "refreshtoken",
];

fn text(claim: &Value) -> Result<Option<String>, &'static str> {
    if claim[0] != "text" {
        return Ok(None);
    }
    let bytes = STANDARD
        .decode(claim[1].as_str().ok_or("policy_bounds_claim_invalid")?)
        .map_err(|_| "policy_bounds_claim_invalid")?;
    if bytes.len() % 4 != 0 {
        return Err("policy_bounds_claim_invalid");
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|part| char::from_u32(u32::from_le_bytes([part[0], part[1], part[2], part[3]])))
        .collect::<Option<String>>())
}

fn diagnostic(code: &str, path: &[Value]) -> Value {
    json!({"code":code,"path_claims":path})
}

pub(super) fn validate(claim: &Value, deadline: Instant) -> Result<Value, &'static str> {
    visit(claim, &[], 0, deadline).map(|result| result.unwrap_or(Value::Null))
}

fn visit(
    claim: &Value,
    path: &[Value],
    depth: usize,
    deadline: Instant,
) -> Result<Option<Value>, &'static str> {
    if Instant::now() >= deadline {
        return Err("policy_document_deadline");
    }
    if depth > 32 {
        return Ok(Some(diagnostic("limit_depth", path)));
    }
    let pair = claim
        .as_array()
        .filter(|pair| pair.len() == 2)
        .ok_or("policy_bounds_claim_invalid")?;
    let error = |code: &str| Ok(Some(diagnostic(code, path)));
    match pair[0].as_str().ok_or("policy_bounds_claim_invalid")? {
        "text" => match text(claim)? {
            None => error("invalid_unicode"),
            Some(value) if value.chars().count() > 4096 => error("limit_string"),
            _ => Ok(None),
        },
        "float" => {
            let bits =
                u64::from_str_radix(pair[1].as_str().ok_or("policy_bounds_claim_invalid")?, 16)
                    .map_err(|_| "policy_bounds_claim_invalid")?;
            error(if f64::from_bits(bits).is_finite() {
                "unsupported_float"
            } else {
                "non_finite_number"
            })
        }
        "scalar" if pair[1].is_null() => Ok(None),
        "list" => {
            let values = pair[1].as_array().ok_or("policy_bounds_claim_invalid")?;
            let is_rules = path.len() == 2
                && text(&path[0])?.as_deref() == Some("spec")
                && text(&path[1])?.as_deref() == Some("rules");
            if values.len() > if is_rules { 1000 } else { 256 } {
                return error("limit_collection");
            }
            for (index, value) in values.iter().enumerate() {
                let mut child = path.to_vec();
                child.push(json!(index));
                if let Some(result) = visit(value, &child, depth + 1, deadline)? {
                    return Ok(Some(result));
                }
            }
            Ok(None)
        }
        "mapping" => {
            let values = pair[1].as_array().ok_or("policy_bounds_claim_invalid")?;
            if values.len() > 256 {
                return error("limit_collection");
            }
            for entry in values {
                let entry = entry
                    .as_array()
                    .filter(|entry| entry.len() == 2)
                    .ok_or("policy_bounds_claim_invalid")?;
                if entry[0][0] != "text" {
                    return error("mapping_key_type");
                }
                let mut child = path.to_vec();
                child.push(entry[0].clone());
                let Some(key) = text(&entry[0])? else {
                    return Ok(Some(diagnostic("invalid_unicode", &child)));
                };
                if key.chars().count() > 128 {
                    return Ok(Some(diagnostic("limit_key", &child)));
                }
                let normalized: String = key
                    .chars()
                    .flat_map(char::to_lowercase)
                    .filter(|character| {
                        character.is_ascii_lowercase() || character.is_ascii_digit()
                    })
                    .collect();
                let extension = path.iter().any(|part| {
                    text(part)
                        .ok()
                        .flatten()
                        .is_some_and(|part| part.starts_with("x-"))
                });
                if SENSITIVE.contains(&normalized.as_str()) && !extension {
                    return Ok(Some(diagnostic("forbidden_sensitive_field", &child)));
                }
                if let Some(result) = visit(&entry[1], &child, depth + 1, deadline)? {
                    return Ok(Some(result));
                }
            }
            Ok(None)
        }
        _ => Err("policy_bounds_claim_invalid"),
    }
}
