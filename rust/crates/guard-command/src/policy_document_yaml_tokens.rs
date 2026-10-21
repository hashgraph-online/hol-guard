//! Restrictions over lossless scanner observations; Rust owns admission.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::time::Instant;

pub(super) fn validate(input: &Value, deadline: Instant) -> Result<Value, &'static str> {
    let tokens = input["tokens"]
        .as_array()
        .ok_or("policy_yaml_tokens_invalid")?;
    let mut depth: usize = 0;
    for (index, token) in tokens.iter().enumerate() {
        if Instant::now() >= deadline {
            return Err("policy_document_deadline");
        }
        let row = token
            .as_array()
            .filter(|row| row.len() == 5)
            .ok_or("policy_yaml_tokens_invalid")?;
        let kind = row[0].as_str().ok_or("policy_yaml_tokens_invalid")?;
        for mark in [&row[1], &row[2]] {
            if !mark.is_null() && mark.as_u64().filter(|mark| *mark > 0).is_none() {
                return Err("policy_yaml_tokens_invalid");
            }
        }
        let diagnostic = |code| json!({"code":code,"line":row[1],"column":row[2]});
        match kind {
            "scanner_resource" => return Ok(diagnostic("yaml_resource_limit")),
            "scanner_syntax" => return Ok(diagnostic("yaml_syntax")),
            _ => {}
        }
        if index >= 200_000 {
            return Ok(diagnostic("limit_tokens"));
        }
        match kind {
            "BlockMappingStartToken"
            | "BlockSequenceStartToken"
            | "FlowMappingStartToken"
            | "FlowSequenceStartToken" => {
                depth += 1;
                if depth > 33 {
                    return Ok(diagnostic("limit_depth"));
                }
            }
            "BlockEndToken" | "FlowMappingEndToken" | "FlowSequenceEndToken" => {
                depth = depth.saturating_sub(1)
            }
            "ScalarToken" => {
                let claim = row[3]
                    .as_array()
                    .filter(|claim| claim.len() == 2 && claim[0] == "text")
                    .ok_or("policy_yaml_tokens_invalid")?;
                let bytes = STANDARD
                    .decode(claim[1].as_str().ok_or("policy_yaml_tokens_invalid")?)
                    .map_err(|_| "policy_yaml_tokens_invalid")?;
                if bytes.len() % 4 != 0 {
                    return Err("policy_yaml_tokens_invalid");
                }
                if bytes.len() / 4 > 4096 {
                    return Ok(diagnostic("limit_string"));
                }
                let units: Vec<u32> = bytes
                    .chunks_exact(4)
                    .map(|part| u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
                    .collect();
                let digits = units.strip_prefix(&[45]).unwrap_or(&units);
                let integer = digits == [48]
                    || (digits.first().is_some_and(|unit| (49..=57).contains(unit))
                        && digits.iter().all(|unit| (48..=57).contains(unit)));
                if row[4].is_null() && integer && digits.len() > 16 {
                    return Ok(diagnostic("limit_integer"));
                }
            }
            "AliasToken" => return Ok(diagnostic("yaml_alias")),
            "AnchorToken" => return Ok(diagnostic("yaml_anchor")),
            "TagToken" => return Ok(diagnostic("yaml_tag")),
            _ => {}
        }
    }
    Ok(Value::Null)
}
