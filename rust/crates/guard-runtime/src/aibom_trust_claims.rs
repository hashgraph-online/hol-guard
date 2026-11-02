//! `aibom_trust_claims` runner-authority kind: the local trust claims and the
//! local security summary `aibom_trust_metadata.py` attaches to one inventory
//! item.
//!
//! Python still owns the filesystem side: it scores the item, picks the Cisco
//! runs whose targets belong to it, and turns each finding path into a path
//! relative to the item. What it asks here is the claim each input becomes,
//! with the evidence and the evidence hash the attestation signer and the
//! verifier read later.
//!
//! One request per item:
//!
//! ```json
//! {
//!   "captured_at": "2026-07-16T12:00:00Z",
//!   "domain": null | {"domain", "profile_id", "profile_version", "spec_id",
//!                     "spec_version", "score", "adapters": [{"adapter_id",
//!                     "label", "weight", "emitted", "components": [{"key",
//!                     "score", "rationale", "evidence": [str]}]}]},
//!   "cisco_layers": [{"scanner": "skill" | "mcp", "run": RUN}],
//!   "security": null | {"scanner": "skill" | "mcp", "entity_type": str,
//!                       "run": RUN, "findings": [{"rule_id", "severity",
//!                       "file", "description", "title"}]}
//! }
//! ```
//!
//! where `RUN` is `{"status", "message", "source", "duration_ms",
//! "metadata", "finding_severities": [str]}`. The answer is
//! `{"resolution": {...} | null, "layers": [...], "local_security": {...} | null}`.

use guard_command::evidence_hash::guard_evidence_hash;
use serde_json::{json, Map, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

#[path = "aibom_trust_claims_scan.rs"]
mod scan;
use scan::{cisco_layer, local_security, merge_layers, Run};

const LOCAL_BASELINE_SCHEMA: &str = "guard-aibom-local-baseline-evidence.v1";
const MAX_DOMAIN_COMPONENTS: usize = 32;

type Fields = Map<String, Value>;

/// The Cisco scanner a run came from, with the names its claims carry.
#[derive(Clone, Copy)]
enum Scanner {
    Skill,
    Mcp,
}

impl Scanner {
    fn parse(value: Option<&Value>) -> Result<Self, &'static str> {
        match value.and_then(Value::as_str) {
            Some("skill") => Ok(Self::Skill),
            Some("mcp") => Ok(Self::Mcp),
            _ => Err(ERR_INVALID),
        }
    }

    fn layer_id(self) -> &'static str {
        match self {
            Self::Skill => "cisco_skill_scanner",
            Self::Mcp => "cisco_mcp_scanner",
        }
    }

    fn component_id(self) -> &'static str {
        match self {
            Self::Skill => "cisco.skill.score",
            Self::Mcp => "cisco.mcp.score",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Skill => "Cisco Skill Scanner",
            Self::Mcp => "Cisco MCP Scanner",
        }
    }

    fn provider(self) -> &'static str {
        match self {
            Self::Skill => "cisco-skill-scanner",
            Self::Mcp => "cisco-mcp-scanner",
        }
    }

    fn default_message(self) -> &'static str {
        match self {
            Self::Skill => "Skill security finding",
            Self::Mcp => "MCP security finding",
        }
    }

    /// The run metadata the security summary keeps for this scanner.
    fn security_metadata_keys(self) -> &'static [&'static str] {
        match self {
            Self::Skill => &[
                "analyzersUsed",
                "policyName",
                "mode",
                "skillsScanned",
                "skillsSkipped",
            ],
            Self::Mcp => &["analyzersUsed", "scanMode", "mode", "targetsScanned"],
        }
    }

    /// The metadata count reported as `scriptsTotal`.
    fn scripts_total_key(self) -> &'static str {
        match self {
            Self::Skill => "skillsScanned",
            Self::Mcp => "targetsScanned",
        }
    }
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let captured_at = args.get("captured_at").ok_or(ERR_INVALID)?;
    let mut layers = Vec::new();
    let mut resolution = Value::Null;
    match args.get("domain") {
        None | Some(Value::Null) => {}
        Some(Value::Object(domain)) => {
            let claims = domain_claims(domain, captured_at)?;
            resolution = claims.0;
            layers.push(claims.1);
        }
        Some(_) => return Err(ERR_INVALID),
    }
    for request in args
        .get("cisco_layers")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
    {
        let request = request.as_object().ok_or(ERR_INVALID)?;
        let scanner = Scanner::parse(request.get("scanner"))?;
        let run = Run::parse(request.get("run"))?;
        layers.push(cisco_layer(&run, scanner, captured_at));
    }
    let local_security = match args.get("security") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Object(security)) => local_security(security, captured_at)?,
        Some(_) => return Err(ERR_INVALID),
    };
    Ok(json!({
        "resolution": resolution,
        "layers": merge_layers(layers),
        "local_security": local_security,
    }))
}

/// `round()` of a score: Python rounds half to even.
fn rounded_score(value: Option<&Value>) -> Result<i64, &'static str> {
    let score = value.and_then(Value::as_f64).ok_or(ERR_INVALID)?;
    if !score.is_finite() {
        return Err(ERR_INVALID);
    }
    Ok(score.round_ties_even() as i64)
}

fn component_status(score: i64) -> &'static str {
    if score < 40 {
        "critical"
    } else if score < 70 {
        "warning"
    } else {
        "positive"
    }
}

fn provenance(derivation: &str) -> Value {
    json!({
        "origin": "hol-guard-local",
        "verificationStatus": "locally_derived",
        "derivation": derivation,
    })
}

fn string_field<'a>(fields: &'a Fields, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

/// The local baseline `trustResolution` claim and its `local_baseline` layer.
fn domain_claims(domain: &Fields, captured_at: &Value) -> Result<(Value, Value), &'static str> {
    let components = domain_components(domain)?;
    let evidence = baseline_evidence(domain, captured_at, &components)?;
    let evidence_hash = guard_evidence_hash(&evidence);
    let trust_score = rounded_score(domain.get("score"))?;
    let metadata = json!({
        "profileId": string_field(domain, "profile_id")?,
        "profileVersion": string_field(domain, "profile_version")?,
        "scorer": "hol-guard-local",
        "specId": string_field(domain, "spec_id")?,
        "specVersion": string_field(domain, "spec_version")?,
        "trustDomain": string_field(domain, "domain")?,
        "attestationStatus": "unsigned",
        "evidenceSchemaVersion": LOCAL_BASELINE_SCHEMA,
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "evidence": evidence,
        "evidenceHash": evidence_hash,
    });
    let resolution = json!({
        "resolutionSource": "local",
        "status": "local",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "trustScore": trust_score,
        "trustComponents": components,
        "capturedAt": captured_at,
        "provenance": provenance("hol-guard-local-baseline"),
        "metadata": metadata,
    });
    let layer = json!({
        "layerId": "local_baseline",
        "layerType": "local_baseline",
        "status": "local",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "trustScore": trust_score,
        "trustComponents": components,
        "capturedAt": captured_at,
        "provenance": provenance("hol-guard-local-baseline"),
        "metadata": metadata,
    });
    Ok((resolution, layer))
}

/// Component rows of every emitted adapter, at most 32.
fn domain_components(domain: &Fields) -> Result<Vec<Value>, &'static str> {
    let mut rows = Vec::new();
    for adapter in domain
        .get("adapters")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
    {
        let adapter = adapter.as_object().ok_or(ERR_INVALID)?;
        if !adapter
            .get("emitted")
            .and_then(Value::as_bool)
            .ok_or(ERR_INVALID)?
        {
            continue;
        }
        for component in adapter
            .get("components")
            .and_then(Value::as_array)
            .ok_or(ERR_INVALID)?
        {
            rows.push(component_row(
                adapter,
                component.as_object().ok_or(ERR_INVALID)?,
            )?);
        }
        if rows.len() >= MAX_DOMAIN_COMPONENTS {
            break;
        }
    }
    rows.truncate(MAX_DOMAIN_COMPONENTS);
    Ok(rows)
}

fn component_row(adapter: &Fields, component: &Fields) -> KindResult {
    let score = rounded_score(component.get("score"))?;
    let mut row = json!({
        "componentId": format!(
            "{}:{}",
            string_field(adapter, "adapter_id")?,
            string_field(component, "key")?
        ),
        "confidence": 85,
        "label": string_field(adapter, "label")?,
        "score": score,
        "status": component_status(score),
        "summary": string_field(component, "rationale")?,
        "weight": adapter.get("weight").filter(|w| w.is_number()).ok_or(ERR_INVALID)?,
    });
    let lines = component
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    if !lines.is_empty() {
        row["evidence"] = json!({ "lines": lines });
    }
    Ok(row)
}

fn baseline_evidence(
    domain: &Fields,
    captured_at: &Value,
    components: &[Value],
) -> Result<Fields, &'static str> {
    let rows: Vec<Value> = components
        .iter()
        .map(|component| {
            let mut row = json!({
                "componentId": component["componentId"],
                "confidence": component["confidence"],
                "label": component["label"],
                "score": component["score"],
                "status": component["status"],
                "summary": component["summary"],
                "weight": component["weight"],
            });
            if let Some(evidence) = component.get("evidence") {
                row["evidence"] = evidence.clone();
            }
            row
        })
        .collect();
    let evidence = json!({
        "source": "hol-guard-local-baseline",
        "capturedAt": captured_at,
        "trustDomain": string_field(domain, "domain")?,
        "profileId": string_field(domain, "profile_id")?,
        "profileVersion": string_field(domain, "profile_version")?,
        "specId": string_field(domain, "spec_id")?,
        "specVersion": string_field(domain, "spec_version")?,
        "componentCount": rows.len(),
        "components": rows,
    });
    match evidence {
        Value::Object(fields) => Ok(fields),
        _ => Err(ERR_INVALID),
    }
}

#[cfg(test)]
#[path = "aibom_trust_claims_tests.rs"]
mod tests;
