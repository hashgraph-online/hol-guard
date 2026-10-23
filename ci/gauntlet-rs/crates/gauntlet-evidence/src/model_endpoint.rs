//! Pure parity with the pinned Python local-model route and advertised-model
//! checks. No socket is opened and a valid route never grants inference.

use crate::{EvidenceError, Result};
use serde_json::{json, Value};

pub const DEFAULT_BASE_URL: &str = "http://host.lima.internal:8001/v1";
const FIXED_HOST: &str = "192.168.5.2";

fn invalid_endpoint() -> EvidenceError {
    EvidenceError::Invalid(
        "local model endpoints require an explicit HTTP port 8001/8002 and exact /v1 path",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEndpoint {
    pub base_url: String,
    pub host: &'static str,
    pub port: u16,
}

impl ModelEndpoint {
    pub fn to_json(&self) -> Value {
        json!({"base_url":self.base_url,"host":self.host,"port":self.port})
    }
}

/// Resolve only the four frozen local aliases on ports 8001/8002. The
/// returned socket address is fixed, so an alias cannot cause DNS egress.
pub fn model_endpoint(base_url: &str) -> Result<ModelEndpoint> {
    let authority = base_url
        .strip_prefix("http://")
        .and_then(|value| value.strip_suffix("/v1"))
        .ok_or_else(invalid_endpoint)?;
    let (alias, port) = authority.split_once(':').ok_or_else(invalid_endpoint)?;
    if !matches!(
        alias,
        "host.lima.internal" | "localhost" | "127.0.0.1" | "192.168.5.2"
    ) || !matches!(port, "8001" | "8002")
    {
        return Err(invalid_endpoint());
    }
    Ok(ModelEndpoint {
        base_url: base_url.to_owned(),
        host: FIXED_HOST,
        port: port.parse().expect("fixed port literal"),
    })
}

/// Historical absent endpoint metadata can establish only the original
/// default route. Explicit metadata must equal every expected field.
pub fn verify_model_endpoint(observed: Option<&Value>, base_url: &str) -> Result<ModelEndpoint> {
    let expected = model_endpoint(base_url)?;
    match observed {
        None if base_url != DEFAULT_BASE_URL => Err(EvidenceError::Invalid(
            "legacy model evidence cannot establish the frozen endpoint",
        )),
        Some(value) if *value != expected.to_json() => Err(EvidenceError::Invalid(
            "observed model endpoint differs from exact frozen controller declaration",
        )),
        _ => Ok(expected),
    }
}

/// Apply the Python preflight's exact one-model advertisement rule to an
/// already bounded, strictly decoded `/v1/models` response. Extra fields on
/// the model row remain allowed by the Python v1 contract.
pub fn verify_advertised_model(models: &Value, model_id: &str) -> Result<()> {
    let valid = models["data"].as_array().is_some_and(|rows| {
        rows.len() == 1
            && rows[0]
                .as_object()
                .is_some_and(|row| row.get("id").and_then(Value::as_str) == Some(model_id))
    });
    if !models.is_object() || !valid {
        return Err(EvidenceError::Invalid(
            "actual advertised model differs from exact frozen model",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "model_endpoint_tests.rs"]
mod tests;
