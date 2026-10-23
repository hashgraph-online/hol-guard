//! Uninstalled, read-only local-model metadata diagnostic.
//! Input pins must be supplied by a trusted caller outside provider HTTP.

use gauntlet_contracts::canonicalize;
use gauntlet_provider_observer::observe_provider_metadata;
use serde_json::{json, Value};
use std::io::{self, Read};
use std::process::ExitCode;

const MAX_REQUEST: usize = 16 * 1024;
const REQUEST_SCHEMA: &str = "hol-gauntlet-provider-observe-request.v1";
const RESPONSE_SCHEMA: &str = "hol-gauntlet-provider-observe-response.v1";

fn parse_request(raw: &[u8]) -> Result<(String, String, Value), &'static str> {
    if raw.is_empty() || raw.len() > MAX_REQUEST {
        return Err("provider observation request exceeds its bound");
    }
    let canonical =
        canonicalize(raw).map_err(|_| "invalid bounded provider observation request")?;
    let value: Value = serde_json::from_slice(&canonical)
        .map_err(|_| "invalid bounded provider observation request")?;
    let fields = value
        .as_object()
        .ok_or("invalid provider observation request fields")?;
    if fields.len() != 4
        || value["schema"] != REQUEST_SCHEMA
        || !fields.contains_key("base_url")
        || !fields.contains_key("model_id")
        || !fields.contains_key("provider_pins")
        || !value["provider_pins"].is_object()
    {
        return Err("invalid provider observation request fields");
    }
    let base_url = value["base_url"]
        .as_str()
        .ok_or("exact provider route required")?;
    let model_id = value["model_id"]
        .as_str()
        .filter(|model| !model.is_empty() && model.len() <= 256)
        .ok_or("exact advertised model ID required")?;
    Ok((
        base_url.to_owned(),
        model_id.to_owned(),
        value["provider_pins"].clone(),
    ))
}

fn run(raw: &[u8]) -> Result<Value, String> {
    let (base_url, model_id, pins) = parse_request(raw).map_err(str::to_owned)?;
    let observation = observe_provider_metadata(&base_url, &model_id, &pins)
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "schema": RESPONSE_SCHEMA,
        "status": "observed",
        "observation": observation.to_json(),
        "qualification_eligible": false,
    }))
}

fn main() -> ExitCode {
    let mut raw = Vec::new();
    let result = io::stdin()
        .take((MAX_REQUEST + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())
        .and_then(|_| run(&raw));
    match result {
        Ok(response) => {
            println!("{response}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!(
                "{}",
                json!({
                    "schema": RESPONSE_SCHEMA,
                    "status": "unavailable",
                    "error": error,
                    "qualification_eligible": false,
                })
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_must_be_bounded_exact_and_externally_pinned() {
        let valid = json!({
            "schema":REQUEST_SCHEMA,
            "base_url":"http://host.lima.internal:8001/v1",
            "model_id":"outside-model",
            "provider_pins":{},
        });
        assert_eq!(
            parse_request(valid.to_string().as_bytes()).unwrap().1,
            "outside-model"
        );
        for raw in [
            br#"{"schema":"hol-gauntlet-provider-observe-request.v1","schema":"hol-gauntlet-provider-observe-request.v1","base_url":"x","model_id":"x","provider_pins":{}}"#.as_slice(),
            br#"{"schema":"hol-gauntlet-provider-observe-request.v1","base_url":"x","model_id":"x","provider_pins":{},"command":"curl"}"#.as_slice(),
            br#"{"schema":"hol-gauntlet-provider-observe-request.v1","base_url":"x","model_id":"x","provider_pins":[]}"#.as_slice(),
        ] {
            assert!(parse_request(raw).is_err());
        }
        assert!(parse_request(&vec![b' '; MAX_REQUEST + 1]).is_err());
    }
}
