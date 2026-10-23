use super::{model_endpoint, verify_advertised_model, verify_model_endpoint};
use serde_json::Value;

#[test]
fn pinned_python_model_route_and_advertisement_cases_match() {
    let frozen: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_model_endpoint_v1.json"
    ))
    .unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = |path: &str| {
        manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .unwrap()["sha256"]
            .clone()
    };
    assert_eq!(frozen["schema"], "gauntlet-model-endpoint-fixtures.v1");
    assert_eq!(
        frozen["model_endpoint_source_sha256"],
        source("ci/gauntlet/benchmark/model_endpoint.py")
    );
    assert_eq!(
        frozen["preflight_source_sha256"],
        source("ci/gauntlet/benchmark/ci_runner_preflight.py")
    );
    let routes = frozen["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 19);
    for row in routes {
        let result = model_endpoint(row["base_url"].as_str().unwrap());
        if let Some(expected) = row.get("route") {
            assert_eq!(result.unwrap().to_json(), *expected, "{row}");
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                row["python_refusal"].as_str().unwrap(),
                "{row}"
            );
        }
    }
    let observed = frozen["observed"].as_array().unwrap();
    assert_eq!(observed.len(), 6);
    for row in observed {
        let metadata = row.get("observed").filter(|value| !value.is_null());
        let result = verify_model_endpoint(metadata, row["base_url"].as_str().unwrap());
        if let Some(expected) = row.get("route") {
            assert_eq!(result.unwrap().to_json(), *expected, "{row}");
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                row["python_refusal"].as_str().unwrap(),
                "{row}"
            );
        }
    }
    let models = frozen["models"].as_array().unwrap();
    assert_eq!(models.len(), 8);
    for row in models {
        let result = verify_advertised_model(&row["models"], row["model_id"].as_str().unwrap());
        if row.get("route").is_some() {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                row["python_refusal"].as_str().unwrap(),
                "{row}"
            );
        }
    }
}
