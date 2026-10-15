//! Replays vectors recorded from the retired Python OCI provider
//! (`tests/fixtures/oci_bundle/vectors.json.gz`). Each vector names the
//! bundle directory layout it needs; the harness builds it under a fresh
//! temporary root and substitutes `{ROOT}` in arguments and expectations.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use serde_json::Value;

use super::runner_authority_op::dispatch;
use super::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../../../../tests/fixtures/oci_bundle/vectors.json.gz");
const PLACEHOLDER: &str = "{ROOT}";

fn substitute(value: &Value, from: &str, to: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(from, to)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| substitute(item, from, to))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), substitute(item, from, to)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn build_layout(root: &Path, layout: &[Value]) {
    for entry in layout {
        let kind = entry[1].as_str().unwrap();
        let path = root.join(entry[0].as_str().unwrap());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        match kind {
            "dir" => fs::create_dir_all(&path).unwrap(),
            "file" => fs::write(&path, b"x").unwrap(),
            _ => symlink(entry[2].as_str().unwrap(), &path).unwrap(),
        }
    }
}

#[test]
fn recorded_python_oci_bundles_match_the_resident() {
    let document = gunzip_json(VECTORS);
    assert_eq!(document["version"], 1);
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 2500);
    let base = std::env::temp_dir().join(format!("oci-vectors-{}", std::process::id()));
    let mut failures = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        let root = base.join(index.to_string());
        fs::create_dir_all(&root).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        build_layout(&canonical, vector["fs"].as_array().unwrap());
        let root_text = canonical.to_string_lossy().into_owned();
        let args = substitute(&vector["args"], PLACEHOLDER, &root_text);
        let result = dispatch(vector["kind"].as_str().unwrap(), &args);
        let matches = match (&result, vector.get("expected_error")) {
            (Err(code), Some(expected)) => expected == code,
            (Ok(actual), None) => {
                let want = substitute(&vector["expected"], PLACEHOLDER, &root_text);
                match want
                    .get("plan_fields")
                    .and_then(|fields| fields["bundle_root"].as_str())
                {
                    // A bundle root is part of the plan digest and differs
                    // per run, so those vectors check every recorded field and
                    // re-derive the digest; rootless vectors pin the digest.
                    Some(root)
                        if !root.is_empty()
                            || vector["args"]["bundle"].to_string().contains(PLACEHOLDER) =>
                    {
                        let mut got = actual.clone();
                        let digest = got["plan_digest"].take();
                        let derived = got["plan_fields"].as_object().and_then(|fields| {
                            super::oci_bundle_op::framed_digest("guard.oci-plan.v1", fields).ok()
                        });
                        let mut expected = want;
                        expected["plan_digest"] = Value::Null;
                        if vector["args"]["bundle"].to_string().contains(PLACEHOLDER) {
                            // The bundle itself names the per-run root, so its
                            // digest is not reproducible; the digest algorithm
                            // is pinned by every other vector.
                            got["plan_fields"]["bundle_digest"] = Value::Null;
                            expected["plan_fields"]["bundle_digest"] = Value::Null;
                        }
                        derived.is_some_and(|expect| digest == expect.as_str()) && got == expected
                    }
                    _ => *actual == want,
                }
            }
            _ => false,
        };
        if !matches {
            failures.push(vector["name"].as_str().unwrap().to_owned());
        }
        let _ = fs::remove_dir_all(&root);
    }
    let _ = fs::remove_dir_all(&base);
    assert!(
        failures.is_empty(),
        "{} mismatches: {:?}",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
}
