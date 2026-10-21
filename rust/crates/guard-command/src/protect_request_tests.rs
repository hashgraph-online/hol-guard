//! Vectors recorded from `protect.py` by
//! `scripts/record_protect_request_vectors.py` (gzipped).

use std::io::Read;

use serde_json::{json, Value};

use super::*;

fn vectors() -> Vec<Value> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(
        &include_bytes!("../tests/fixtures/protect_request_vectors.json.gz")[..],
    )
    .read_to_string(&mut text)
    .unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn strings(value: &Value) -> Vec<String> {
    serde_json::from_value(value.clone()).unwrap()
}

#[test]
fn parity_vectors_match_the_recorded_python_outputs() {
    let vectors = vectors();
    assert!(vectors.len() > 400);
    let mut mismatches = Vec::new();
    for vector in &vectors {
        let command = strings(&vector["command"]);
        // The vectors were recorded on POSIX, where a backslash is not a path
        // separator. Windows strips the directory, so those executables differ.
        if cfg!(windows)
            && command
                .first()
                .is_some_and(|program| program.contains('\\'))
        {
            continue;
        }
        let advisories = vector["advisories"].as_array().unwrap();
        let actual = match parse_protect_command(&command) {
            Ok(request) => {
                let verdict = evaluate_protect_request(&request, advisories);
                json!({
                    "request": request.to_value(),
                    "verdict": {
                        "action": verdict.action,
                        "reason": verdict.reason,
                        "risk_signals": verdict.risk_signals,
                        "matched": verdict.matched,
                    },
                })
            }
            Err(ProtectParseError::InvalidUrl(message)) => {
                json!({ "error": format!("invalid_url:{message}") })
            }
            Err(error) => json!({ "error": format!("{error:?}") }),
        };
        let mut expected = vector.as_object().unwrap().clone();
        for key in ["name", "command", "advisories"] {
            expected.remove(key);
        }
        if actual != Value::Object(expected.clone()) {
            mismatches.push(format!(
                "{} {:?}:\n  expected {}\n  got      {actual}",
                vector["name"],
                command,
                Value::Object(expected)
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn unrepresentable_registration_json_is_a_typed_error() {
    let command: Vec<String> = ["claude", "mcp", "add-json", "x", r#"{"url": NaN}"#]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(
        parse_protect_command(&command),
        Err(ProtectParseError::UnsupportedPayload)
    );
}

#[test]
fn yarn_add_cwd_names_a_directory_not_a_package() {
    let command: Vec<String> = ["yarn", "add", "--cwd", "/tmp/project", "left-pad"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let request = parse_protect_command(&command).expect("yarn add parses");
    let names: Vec<_> = request
        .targets
        .iter()
        .filter_map(|target| target.package_name.clone())
        .collect();
    assert_eq!(names, ["left-pad"]);
}
