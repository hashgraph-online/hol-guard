//! Replays `metadata_vectors.json`, recorded from the original Python
//! `_safe_artifact_metadata`, through the native operation.

use serde_json::{json, Value};

use crate::inventory_export_redaction::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../testdata/inventory_artifact_metadata/metadata_vectors.json");

fn request(artifacts: Value) -> Value {
    json!({
        "op": "artifact_metadata",
        "home_dir": "/nonexistent-agent/home",
        "workspace_dir": "/nonexistent-agent/work",
        "cwd": "/nonexistent-agent/work",
        "artifacts": artifacts,
        "window": null,
    })
}

fn entry(metadata: Value) -> String {
    json!({
        "metadata": metadata,
        "artifact_type": "mcp_server",
        "config_path": null,
        "command": null,
        "url": null,
        "transport": null,
    })
    .to_string()
}

fn answers(request: &Value) -> Vec<String> {
    let answer = dispatch(request).expect("answer");
    answer["metadata"]
        .as_array()
        .expect("metadata")
        .iter()
        .map(|text| text.as_str().expect("text").to_owned())
        .collect()
}

// The recorded paths are POSIX paths; a Windows host reads them differently.
#[cfg(unix)]
#[test]
fn every_recorded_artifact_exports_the_metadata_python_exported() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    for vector in vectors["vectors"].as_array().expect("vectors") {
        let mut request = request(json!([vector["artifact"]]));
        request["home_dir"] = vectors["home_dir"].clone();
        request["cwd"] = vectors["cwd"].clone();
        request["workspace_dir"] = vector
            .get("workspace_dir")
            .cloned()
            .unwrap_or_else(|| vectors["workspace_dir"].clone());
        assert_eq!(
            answers(&request),
            vec![vector["expected"].as_str().expect("expected").to_owned()],
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn a_batch_answers_each_artifact_in_order() {
    let batch = request(json!([entry(json!({"b": 1})), entry(json!({"a": 2}))]));
    assert_eq!(
        answers(&batch),
        vec![
            r#"{"b":1,"artifactType":"mcp_server"}"#.to_owned(),
            r#"{"a":2,"artifactType":"mcp_server"}"#.to_owned(),
        ]
    );
    assert!(answers(&request(json!([]))).is_empty());
}

#[test]
fn a_mapped_surrogate_is_written_back_as_its_escape() {
    let text = r#"{"metadata":{"name":"\udc80"},"artifact_type":"t","config_path":null,"command":null,"url":null,"transport":null}"#;
    assert_eq!(
        answers(&request(json!([text]))),
        vec![r#"{"name":"\udc80","artifactType":"t"}"#.to_owned()]
    );
}

#[test]
fn a_window_reads_one_answer_in_parts() {
    let metadata = json!({"name": "\u{e9}t\u{e9}", "n": 1});
    let whole = answers(&request(json!([entry(metadata.clone())])));
    let whole_text = &whole[0];
    let total = whole_text.chars().count();
    let mut read = String::new();
    let mut start = 0;
    while start < total {
        let mut windowed = request(json!([entry(metadata.clone())]));
        windowed["window"] = json!({"start": start, "length": 5});
        let answer = dispatch(&windowed).expect("answer");
        assert_eq!(answer["total"], json!(total));
        let part = answer["metadata"][0].as_str().expect("part");
        assert!(part.chars().count() <= 5);
        read.push_str(part);
        start += 5;
    }
    assert_eq!(&read, whole_text);
    let mut past_end = request(json!([entry(metadata)]));
    past_end["window"] = json!({"start": total + 3, "length": 5});
    assert_eq!(
        dispatch(&past_end).expect("answer"),
        json!({"metadata": [""], "total": total})
    );
}

#[test]
fn a_malformed_window_is_refused() {
    let one = json!([entry(json!({}))]);
    let two = json!([entry(json!({})), entry(json!({}))]);
    for (artifacts, window) in [
        (two, json!({"start": 0, "length": 5})),
        (json!([]), json!({"start": 0, "length": 5})),
        (one.clone(), json!({"start": 0, "length": 0})),
        (one.clone(), json!({"start": 0, "length": 262_145})),
        (one.clone(), json!({"start": -1, "length": 5})),
        (one.clone(), json!({"start": 0})),
        (one.clone(), json!({"start": 0, "length": 5, "extra": 1})),
        (one, json!(5)),
    ] {
        let mut bad = request(artifacts);
        bad["window"] = window;
        assert_eq!(dispatch(&bad), Err(ERR_INVALID), "{bad}");
    }
}

#[test]
fn a_malformed_request_is_refused() {
    let mut extra = request(json!([]));
    extra["extra"] = json!(1);
    let mut workspace = request(json!([]));
    workspace["workspace_dir"] = json!(5);
    let mut home = request(json!([]));
    home["home_dir"] = json!(null);
    let mut no_window = request(json!([]));
    no_window.as_object_mut().expect("object").remove("window");
    let wide: Vec<String> = vec![entry(json!({})); 4097];
    for bad in [
        extra,
        workspace,
        home,
        no_window,
        request(json!({})),
        request(json!(wide)),
    ] {
        assert_eq!(dispatch(&bad), Err(ERR_INVALID), "{bad}");
    }
}

#[test]
fn a_malformed_artifact_is_refused() {
    let base = json!({
        "metadata": {},
        "artifact_type": "t",
        "config_path": null,
        "command": null,
        "url": null,
        "transport": null,
    });
    let mut cases: Vec<Value> = vec![json!(5), json!("not json"), json!("[]")];
    for (key, value) in [
        ("metadata", json!([])),
        ("metadata", json!(null)),
        ("artifact_type", json!(null)),
        ("config_path", json!(5)),
        ("command", json!(["node"])),
        ("url", json!(true)),
        ("transport", json!({})),
    ] {
        let mut artifact = base.clone();
        artifact[key] = value;
        cases.push(Value::from(artifact.to_string()));
    }
    let mut missing = base.clone();
    missing.as_object_mut().expect("object").remove("url");
    cases.push(Value::from(missing.to_string()));
    let mut extra = base.clone();
    extra["extra"] = json!(1);
    cases.push(Value::from(extra.to_string()));
    for artifact in cases {
        assert_eq!(
            dispatch(&request(json!([artifact]))),
            Err(ERR_INVALID),
            "{artifact}"
        );
    }
}
