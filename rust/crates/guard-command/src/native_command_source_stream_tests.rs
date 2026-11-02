use super::*;
use serde_json::json;

fn append(stream: &mut Vec<u8>, bytes: &[u8]) {
    stream.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    stream.extend_from_slice(bytes);
}

fn input(record: &[u8]) -> Vec<u8> {
    let mut stream = MAGIC.to_vec();
    append(
        &mut stream,
        &serde_json::to_vec(&json!({
            "schema":"guard.command-extension-source-stream.v1",
        "sources":1,"mcp_sources":0,"trust":{
            "schemaVersion":"guard.extension-trust-class-map.v1",
            "publishers":{"hol":{"id":"hol","displayName":"HOL"},
                          "hol-curated":{"id":"hol-curated","displayName":"HOL curated library"}},
            "classes":{"first-party":[],"trusted-library":[],"external":[]}
        }
        }))
        .unwrap(),
    );
    append(&mut stream, record);
    stream
}

#[test]
fn strict_record_errors_keep_the_source_position() {
    let source = include_bytes!("../tests/fixtures/command-source-example.v1.json");
    let mut unknown: Value = serde_json::from_slice(source).unwrap();
    unknown["extension"]["unknown"] = json!(true);
    let nested = format!("{{\"extra\":{}0{}}}", "[".repeat(97), "]".repeat(97));
    for (record, code) in [
        (
            br#"{"extension":{},"extension":{}}"#.to_vec(),
            "command_source_json_invalid",
        ),
        (br#"{"value":NaN}"#.to_vec(), "command_source_json_invalid"),
        (nested.into_bytes(), "command_source_json_invalid"),
        (
            serde_json::to_vec(&unknown).unwrap(),
            "command_source_contract_invalid",
        ),
    ] {
        let error = compile_source_stream(input(&record).as_slice()).unwrap_err();
        assert_eq!(error.code, code);
        assert_eq!(error.record, Some(0));
    }
}

#[test]
fn rejects_bad_frames_before_allocating_payloads() {
    let mut oversized = input(b"{}");
    oversized.truncate(oversized.len() - 6);
    oversized.extend_from_slice(&((json::MAX_SOURCE_BYTES + 1) as u32).to_be_bytes());
    assert_eq!(
        compile_source_stream(oversized.as_slice())
            .unwrap_err()
            .code,
        "command_source_bytes_invalid"
    );
    let mut truncated = input(b"{}");
    truncated.pop();
    assert_eq!(
        compile_source_stream(truncated.as_slice())
            .unwrap_err()
            .code,
        "command_source_stream_truncated"
    );
    for header in [
        json!({"schema":"guard.command-extension-source-stream.v1","sources":513,"mcp_sources":0,"trust":{}}),
        json!({"schema":"guard.command-extension-source-stream.v1","sources":0,"mcp_sources":0,"trust":{}}),
        json!({"schema":"guard.command-extension-source-stream.v1","sources":1,"mcp_sources":0,"trust":{},"extra":true}),
    ] {
        let mut stream = MAGIC.to_vec();
        append(&mut stream, &serde_json::to_vec(&header).unwrap());
        assert_eq!(
            compile_source_stream(stream.as_slice()).unwrap_err().code,
            "command_source_stream_header_invalid"
        );
    }
}

#[test]
fn rejects_excess_retained_work_before_collecting_the_complete_catalog() {
    let mut source: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/command-source-example.v1.json"
    ))
    .unwrap();
    source["extension"]["project_markers"] = json!((0..1280)
        .map(|index| format!("marker-{index}-{}", "x".repeat(3990)))
        .collect::<Vec<_>>());
    let record = serde_json::to_vec(&source).unwrap();
    assert!(record.len() < json::MAX_SOURCE_BYTES);
    let second = String::from_utf8(record.clone())
        .unwrap()
        .replace("command.example-cli", "command.example-two")
        .into_bytes();
    let first = input(&record);
    let length = u32::from_be_bytes(first[5..9].try_into().unwrap()) as usize;
    let mut header: Value = serde_json::from_slice(&first[9..9 + length]).unwrap();
    header["sources"] = json!(2);
    let mut stream = MAGIC.to_vec();
    append(&mut stream, &serde_json::to_vec(&header).unwrap());
    append(&mut stream, &record);
    append(&mut stream, &second);
    let error = compile_source_stream(stream.as_slice()).unwrap_err();
    assert_eq!(error.code, "command_source_catalog_work_budget_exceeded");
    assert_eq!(error.record, Some(1));
}

fn binding_stream(bindings: &[Value]) -> Vec<u8> {
    let source = include_bytes!("../tests/fixtures/command-source-example.v1.json");
    let base = input(source);
    let length = u32::from_be_bytes(base[5..9].try_into().unwrap()) as usize;
    let mut header: Value = serde_json::from_slice(&base[9..9 + length]).unwrap();
    header["cloud_bindings"] = json!(bindings.len());
    let mut stream = MAGIC.to_vec();
    append(&mut stream, &serde_json::to_vec(&header).unwrap());
    append(&mut stream, source);
    for binding in bindings {
        append(&mut stream, &serde_json::to_vec(binding).unwrap());
    }
    stream
}

fn binding(extension: &str, action: &str) -> Value {
    json!({
        "schemaVersion": "guard.cloud-action-binding-contribution.v1",
        "extensionId": extension,
        "bindings": [{
            "actionId": action,
            "permissionId": "command.example-cli.permission.destroy",
            "effect": "destructive",
            "requiredCapabilities": [],
            "cloudSupport": "portable-policy"
        }]
    })
}

/// The complete authored inventory, as the release build streams it.
fn release_stream(bindings: &[Value]) -> Vec<u8> {
    use crate::native_command_program::authored_test_support::{sources, trust_map};
    let sources = sources();
    let mut trust = trust_map();
    let (mut commands, mut servers) = (Vec::new(), Vec::new());
    for (metadata, bytes) in &sources {
        for (class, ids) in metadata["trust"]["classes"].as_object().unwrap() {
            trust["classes"][class]
                .as_array_mut()
                .unwrap()
                .extend(ids.as_array().unwrap().iter().cloned());
        }
        if metadata["kind"] == "command" {
            commands.push(bytes);
        } else {
            servers.push(bytes);
        }
    }
    let mut stream = MAGIC.to_vec();
    append(
        &mut stream,
        &serde_json::to_vec(&json!({
            "schema": "guard.command-extension-source-stream.v1",
            "sources": commands.len(),
            "mcp_sources": servers.len(),
            "cloud_bindings": bindings.len(),
            "trust": trust,
        }))
        .unwrap(),
    );
    for bytes in commands.into_iter().chain(servers) {
        append(&mut stream, bytes);
    }
    for binding in bindings {
        append(&mut stream, &serde_json::to_vec(binding).unwrap());
    }
    stream
}

#[test]
fn cloud_binding_records_are_optional_and_resolve_against_the_stream() {
    let compile = |bindings: &[Value]| {
        compile_source_stream(release_stream(bindings).as_slice())
            .unwrap_or_else(|error| panic!("release stream must compile: {}", error.code))
    };
    let legacy = compile(&[]);
    let binding = json!({
        "schemaVersion": "guard.cloud-action-binding-contribution.v1",
        "extensionId": "mcp.instapods",
        "bindings": [{
            "actionId": "instapods.pod.delete",
            "tool": "delete_pod",
            "effect": "destructive",
            "requiredCapabilities": ["egress-pinned", "bounded-output"],
            "cloudSupport": "cloud-executable"
        }]
    });
    let bound = compile(std::slice::from_ref(&binding));
    // Bindings never change the compiled local catalog in this version.
    assert_eq!(bound.source_digest, legacy.source_digest);
    assert_eq!(bound.program, legacy.program);

    // Without bindings the build output is exactly what it was before.
    assert!(legacy.cloud_bindings.is_none());
    assert!(serde_json::to_value(&legacy)
        .unwrap()
        .get("cloud_bindings")
        .is_none());

    let artifact = bound.cloud_bindings.as_ref().unwrap();
    assert_eq!(artifact["program_digest"], bound.program["program_digest"]);
    assert_eq!(artifact["actions"].as_array().unwrap().len(), 1);
    assert_eq!(
        serde_json::to_value(&bound).unwrap()["cloud_bindings"],
        *artifact
    );
    // The same input compiles to the same artifact.
    assert_eq!(
        compile(std::slice::from_ref(&binding))
            .cloud_bindings
            .as_ref(),
        Some(artifact)
    );
}

#[test]
fn binding_records_draw_on_the_shared_retention_budget() {
    // Each record stays under the per-record cap, but together they exceed
    // what the stream may retain once the sources are counted.
    let segment = "x".repeat(100);
    let tool = "t".repeat(256);
    let large: Vec<Value> = (0..100)
        .map(|index| {
            json!({
                "schemaVersion": "guard.cloud-action-binding-contribution.v1",
                "extensionId": format!("mcp.filler-{index}"),
                "bindings": (0..256).map(|action| json!({
                    "actionId": format!("filler.a{action}.{segment}"),
                    "tool": tool,
                    "effect": "read",
                    "requiredCapabilities": [],
                    "cloudSupport": "portable-policy"
                })).collect::<Vec<_>>()
            })
        })
        .collect();
    let error = compile_source_stream(release_stream(&large).as_slice()).unwrap_err();
    assert_eq!(error.code, "command_source_catalog_work_budget_exceeded");
    assert!(error.record.is_some());
}

#[test]
fn cloud_binding_record_errors_keep_their_position() {
    for (bindings, code) in [
        (
            vec![binding("command.missing", "example.resource.destroy")],
            "cloud_binding_extension_unknown",
        ),
        (
            vec![
                binding("command.example-cli", "example.resource.destroy"),
                binding("command.example-cli", "example.resource.remove"),
            ],
            "cloud_binding_duplicate_extension",
        ),
        (
            vec![
                json!({"schemaVersion":"guard.cloud-action-binding-contribution.v1",
                "extensionId":"command.example-cli","bindings":[],"allow":true}),
            ],
            "cloud_binding_contract_invalid",
        ),
    ] {
        let error = compile_source_stream(binding_stream(&bindings).as_slice()).unwrap_err();
        assert_eq!(error.code, code);
        assert_eq!(error.record, Some(bindings.len()));
    }
    let mut too_many = binding_stream(&[]);
    let length = u32::from_be_bytes(too_many[5..9].try_into().unwrap()) as usize;
    let mut header: Value = serde_json::from_slice(&too_many[9..9 + length]).unwrap();
    header["cloud_bindings"] = json!(MAX_RECORDS + 1);
    too_many = MAGIC.to_vec();
    append(&mut too_many, &serde_json::to_vec(&header).unwrap());
    assert_eq!(
        compile_source_stream(too_many.as_slice()).unwrap_err().code,
        "command_source_stream_header_invalid"
    );
}
