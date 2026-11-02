//! Offline length-framed ingestion. Bounds apply to individual raw records;
//! compiled-program and catalog-admission budgets remain independently enforced.

use super::{
    catalog, cloud_binding, contract::SourceDocument, json, mcp, validation, CompiledSourceCatalog,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

const MAGIC: &[u8; 5] = b"HGCS\x01";
const MAX_RECORDS: usize = 512; // The current complete-program extension contract.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    sources: usize,
    mcp_sources: usize,
    /// Optional sibling cloud action binding records. Absent in legacy streams.
    #[serde(default)]
    cloud_bindings: usize,
    trust: Value,
}

#[derive(Debug)]
pub struct SourceStreamError {
    pub code: &'static str,
    /// Zero-based position in command records, then MCP records, then cloud
    /// binding records.
    pub record: Option<usize>,
}

impl From<&'static str> for SourceStreamError {
    fn from(code: &'static str) -> Self {
        Self { code, record: None }
    }
}

fn frame(reader: &mut impl Read) -> Result<Vec<u8>, &'static str> {
    let mut length = [0; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| "command_source_stream_truncated")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > json::MAX_SOURCE_BYTES {
        return Err("command_source_bytes_invalid");
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| "command_source_stream_truncated")?;
    Ok(bytes)
}

/// Shared build-time ingestion for stdin records and Cargo source files.
/// Strict syntax and source validation precede normalization and retention.
pub fn validate_and_compact_source(
    bytes: &[u8],
    server: bool,
    remaining: &mut usize,
) -> Result<(Vec<u8>, usize), &'static str> {
    let value = json::decode(bytes)?;
    let document = if server {
        mcp::lower(bytes)?.document
    } else {
        serde_json::from_value::<SourceDocument>(value.clone())
            .map_err(|_| "command_source_contract_invalid")?
    };
    validation::validate(&document, server)?;
    let rules = document.extension.rules.len();
    Ok((json::compact_record(&value, remaining)?, rules))
}

/// Compile a complete release catalog from bounded records. No file paths,
/// includes, activation, or network authority is accepted by this protocol.
pub fn compile_source_stream(
    mut reader: impl Read,
) -> Result<CompiledSourceCatalog, SourceStreamError> {
    let mut magic = [0; 5];
    reader
        .read_exact(&mut magic)
        .map_err(|_| "command_source_stream_truncated")?;
    if &magic != MAGIC {
        return Err("command_source_stream_version_unsupported".into());
    }
    let header: Header = serde_json::from_value(json::decode(&frame(&mut reader)?)?)
        .map_err(|_| "command_source_stream_header_invalid")?;
    if header.schema != "guard.command-extension-source-stream.v1"
        || header
            .sources
            .checked_add(header.mcp_sources)
            .is_none_or(|count| count == 0 || count > MAX_RECORDS)
        || header.cloud_bindings > MAX_RECORDS
    {
        return Err("command_source_stream_header_invalid".into());
    }
    let trust = serde_json::to_vec(&header.trust).map_err(|_| "command_source_encoding_failed")?;
    catalog::validate_trust(&trust)?;
    let mut commands = Vec::new();
    let mut servers = Vec::new();
    let mut rules = 0usize;
    let mut remaining = json::MAX_SOURCE_BYTES;
    for record in 0..header.sources + header.mcp_sources {
        let mut ingest = || -> Result<Vec<u8>, &'static str> {
            let bytes = frame(&mut reader)?;
            // Duplicate keys, depth, values and typed unknown fields are checked
            // before compacting. Whitespace cannot consume another source's budget.
            let (compact, count) =
                validate_and_compact_source(&bytes, record >= header.sources, &mut remaining)?;
            rules = rules
                .checked_add(count)
                .ok_or("command_source_program_rule_budget_exceeded")?;
            if rules > super::super::MAX_RULES {
                return Err("command_source_program_rule_budget_exceeded");
            }
            Ok(compact)
        };
        let bytes = ingest().map_err(|code| SourceStreamError {
            code,
            record: Some(record),
        })?;
        if record < header.sources {
            commands.push(bytes);
        } else {
            servers.push(bytes);
        }
    }
    let first_binding = header.sources + header.mcp_sources;
    let mut bindings = Vec::with_capacity(header.cloud_bindings);
    for offset in 0..header.cloud_bindings {
        let record = first_binding + offset;
        // Bindings are retained until every source has arrived, so they draw on
        // the same compact-byte budget as the sources they extend.
        let parsed = frame(&mut reader)
            .and_then(|bytes| {
                let compact = json::compact_record(
                    &json::decode(&bytes).map_err(|_| "cloud_binding_json_invalid")?,
                    &mut remaining,
                )?;
                cloud_binding::parse_binding_contribution(&compact)
            })
            .map_err(|code| SourceStreamError {
                code,
                record: Some(record),
            })?;
        bindings.push((record, parsed));
    }
    let mut trailing = [0];
    if reader
        .read(&mut trailing)
        .map_err(|_| "command_source_stream_read_failed")?
        != 0
    {
        return Err("command_source_stream_trailing_data".into());
    }
    resolve_bindings(&bindings, &commands, &servers)?;
    let commands: Vec<_> = commands.iter().map(Vec::as_slice).collect();
    let servers: Vec<_> = servers.iter().map(Vec::as_slice).collect();
    Ok(catalog::compile_catalog_with_mcp(
        &commands, &servers, &trust,
    )?)
}

/// Each binding contribution extends exactly one extension in the same
/// stream, at most once, and an action ID names one hosted action stream-wide.
fn resolve_bindings(
    bindings: &[(usize, cloud_binding::CloudBindingContribution)],
    commands: &[Vec<u8>],
    servers: &[Vec<u8>],
) -> Result<(), SourceStreamError> {
    if bindings.is_empty() {
        return Ok(());
    }
    let mut sources = BTreeMap::new();
    for (bytes, server) in commands
        .iter()
        .map(|bytes| (bytes, false))
        .chain(servers.iter().map(|bytes| (bytes, true)))
    {
        let value = json::decode(bytes)?;
        let id = if server {
            &value["id"]
        } else {
            &value["extension"]["extension_id"]
        };
        if let Some(id) = id.as_str() {
            sources.insert(id.to_owned(), (bytes.as_slice(), server));
        }
    }
    let mut extended = BTreeSet::new();
    let mut actions = BTreeSet::new();
    for (record, contribution) in bindings {
        let fail = |code| SourceStreamError {
            code,
            record: Some(*record),
        };
        let (bytes, server) = sources
            .get(&contribution.extension_id)
            .ok_or_else(|| fail("cloud_binding_extension_unknown"))?;
        if !extended.insert(contribution.extension_id.as_str()) {
            return Err(fail("cloud_binding_duplicate_extension"));
        }
        if contribution
            .bindings
            .iter()
            .any(|binding| !actions.insert(binding.action_id.as_str()))
        {
            return Err(fail("cloud_binding_duplicate_action"));
        }
        let target = cloud_binding::BindingTarget::from_source(bytes, *server).map_err(fail)?;
        cloud_binding::resolve(contribution, &target).map_err(fail)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
        let bound = compile(&[json!({
            "schemaVersion": "guard.cloud-action-binding-contribution.v1",
            "extensionId": "mcp.instapods",
            "bindings": [{
                "actionId": "instapods.pod.delete",
                "tool": "delete_pod",
                "effect": "destructive",
                "requiredCapabilities": ["egress-pinned", "bounded-output"],
                "cloudSupport": "cloud-executable"
            }]
        })]);
        // Bindings never change the compiled local catalog in this version.
        assert_eq!(bound.source_digest, legacy.source_digest);
        assert_eq!(bound.program, legacy.program);
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
}
