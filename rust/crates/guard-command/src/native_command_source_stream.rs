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
    /// The binding inside a cloud binding record, when one is to blame.
    pub binding: Option<usize>,
}

impl From<&'static str> for SourceStreamError {
    fn from(code: &'static str) -> Self {
        Self {
            code,
            record: None,
            binding: None,
        }
    }
}

impl SourceStreamError {
    fn at(record: usize, code: &'static str) -> Self {
        Self {
            code,
            record: Some(record),
            binding: None,
        }
    }

    pub(super) fn rejected(record: usize, rejection: cloud_binding::BindingRejection) -> Self {
        Self {
            code: rejection.code,
            record: Some(record),
            binding: rejection.binding,
        }
    }

    /// JSON pointer to the record at fault, under the array named by `records`
    /// (`/records` for a stream). Empty when no record is to blame.
    pub fn pointer(&self, records: &str) -> String {
        match (self.record, self.binding) {
            (Some(record), Some(binding)) => format!("{records}/{record}/bindings/{binding}"),
            (Some(record), None) => format!("{records}/{record}"),
            (None, _) => String::new(),
        }
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
        let bytes = ingest().map_err(|code| SourceStreamError::at(record, code))?;
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
                json::compact_record(
                    &json::decode(&bytes).map_err(|_| "cloud_binding_json_invalid")?,
                    &mut remaining,
                )
            })
            .map_err(cloud_binding::BindingRejection::from)
            .and_then(|compact| cloud_binding::parse_contribution(&compact))
            .map_err(|rejection| SourceStreamError::rejected(record, rejection))?;
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
    let resolved = resolve_bindings(&bindings, &commands, &servers)?;
    let commands: Vec<_> = commands.iter().map(Vec::as_slice).collect();
    let servers: Vec<_> = servers.iter().map(Vec::as_slice).collect();
    let mut output = catalog::compile_catalog_with_mcp(&commands, &servers, &trust)?;
    if !resolved.is_empty() {
        let program_digest = output.program["program_digest"]
            .as_str()
            .ok_or("command_source_encoding_failed")?;
        output.cloud_bindings = Some(cloud_binding::compile_artifact(&resolved, program_digest)?);
    }
    Ok(output)
}

/// Each binding contribution extends exactly one extension in the same
/// stream, at most once, and an action ID names one hosted action stream-wide.
pub(super) fn resolve_bindings<'a>(
    bindings: &'a [(usize, cloud_binding::CloudBindingContribution)],
    commands: &[Vec<u8>],
    servers: &[Vec<u8>],
) -> Result<
    Vec<(
        &'a cloud_binding::CloudBindingContribution,
        cloud_binding::BindingTarget,
    )>,
    SourceStreamError,
> {
    let mut resolved = Vec::with_capacity(bindings.len());
    if bindings.is_empty() {
        return Ok(resolved);
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
        let fail = |code| SourceStreamError::at(*record, code);
        let (bytes, server) = sources
            .get(&contribution.extension_id)
            .ok_or_else(|| fail("cloud_binding_extension_unknown"))?;
        if !extended.insert(contribution.extension_id.as_str()) {
            return Err(fail("cloud_binding_duplicate_extension"));
        }
        // Name the binding that repeats an action an earlier contribution bound.
        if let Some(binding) = contribution
            .bindings
            .iter()
            .position(|binding| !actions.insert(binding.action_id.as_str()))
        {
            return Err(SourceStreamError::rejected(
                *record,
                cloud_binding::BindingRejection {
                    code: "cloud_binding_duplicate_action",
                    binding: Some(binding),
                },
            ));
        }
        let target = cloud_binding::BindingTarget::from_source(bytes, *server).map_err(fail)?;
        cloud_binding::resolve(contribution, &target)
            .map_err(|rejection| SourceStreamError::rejected(*record, rejection))?;
        resolved.push((contribution, target));
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "native_command_source_stream_tests.rs"]
mod tests;
