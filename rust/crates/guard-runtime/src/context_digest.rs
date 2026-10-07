//! Native approval-context digest authority.
//!
//! Saved approvals are bound to an opaque context token built from five
//! component digests, and to domain-separated configured environment/header
//! digests. Computing those digests is authoritative work: this module owns
//! the canonical serialization and hashing so Python callers transport raw
//! components and project the typed result, never a Python-built hash, into
//! approval evidence.

use std::path::Path;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::context_digest_json::{
    write_canonical_json, write_canonical_json_with_limit, write_json_string,
};
use guard_contracts::{
    ContextDigestComponentsV1, ContextDigestKindV1, ContextDigestRequestV1, ContextDigestResultV1,
    PackageContextComponentV1, PackageContextEvidenceV1, APPROVAL_CONTEXT_TOKEN_PREFIX,
    CONTEXT_COMPONENT_MAX_BYTES, CONTEXT_DIGEST_REQUEST_SCHEMA, CONTEXT_DIGEST_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

const TOKEN_VERSION: u64 = 1;
const TOKEN_DOMAIN: &str = "hol.guard.approval-context";
const CONFIGURED_ENV_HASH_DOMAIN: &[u8] = b"hol.guard.configured-environment:v1\0";
const CONFIGURED_HEADER_HASH_DOMAIN: &[u8] = b"hol.guard.configured-headers:v1\0";
const TOKEN_HASH_FIELDS: [&str; 5] = ["identity", "content", "capabilities", "policy", "sandbox"];

pub(super) const ERR_COMPONENT: &str = "native_context_component_invalid";
const ERR_VALUES: &str = "native_context_values_invalid";
const ERR_ARGUMENTS: &str = "native_mcp_arguments_invalid";

fn component_hash(component: &str, value: &Value) -> Result<String, &'static str> {
    component_hash_with(component, |out| write_canonical_json(value, out))
}

fn component_hash_with(
    component: &str,
    write_value: impl FnOnce(&mut Vec<u8>) -> Result<(), &'static str>,
) -> Result<String, &'static str> {
    // {"component": ..., "domain": ..., "value": ..., "version": 1}
    // Wrapper keys are already in sorted order for the canonical writer.
    let mut material = Vec::with_capacity(128);
    material.push(b'{');
    write_json_string("component", &mut material);
    material.push(b':');
    write_json_string(component, &mut material);
    material.push(b',');
    write_json_string("domain", &mut material);
    material.push(b':');
    write_json_string(TOKEN_DOMAIN, &mut material);
    material.push(b',');
    write_json_string("value", &mut material);
    material.push(b':');
    write_value(&mut material)?;
    if material.len() > CONTEXT_COMPONENT_MAX_BYTES {
        return Err(ERR_COMPONENT);
    }
    material.push(b',');
    write_json_string("version", &mut material);
    material.push(b':');
    material.push(b'1');
    material.push(b'}');
    Ok(digest_bytes(&material))
}

fn base64_url_no_pad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let block = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(block >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(block >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(block >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[block as usize & 0x3f] as char);
        }
    }
    out
}

fn base64_url_decode(encoded: &str) -> Option<Vec<u8>> {
    fn nibble(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let v0 = nibble(chunk[0])?;
        let v1 = nibble(chunk[1])?;
        out.push(((v0 << 2) | (v1 >> 4)) as u8);
        if chunk.len() > 2 {
            let v2 = nibble(chunk[2])?;
            out.push((((v1 & 0x0f) << 4) | (v2 >> 2)) as u8);
            if chunk.len() > 3 {
                let v3 = nibble(chunk[3])?;
                out.push((((v2 & 0x03) << 6) | v3) as u8);
            }
        }
    }
    Some(out)
}

/// Parsed non-secret approval-context component digests.
pub(crate) struct ParsedContextToken {
    pub(crate) identity: String,
    pub(crate) content: String,
    pub(crate) capabilities: String,
    pub(crate) policy: String,
    pub(crate) sandbox: String,
}

fn is_sha256_hex(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    if text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Some(text.to_owned())
    } else {
        None
    }
}

pub(crate) fn parse_context_token(token: &Value) -> Option<ParsedContextToken> {
    let text = token.as_str()?;
    let encoded = text.strip_prefix(APPROVAL_CONTEXT_TOKEN_PREFIX)?;
    if text.len() > guard_contracts::APPROVAL_CONTEXT_TOKEN_MAX_BYTES
        || encoded.is_empty()
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let raw = base64_url_decode(encoded)?;
    let payload_text = std::str::from_utf8(&raw).ok()?;
    let payload: Value = serde_json::from_str(payload_text).ok()?;
    let object = payload.as_object()?;
    if object.len() != 6 {
        return None;
    }
    // Python compares `payload.get("version") != 1` numerically: JSON 1.0
    // passes (`1.0 == 1`) and `true` also passes (`True == 1`).
    match object.get("version") {
        Some(Value::Bool(true)) => {}
        Some(other) if other.as_f64() == Some(TOKEN_VERSION as f64) => {}
        _ => return None,
    }
    let mut parsed: [Option<String>; 5] = std::array::from_fn(|_| None);
    for (index, field) in TOKEN_HASH_FIELDS.iter().enumerate() {
        parsed[index] = Some(is_sha256_hex(object.get(*field)?)?);
    }
    let [identity, content, capabilities, policy, sandbox] = parsed;
    Some(ParsedContextToken {
        identity: identity?,
        content: content?,
        capabilities: capabilities?,
        policy: policy?,
        sandbox: sandbox?,
    })
}

pub(crate) fn build_context_token(
    components: &ContextDigestComponentsV1,
) -> Result<String, &'static str> {
    build_context_token_fields(
        &components.identity,
        &components.content,
        &components.capabilities,
        &components.sandbox,
        &components.extension_control_digest,
        |out| write_canonical_json(&components.policy, out),
    )
}

fn build_context_token_fields(
    identity: &Value,
    content: &Value,
    capabilities: &Value,
    sandbox: &Value,
    extension_control_digest: &str,
    write_policy: impl FnOnce(&mut Vec<u8>) -> Result<(), &'static str>,
) -> Result<String, &'static str> {
    let digests = [
        component_hash("identity", identity)?,
        component_hash("content", content)?,
        component_hash("capabilities", capabilities)?,
        component_hash_with("policy", |out| {
            out.extend_from_slice(b"{\"extension_control_digest\":");
            write_json_string(extension_control_digest, out);
            out.extend_from_slice(b",\"policy\":");
            write_policy(out)?;
            out.push(b'}');
            Ok(())
        })?,
        component_hash("sandbox", sandbox)?,
    ];
    // Payload keys emitted in sorted order: capabilities, content, identity,
    // policy, sandbox, version.
    let mut payload = Vec::with_capacity(512);
    payload.push(b'{');
    for (index, (key, digest)) in [
        ("capabilities", &digests[2]),
        ("content", &digests[1]),
        ("identity", &digests[0]),
        ("policy", &digests[3]),
        ("sandbox", &digests[4]),
    ]
    .iter()
    .enumerate()
    {
        if index > 0 {
            payload.push(b',');
        }
        write_json_string(key, &mut payload);
        payload.push(b':');
        write_json_string(digest, &mut payload);
    }
    payload.extend_from_slice(b",\"version\":1}");
    Ok(format!(
        "{APPROVAL_CONTEXT_TOKEN_PREFIX}{}",
        base64_url_no_pad(&payload)
    ))
}

/// First-difference validation over two opaque tokens; malformed input fails
/// closed as changed content, matching the legacy contract exactly.
pub(crate) fn validate_context_tokens(saved: &Value, current: &Value) -> Option<String> {
    let saved = parse_context_token(saved);
    let current = parse_context_token(current);
    let (Some(saved), Some(current)) = (saved, current) else {
        return Some("approval_reuse_content_changed".to_owned());
    };
    let comparisons = [
        (
            saved.identity,
            current.identity,
            "approval_reuse_identity_changed",
        ),
        (
            saved.content,
            current.content,
            "approval_reuse_content_changed",
        ),
        (
            saved.capabilities,
            current.capabilities,
            "approval_reuse_capability_changed",
        ),
        (
            saved.policy,
            current.policy,
            "approval_reuse_policy_changed",
        ),
        (
            saved.sandbox,
            current.sandbox,
            "approval_reuse_sandbox_changed",
        ),
    ];
    for (left, right, reason) in comparisons {
        if !crate::constant_time_eq(left.as_bytes(), right.as_bytes()) {
            return Some(reason.to_owned());
        }
    }
    None
}

/// CPython `str.strip()` whitespace set: the ASCII controls 0x09-0x0d and
/// 0x1c-0x1f plus every Unicode code point whose `isspace` is true.
fn is_python_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{09}'..='\u{0d}'
            | ' '
            | '\u{1c}'..='\u{1f}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(|ch: char| is_python_space(ch))
}

fn configured_values_hash(
    values: Option<&Value>,
    configured_keys: Option<&[String]>,
    domain: &[u8],
) -> Result<String, &'static str> {
    // Python evaluates `(values or {})`: every JSON-falsy input normalizes to
    // an empty mapping, while truthy non-mappings fail on `.items()`.
    //
    // Mappings arrive as ordered `["key", value]` pairs: distinct raw keys can
    // collide after whitespace stripping, and the legacy dict comprehension
    // resolves the collision by the last pair in caller iteration order. A
    // plain JSON object cannot transport that order, so objects are rejected
    // rather than silently reordering a caller's inputs.
    let mut normalized: Map<String, Value> = Map::new();
    match values {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => {}
        Some(Value::String(text)) if text.is_empty() => {}
        Some(Value::Array(items)) => {
            for item in items {
                let pair = item.as_array().ok_or(ERR_VALUES)?;
                let (Some(raw_key), Some(entry)) = (pair.first(), pair.get(1)) else {
                    return Err(ERR_VALUES);
                };
                let raw_key = raw_key.as_str().ok_or(ERR_VALUES)?;
                if pair.len() != 2 {
                    return Err(ERR_VALUES);
                }
                let stripped = python_strip(raw_key);
                if stripped.is_empty() {
                    continue;
                }
                normalized.insert(stripped.to_owned(), entry.clone());
            }
        }
        Some(_) => return Err(ERR_VALUES),
    }
    let mut keys: Vec<String> = match configured_keys {
        None => normalized.keys().cloned().collect(),
        Some(configured) => configured
            .iter()
            .map(|key| python_strip(key).to_owned())
            .filter(|key| !key.is_empty())
            .collect(),
    };
    keys.sort();
    keys.dedup();

    let mut hasher = Sha256::new();
    hasher.update(domain);
    for key in keys {
        let key_bytes = key.as_bytes();
        hasher.update((key_bytes.len() as u64).to_be_bytes());
        hasher.update(key_bytes);
        match normalized.get(&key) {
            None => hasher.update([0x00]),
            Some(Value::String(text)) => {
                hasher.update([0x01]);
                let value_bytes = text.as_bytes();
                hasher.update((value_bytes.len() as u64).to_be_bytes());
                hasher.update(value_bytes);
            }
            // Python raises AttributeError on non-str values; the native op
            // surfaces the same boundary as a typed failure.
            Some(_) => return Err(ERR_VALUES),
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

fn evaluate_request(
    request: &ContextDigestRequestV1,
    result: &mut ContextDigestResultV1,
) -> Result<(), &'static str> {
    match &request.kind {
        ContextDigestKindV1::BuildApprovalContextToken { components } => {
            result.token = Some(build_context_token(components)?);
        }
        ContextDigestKindV1::ValidateApprovalContextTokens {
            saved_token,
            current_token,
        } => {
            result.validation_reason = validate_context_tokens(saved_token, current_token);
        }
        ContextDigestKindV1::ValidateApprovalContext {
            saved_token,
            components,
        } => {
            let current = build_context_token(components)?;
            result.validation_reason =
                validate_context_tokens(saved_token, &Value::String(current));
        }
        ContextDigestKindV1::ConfiguredEnvironmentHash {
            values,
            configured_keys,
        } => {
            result.digest = Some(configured_values_hash(
                values.as_ref(),
                configured_keys.as_deref(),
                CONFIGURED_ENV_HASH_DOMAIN,
            )?);
        }
        ContextDigestKindV1::ConfiguredHeadersHash {
            values,
            configured_keys,
        } => {
            result.digest = Some(configured_values_hash(
                values.as_ref(),
                configured_keys.as_deref(),
                CONFIGURED_HEADER_HASH_DOMAIN,
            )?);
        }
        ContextDigestKindV1::LaunchArgvDigest { argv } => {
            // _launch_argv_digest: sha256 over ensure_ascii compact JSON of
            // the argv list — no sort_keys (arrays keep their order).
            let mut material = Vec::with_capacity(128);
            let argv_values: Vec<Value> =
                argv.iter().map(|arg| Value::String(arg.clone())).collect();
            write_canonical_json(&Value::Array(argv_values), &mut material)?;
            result.digest = Some(digest_bytes(&material));
        }
        ContextDigestKindV1::CanonicalSha256 { material, prefix } => {
            // canonical_sha256: CPython-exact canonical JSON -> sha256. The
            // material arrives as a JSON value; write_canonical_json enforces
            // sort_keys / (",",":") / ensure_ascii / allow_nan=false, so the
            // digest is byte-identical to json.dumps(...).encode() + sha256.
            let mut material_bytes = Vec::with_capacity(256);
            write_canonical_json(material, &mut material_bytes)?;
            let hex = digest_bytes(&material_bytes);
            result.digest = Some(match prefix {
                Some(p) => format!("{p}{hex}"),
                None => hex,
            });
        }
        ContextDigestKindV1::OpaqueMaterialDigest { material } => {
            // opaque_material_digest: sha256 over raw UTF-8 string bytes —
            // NO JSON serialization (module specifiers, source text, h:s:n).
            result.digest = Some(digest_bytes(material.as_bytes()));
        }
        ContextDigestKindV1::McpArgumentsProjection {
            tool_name,
            arguments,
        } => {
            // _launch_target: safe arguments + display serialization +
            // sha256 over the RAW arguments (default=str is irrelevant at
            // the JSON transport boundary — every surviving value is a JSON
            // scalar/container already).
            let arguments_value = arguments.clone().unwrap_or(Value::Null);
            let safe = match arguments {
                Some(inner) => guard_command::mcp_arguments::mcp_safe_arguments(inner)
                    .map_err(|_| ERR_ARGUMENTS)?,
                None => Value::Null,
            };
            let mut digest_material = Vec::with_capacity(256);
            write_canonical_json(&arguments_value, &mut digest_material)?;
            result.digest = Some(digest_bytes(&digest_material));
            let serialized = if arguments.is_some() {
                let mut out = Vec::with_capacity(256);
                write_canonical_json(&safe, &mut out)?;
                String::from_utf8(out).map_err(|_| "canonical_json_unencodable")?
            } else {
                String::new()
            };
            result.mcp_serialized_arguments = Some(serialized.clone());
            result.mcp_safe_arguments = Some(safe);
            let label = format!(
                "{tool_name} {serialized} [arguments-sha256:{}]",
                result.digest.as_deref().unwrap_or("")
            );
            result.mcp_launch_target = Some(label.trim().to_owned());
        }
        ContextDigestKindV1::McpRedactJson { material } => {
            result.mcp_redacted_value = Some(
                guard_command::mcp_arguments::redact_json(material).map_err(|_| ERR_ARGUMENTS)?,
            );
        }
        ContextDigestKindV1::PackageEnvironmentPolicy {
            manager,
            environment,
            referenced_names,
        } => {
            result.environment_values = Some(
                guard_command::package_context_environment::environment_policy_values(
                    manager,
                    environment,
                    referenced_names,
                ),
            );
        }
        ContextDigestKindV1::McpLaunchEnvironment {
            inherited,
            configured,
        } => {
            result.mcp_launch_environment = Some(
                guard_command::mcp_launch_environment::build_launch_environment(
                    inherited, configured,
                ),
            );
        }
        ContextDigestKindV1::PackageExecutionContextFromEvidence { material } => {
            result.package_context =
                guard_command::package_execution_context::package_execution_context_from_evidence(
                    material,
                )
                .map(package_context_evidence);
        }
        ContextDigestKindV1::PackageExecutionContextFromScannerEvidence { material } => {
            result.package_context =
                guard_command::package_execution_context::package_execution_context_from_scanner_evidence(
                    material,
                )
                .map(package_context_evidence);
        }
        ContextDigestKindV1::McpServerIdentity { request } => {
            let environment = request.environment.as_ref().map(|pairs| {
                let mut values = Map::new();
                for (key, value) in pairs {
                    let key = python_strip(key);
                    if !key.is_empty() {
                        values.insert(key.to_owned(), Value::String(value.clone()));
                    }
                }
                values
            });
            let identity = guard_command::mcp_decision::build_mcp_server_identity(
                &request.config_path,
                &request.command,
                &request.args,
                &request.transport,
                environment.as_ref(),
                &request.env_keys,
            );
            result.mcp_server_identity = Some(guard_contracts::McpServerIdentityV1 {
                config_path: identity.config_path,
                command: identity.command,
                args_hash: identity.args_hash,
                package_name: identity.package_name,
                package_version: identity.package_version,
                package_source: identity.package_source,
                transport: identity.transport,
                env_keys: identity.env_keys,
                env_values_hash: identity.env_values_hash,
                identity_hash: identity.identity_hash,
            });
        }
        ContextDigestKindV1::McpToolIdentity { request } => {
            let identity = guard_command::mcp_decision::build_mcp_tool_identity(
                &request.server_hash,
                &request.tool_name,
                request.schema.as_ref(),
                request.description.as_deref(),
            );
            result.mcp_tool_identity = Some(guard_contracts::McpToolIdentityV1 {
                server_hash: identity.server_hash,
                tool_name: identity.tool_name,
                schema_hash: identity.schema_hash,
                description_hash: identity.description_hash,
                identity_hash: identity.identity_hash,
            });
        }
        ContextDigestKindV1::McpServerDescriptor { request } => {
            result.mcp_descriptor = Some(
                guard_command::mcp_decision::portal_mcp_server_descriptor(request),
            );
        }
        ContextDigestKindV1::McpToolDescriptor { request } => {
            result.mcp_descriptor = Some(guard_command::mcp_decision::portal_mcp_tool_descriptor(
                request,
            ));
        }
        ContextDigestKindV1::McpToolContentDigest { request } => {
            result.digest = Some(guard_command::mcp_decision::mcp_tool_content_digest(
                request,
            )?);
        }
        ContextDigestKindV1::BrowserMcp { request } => {
            result.browser_mcp = Some(guard_command::browser_mcp_intent::evaluate_browser_mcp(
                request,
            )?);
        }
        ContextDigestKindV1::McpToolRisk {
            artifact,
            arguments,
        } => {
            result.mcp_tool_risk = Some(guard_command::mcp_tool_risk::evaluate_tool_risk(
                artifact, arguments,
            )?);
        }
        ContextDigestKindV1::McpToolPolicy { request } => {
            result.mcp_tool_policy = Some(guard_command::mcp_tool_policy::evaluate_tool_policy(
                request,
            )?);
        }
        ContextDigestKindV1::BuildMcpToolApprovalHash { request } => match &request.config {
            None => {
                let hash = guard_command::mcp_tool_approval::build_tool_approval_digest(request)?;
                result.digest = Some(hash.token_or_digest);
                result.mcp_tool_risk = Some(hash.risk_categories);
            }
            Some(config) => {
                let material = guard_command::mcp_tool_approval::tool_approval_token_material(
                    request, config,
                )?;
                let extension_control_digest = request
                    .extension_control_digest
                    .as_deref()
                    .ok_or("native_context_component_invalid")?;
                result.token = Some(build_context_token_fields(
                    &material.identity,
                    &Value::String(material.content_digest.clone()),
                    &material.capabilities,
                    &material.sandbox,
                    extension_control_digest,
                    |out| {
                        guard_command::mcp_tool_policy::write_tool_policy_context(
                            &guard_contracts::McpToolApprovalContextRequestV1 {
                                config: config.clone(),
                                harness: request.harness.clone(),
                                artifact_id: request.artifact_id.clone(),
                                publisher: request.publisher.clone(),
                                identity: material.identity.clone(),
                                content: Value::String(material.content_digest.clone()),
                                capabilities: material.capabilities.clone(),
                                sandbox: material.sandbox.clone(),
                                extension_control_digest: extension_control_digest.to_owned(),
                            },
                            out,
                        )
                    },
                )?);
                result.mcp_tool_risk = Some(material.risk_categories);
            }
        },
        ContextDigestKindV1::McpToolApprovalDigest { request } => {
            result.digest = Some(guard_command::mcp_decision::mcp_tool_approval_digest(
                request,
            )?);
        }
        ContextDigestKindV1::PackageLauncherToken { command_name, args } => {
            result.package_launcher = Some(guard_contracts::PackageLauncherResultV1 {
                package: guard_command::mcp_decision::package_token(command_name, args),
            });
        }
        ContextDigestKindV1::RuntimeExecutableIdentity {
            command,
            search_path,
            cwd,
            home_dir,
            require_executable,
        } => {
            result.runtime_identity = Some(
                guard_command::launch_identity::build_runtime_executable_identity(
                    command.as_ref().unwrap_or(&Value::Null),
                    search_path.as_deref(),
                    cwd.as_deref().map(Path::new),
                    home_dir.as_deref().map(Path::new),
                    *require_executable,
                ),
            );
        }
        ContextDigestKindV1::RuntimeLaunchIdentity {
            command,
            args,
            structured_command,
            direct_executable,
            search_path,
            cwd,
            home_dir,
            launch_env,
        } => {
            let launch_env_value = launch_env.as_ref().map(|env| {
                Value::Object(
                    env.iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect(),
                )
            });
            result.runtime_identity = Some(
                guard_command::launch_identity::build_runtime_launch_identity(
                    command.as_ref().unwrap_or(&Value::Null),
                    args,
                    *structured_command,
                    *direct_executable,
                    search_path.as_deref(),
                    cwd.as_deref().map(Path::new),
                    home_dir.as_deref().map(Path::new),
                    launch_env_value.as_ref(),
                ),
            );
        }
        ContextDigestKindV1::RuntimeLaunchIdentityMatches {
            expected_identity,
            command,
            args,
            structured_command,
            direct_executable,
            search_path,
            cwd,
            launch_env,
        } => {
            let launch_env_value = launch_env.as_ref().map(|env| {
                Value::Object(
                    env.iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect(),
                )
            });
            result.runtime_identity_match = Some(
                guard_command::launch_identity::runtime_launch_identity_matches(
                    expected_identity,
                    command.as_ref().unwrap_or(&Value::Null),
                    args,
                    *structured_command,
                    *direct_executable,
                    search_path.as_deref(),
                    cwd.as_deref().map(Path::new),
                    launch_env_value.as_ref(),
                ),
            );
        }
        ContextDigestKindV1::RuntimeLaunchIdentityProjection { identity, args } => {
            result.runtime_identity_reusable =
                Some(guard_command::launch_identity::runtime_launch_identity_is_reusable(identity));
            result.runtime_resolved_executable =
                guard_command::launch_identity::resolved_runtime_launch_executable(identity);
            result.runtime_resolved_argv =
                guard_command::launch_identity::resolved_runtime_launch_argv(identity, args);
        }
        ContextDigestKindV1::McpToolCatalogFingerprint {
            entries,
            state,
            version,
        } => {
            let (digest, canonical) =
                guard_command::mcp_tool_catalog::tool_catalog_fingerprint(entries, state, version);
            result.digest = digest;
            result.tool_catalog = canonical;
        }
    }
    Ok(())
}

fn package_context_evidence(
    context: guard_command::package_execution_context::PackageExecutionContext,
) -> PackageContextEvidenceV1 {
    PackageContextEvidenceV1 {
        digest: context.digest,
        portable: context.portable,
        components: context
            .components
            .into_iter()
            .map(|component| PackageContextComponentV1 {
                name: component.name,
                digest: component.digest,
            })
            .collect(),
        non_portable_reason: context.non_portable_reason,
    }
}

/// Canonical-JSON digest of a request — order-independent, so the caller can
/// reproduce it by canonicalizing its own request serialization.
fn request_digest(request: &ContextDigestRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_context_digest_invalid")?;
    let mut canonical = Vec::with_capacity(512);
    // The request itself is already bounded by transport framing; the
    // component cap is enforced when hashing components, not the envelope.
    write_canonical_json_with_limit(&material, &mut canonical, usize::MAX)?;
    Ok(digest_bytes(&canonical))
}

pub(crate) fn evaluate_context_digest_request(
    request: &ContextDigestRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTEXT_DIGEST_REQUEST_SCHEMA {
        return Err("native_context_digest_schema_mismatch".to_owned());
    }
    let mut result = ContextDigestResultV1 {
        schema: CONTEXT_DIGEST_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_digest(request)?,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        token: None,
        digest: None,
        validation_reason: None,
        environment_values: None,
        mcp_launch_environment: None,
        package_context: None,
        mcp_server_identity: None,
        mcp_tool_identity: None,
        package_launcher: None,
        mcp_descriptor: None,
        browser_mcp: None,
        mcp_tool_risk: None,
        mcp_tool_policy: None,
        mcp_launch_target: None,
        mcp_safe_arguments: None,
        mcp_serialized_arguments: None,
        mcp_redacted_value: None,
        runtime_identity: None,
        runtime_identity_match: None,
        runtime_identity_reusable: None,
        runtime_resolved_executable: None,
        runtime_resolved_argv: None,
        tool_catalog: None,
    };
    if let Err(code) = evaluate_request(request, &mut result) {
        result.status = "error".to_owned();
        result.code = code.to_owned();
    }
    crate::encode_response(&result)
}

pub(crate) fn evaluate_context_digest_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: ContextDigestRequestV1 = crate::strict_json::from_value(value)
        .map_err(|_| "native_context_digest_invalid_json".to_owned())?;
    evaluate_context_digest_request(&request)
}

#[cfg(test)]
#[path = "context_digest_tests.rs"]
mod tests;
