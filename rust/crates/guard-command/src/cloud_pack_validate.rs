//! Structural validation of a cloud action pack.
//!
//! Serde already refused unknown fields and wrong types. This pass checks
//! every rule a type cannot carry: names and hosts, anchored patterns that the
//! linear-time engine compiles within a size bound, path placeholders that sit
//! on whole segments, constant non-credential headers, extractors that read
//! arguments of the right kind, an effect no weaker than the fact class, and
//! a safe and a risky fixture for every action.

use crate::cloud_action_binding::{valid_action_id, valid_label, TargetCapability};
use crate::cloud_action_v2::{class_effect, effect_rank};
use crate::cloud_pack::*;
use crate::cloud_pack_validate_facts::validate_facts;
use std::collections::BTreeSet;

pub use crate::cloud_pack_pattern::{compile, compile_whole};

const MAX_TEXT_LENGTH: u32 = 65_536;
const MAX_ARRAY_ITEMS: u32 = 1_000;
const MAX_FIELDS: usize = 64;
const MAX_RESPONSE_DEPTH: usize = 4;
/// Header names a pack may never set: credentials, cookies and framing.
const FORBIDDEN_HEADER_PARTS: [&str; 8] = [
    "auth",
    "cookie",
    "token",
    "secret",
    "key",
    "session",
    "password",
    "credential",
];
const FORBIDDEN_HEADERS: [&str; 8] = [
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "forwarded",
];

type Check = Result<(), PackError>;

fn fail(code: &'static str, pointer: impl Into<String>) -> Check {
    Err(PackError::new(code, pointer))
}

/// Validate a source pack: every action carries a safe and a risky fixture.
pub fn validate(pack: &CloudActionPack) -> Check {
    validate_form(pack, true)
}

/// Validate the pack inside a compiled artifact, where fixtures are stripped.
pub fn validate_compiled(pack: &CloudActionPack) -> Check {
    validate_form(pack, false)
}

fn validate_form(pack: &CloudActionPack, source: bool) -> Check {
    if pack.schema != PACK_SCHEMA {
        return fail("cloud_pack_schema_unsupported", "/schema");
    }
    if !provider_id(&pack.provider.id) {
        return fail("cloud_pack_provider_invalid", "/provider/id");
    }
    if !display_text(&pack.provider.name, 128) || !display_text(&pack.provider.publisher.name, 128)
    {
        return fail("cloud_pack_provider_invalid", "/provider");
    }
    let hosts: BTreeSet<&str> = pack.hosts.iter().map(String::as_str).collect();
    if pack.hosts.is_empty()
        || pack.hosts.len() > MAX_HOSTS
        || hosts.len() != pack.hosts.len()
        || !pack.hosts.iter().all(|host| valid_host(host))
    {
        return fail("cloud_pack_hosts_invalid", "/hosts");
    }
    if !pack
        .auth
        .scopes
        .iter()
        .all(|scope| valid_label(scope) && scope.len() <= 128)
        || (pack.auth.mode == AuthMode::None && !pack.auth.scopes.is_empty())
    {
        return fail("cloud_pack_auth_invalid", "/auth");
    }
    if pack.actions.is_empty() || pack.actions.len() > MAX_ACTIONS {
        return fail("cloud_pack_actions_invalid", "/actions");
    }
    let mut ids = BTreeSet::new();
    let prefix = format!("{}.", pack.provider.id);
    for (index, action) in pack.actions.iter().enumerate() {
        let at = format!("/actions/{index}");
        if !valid_action_id(&action.action_id)
            || !action.action_id.starts_with(&prefix)
            || !ids.insert(action.action_id.as_str())
        {
            return fail("cloud_pack_action_id_invalid", format!("{at}/actionId"));
        }
        validate_action(pack, action, &hosts, &at)?;
        let fixtures = if source {
            validate_fixtures(action)
        } else if action.fixtures.is_empty() {
            Ok(())
        } else {
            Err("cloud_pack_fixtures_invalid")
        };
        fixtures.map_err(|code| PackError::new(code, format!("{at}/fixtures")))?;
    }
    Ok(())
}

fn validate_action(
    pack: &CloudActionPack,
    action: &PackAction,
    hosts: &BTreeSet<&str>,
    at: &str,
) -> Check {
    if !display_text(&action.title, 120) {
        return fail("cloud_pack_title_invalid", format!("{at}/title"));
    }
    if let Some(link) = &action.link {
        let ok = match (&link.permission_id, &link.tool) {
            (Some(name), None) | (None, Some(name)) => valid_label(name) && name.len() <= 128,
            _ => false,
        };
        if !ok {
            return fail("cloud_pack_link_invalid", format!("{at}/link"));
        }
    }
    if action.arguments.len() > MAX_ARGUMENTS {
        return fail("cloud_pack_arguments_invalid", format!("{at}/arguments"));
    }
    for (name, spec) in &action.arguments {
        if !snake_name(name) {
            return fail(
                "cloud_pack_argument_name_invalid",
                format!("{at}/arguments/{name}"),
            );
        }
        validate_argument(spec)
            .map_err(|code| PackError::new(code, format!("{at}/arguments/{name}")))?;
    }
    match &action.executor {
        Executor::DeclarativeHttp { request } => {
            crate::cloud_pack_validate_request::validate_request(action, request, hosts).map_err(
                |(code, rest)| PackError::new(code, format!("{at}/executor/request{rest}")),
            )?;
        }
        Executor::RemoteMcp { tool } => {
            if !valid_label(tool) || tool.len() > 128 {
                return fail("cloud_pack_executor_invalid", format!("{at}/executor/tool"));
            }
        }
        Executor::Broker => {}
    }
    validate_facts(pack, action).map_err(|code| PackError::new(code, format!("{at}/facts")))?;
    validate_response(&action.response.fields, 0)
        .map_err(|code| PackError::new(code, format!("{at}/response")))?;
    if action.response.max_bytes == 0 || action.response.max_bytes > MAX_RESPONSE_BYTES {
        return fail(
            "cloud_pack_response_invalid",
            format!("{at}/response/maxBytes"),
        );
    }
    validate_safety(pack, action).map_err(|code| PackError::new(code, format!("{at}/safety")))
}

fn validate_argument(spec: &ArgumentSpec) -> Result<(), &'static str> {
    match spec {
        ArgumentSpec::Integer {
            minimum, maximum, ..
        } => {
            let safe = 1_i64 << 53;
            if minimum > maximum || *minimum < -safe || *maximum > safe {
                return Err("cloud_pack_argument_bounds_invalid");
            }
        }
        ArgumentSpec::Boolean { .. } => {}
        ArgumentSpec::String { .. } => validate_text(&spec.text_rule().unwrap_or_else(empty_rule))?,
        ArgumentSpec::Array {
            min_items,
            max_items,
            items,
            ..
        } => {
            if *min_items == 0 || min_items > max_items || *max_items > MAX_ARRAY_ITEMS {
                return Err("cloud_pack_argument_bounds_invalid");
            }
            validate_text(items)?;
        }
    }
    Ok(())
}

fn empty_rule() -> TextRule {
    TextRule {
        pattern: None,
        max_length: 0,
        forbidden: None,
    }
}

fn validate_text(rule: &TextRule) -> Result<(), &'static str> {
    if rule.max_length == 0 || rule.max_length > MAX_TEXT_LENGTH {
        return Err("cloud_pack_argument_bounds_invalid");
    }
    if let Some(pattern) = &rule.pattern {
        if !pattern.starts_with('^') || !pattern.ends_with('$') || compile_whole(pattern).is_none()
        {
            return Err("cloud_pack_pattern_invalid");
        }
    }
    if let Some(forbidden) = &rule.forbidden {
        if compile(forbidden).is_none() {
            return Err("cloud_pack_pattern_invalid");
        }
    }
    Ok(())
}

fn validate_response(fields: &[ResponseField], depth: usize) -> Result<(), &'static str> {
    if fields.is_empty() || fields.len() > MAX_FIELDS || depth >= MAX_RESPONSE_DEPTH {
        return Err("cloud_pack_response_invalid");
    }
    let mut names = BTreeSet::new();
    for field in fields {
        if !snake_name(&field.name) || !names.insert(field.name.as_str()) {
            return Err("cloud_pack_response_invalid");
        }
        let labelled = field.untrusted || field.sensitivity.is_some();
        match &field.value {
            FieldSource::From(path) | FieldSource::Exists(path) => {
                if !response_path(path, false) {
                    return Err("cloud_pack_response_path_invalid");
                }
                if labelled && matches!(field.value, FieldSource::Exists(_)) {
                    return Err("cloud_pack_response_label_invalid");
                }
            }
            FieldSource::List {
                from,
                max_items,
                fields,
            } => {
                if labelled
                    || *max_items == 0
                    || *max_items > MAX_ARRAY_ITEMS
                    || !response_path(from, true)
                {
                    return Err("cloud_pack_response_invalid");
                }
                validate_response(fields, depth + 1)?;
            }
            FieldSource::Object { from, fields } => {
                if labelled || !response_path(from, true) {
                    return Err("cloud_pack_response_invalid");
                }
                validate_response(fields, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn response_path(path: &str, allow_empty: bool) -> bool {
    if path.is_empty() {
        return allow_empty;
    }
    path.len() <= 256
        && path.split('.').all(|key| {
            !key.is_empty()
                && key.len() <= 64
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'$' | b'@'))
        })
}

fn validate_safety(pack: &CloudActionPack, action: &PackAction) -> Result<(), &'static str> {
    let safety = &action.safety;
    if effect_rank(safety.effect) < effect_rank(class_effect(action.facts.class)) {
        return Err("cloud_pack_effect_below_facts");
    }
    let floor = [
        TargetCapability::EgressPinned,
        TargetCapability::BoundedOutput,
    ];
    if !floor
        .iter()
        .all(|cap| safety.required_capabilities.contains(cap))
    {
        return Err("cloud_pack_capabilities_invalid");
    }
    if let Some(resource) = &safety.resource {
        let string_arg = matches!(
            action.arguments.get(&resource.argument),
            Some(ArgumentSpec::String { required: true, .. })
        );
        if !string_arg
            || !valid_label(&resource.kind)
            || !safety
                .required_capabilities
                .contains(&TargetCapability::ResourceAllowlist)
        {
            return Err("cloud_pack_resource_invalid");
        }
    }
    match safety.idempotency {
        Idempotency::SafeRead
            if safety.effect != crate::cloud_action_binding::ActionEffect::Read =>
        {
            return Err("cloud_pack_idempotency_invalid")
        }
        Idempotency::ProviderKey
            if !safety
                .required_capabilities
                .contains(&TargetCapability::ProviderIdempotency) =>
        {
            return Err("cloud_pack_idempotency_invalid")
        }
        _ => {}
    }
    if !safety.scopes.is_subset(&pack.auth.scopes)
        || (pack.auth.mode != AuthMode::None && safety.scopes.is_empty())
    {
        return Err("cloud_pack_scopes_invalid");
    }
    if safety.max_items == 0
        || safety.max_items > 10_000
        || safety.min_interval_ms > 86_400_000
        || safety.timeout_ms == 0
        || safety.timeout_ms > 60_000
    {
        return Err("cloud_pack_limits_invalid");
    }
    Ok(())
}

fn validate_fixtures(action: &PackAction) -> Result<(), &'static str> {
    if action.fixtures.len() > MAX_FIXTURES {
        return Err("cloud_pack_fixtures_invalid");
    }
    let has = |kind| action.fixtures.iter().any(|fixture| fixture.kind == kind);
    if !has(FixtureKind::Safe) || !has(FixtureKind::Risky) {
        return Err("cloud_pack_fixtures_missing");
    }
    let http = matches!(action.executor, Executor::DeclarativeHttp { .. });
    let mut names = BTreeSet::new();
    for fixture in &action.fixtures {
        let expect = &fixture.expect;
        if !display_text(&fixture.name, 120)
            || !names.insert(fixture.name.as_str())
            || !fixture.arguments.is_object()
            || (expect.request.is_some() && !http)
            || expect.response.is_some() != expect.projection.is_some()
            || (expect.error.is_some() && (expect.facts.is_some() || expect.request.is_some()))
        {
            return Err("cloud_pack_fixtures_invalid");
        }
    }
    Ok(())
}

fn provider_id(value: &str) -> bool {
    (2..=32).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(crate) fn snake_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0] == b'_')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn display_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= max && !value.chars().any(char::is_control)
}

/// A lowercase DNS name with at least two labels and no IP literal or port.
pub(crate) fn valid_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_lowercase()))
}

pub(crate) fn header_allowed(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !FORBIDDEN_HEADERS.contains(&name)
        && !FORBIDDEN_HEADER_PARTS
            .iter()
            .any(|part| name.contains(part))
        && !name.starts_with("proxy-")
        && !name.starts_with("x-forwarded")
}
