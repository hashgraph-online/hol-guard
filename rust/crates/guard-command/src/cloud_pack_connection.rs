//! Per-connection values for cloud action packs.
//!
//! Some services address one customer's data by a value that belongs to the
//! connection rather than the call: a help desk's subdomain, an accounting
//! company id, the server a chat bot was added to. A pack declares each such
//! value once, with bounds. The host fills it from the verified connection
//! when it renders a request; a caller can never supply it, so no argument can
//! move a request to another customer's tenant.
//!
//! A value is used by name like a required string argument: as a path
//! placeholder, a query value or a body field. It may also be the leftmost
//! label of a host (`{subdomain}.example.com`), and then it must be one
//! lowercase DNS label when rendered.

use crate::cloud_pack::{ArgumentSpec, AuthMode, CloudActionPack, Executor, PackError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Most values one pack may declare.
pub const MAX_CONNECTION_VALUES: usize = 4;
const MAX_VALUE_LENGTH: u32 = 128;
/// Longest DNS name, the bound plain hosts already meet.
const MAX_HOST_LENGTH: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Connection {
    pub values: BTreeMap<String, ConnectionValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionValue {
    /// What the value is, as a reviewer reads it.
    pub title: String,
    /// Anchored pattern the value must match.
    pub pattern: String,
    pub max_length: u32,
}

/// A present `connection` key must hold a block; `null` is refused, not read as absent.
pub(crate) fn present<'de, D>(deserializer: D) -> Result<Option<Connection>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Connection::deserialize(deserializer).map(Some)
}

/// Split `{name}.rest` into the value name and the fixed host after it.
pub fn host_template(host: &str) -> Option<(&str, &str)> {
    let (name, rest) = host.strip_prefix('{')?.split_once("}.")?;
    Some((name, rest))
}

/// A declared host: an exact DNS name, or one whose leftmost label is a
/// declared connection value followed by an exact name of two or more labels.
pub(crate) fn valid_pack_host(pack: &CloudActionPack, host: &str) -> bool {
    match host_template(host) {
        Some((name, rest)) => {
            declared(pack.connection.as_ref(), name) && crate::cloud_pack_validate::valid_host(rest)
        }
        None => crate::cloud_pack_validate::valid_host(host),
    }
}

fn declared(connection: Option<&Connection>, name: &str) -> bool {
    connection.is_some_and(|connection| connection.values.contains_key(name))
}

/// Check the optional `connection` block. Values are filled into plain HTTP
/// requests only, need a sign-in to belong to, and may not share a name with
/// any action argument.
pub fn validate_connection(pack: &CloudActionPack) -> Result<(), PackError> {
    let Some(connection) = &pack.connection else {
        return Ok(());
    };
    let invalid = |pointer: String| PackError::new("cloud_pack_connection_invalid", pointer);
    let http_only = pack
        .actions
        .iter()
        .all(|action| matches!(action.executor, Executor::DeclarativeHttp { .. }));
    if pack.auth.mode == AuthMode::None
        || !http_only
        || connection.values.is_empty()
        || connection.values.len() > MAX_CONNECTION_VALUES
    {
        return Err(invalid("/connection".into()));
    }
    for (name, value) in &connection.values {
        let shadowed = pack
            .actions
            .iter()
            .any(|action| action.arguments.contains_key(name));
        let ok = crate::cloud_pack_validate::snake_name(name)
            && !shadowed
            && crate::cloud_pack_validate::display_text(&value.title, 120)
            && (1..=MAX_VALUE_LENGTH).contains(&value.max_length)
            && value.pattern.starts_with('^')
            && value.pattern.ends_with('$')
            && crate::cloud_pack_validate::compile_whole(&value.pattern).is_some();
        if !ok {
            return Err(invalid(format!("/connection/values/{name}")));
        }
    }
    Ok(())
}

/// The action's arguments with each connection value added as a required,
/// bounded string, so request templates may use it where they use one.
pub(crate) fn bound_arguments<'a>(
    arguments: &'a BTreeMap<String, ArgumentSpec>,
    connection: Option<&Connection>,
) -> Cow<'a, BTreeMap<String, ArgumentSpec>> {
    let Some(connection) = connection else {
        return Cow::Borrowed(arguments);
    };
    let mut bound = arguments.clone();
    for (name, value) in &connection.values {
        bound.insert(
            name.clone(),
            ArgumentSpec::String {
                required: true,
                pattern: Some(value.pattern.clone()),
                max_length: value.max_length,
                forbidden: None,
            },
        );
    }
    Cow::Owned(bound)
}

/// Why a connection value could not be bound: an error code and the value's name.
pub(crate) type BindError = (&'static str, Option<String>);

/// Add the connection's values to checked caller arguments and resolve the
/// request host. Every declared value must be given and fit its bounds; a
/// value the pack does not declare is refused.
pub(crate) fn bind<'a>(
    connection: Option<&Connection>,
    host: &str,
    record: &'a Map<String, Value>,
    values: &Map<String, Value>,
) -> Result<(Cow<'a, Map<String, Value>>, String), BindError> {
    if let Some(name) = values.keys().find(|name| !declared(connection, name)) {
        return Err(("connection_value_unknown", Some(name.clone())));
    }
    let Some(connection) = connection else {
        // A templated host cannot resolve without the connection that fills it.
        if let Some((name, _)) = host_template(host) {
            return Err(("connection_value_missing", Some(name.to_owned())));
        }
        return Ok((Cow::Borrowed(record), host.to_owned()));
    };
    let mut bound = record.clone();
    for (name, spec) in &connection.values {
        let Some(value) = values.get(name) else {
            return Err(("connection_value_missing", Some(name.clone())));
        };
        if record.contains_key(name) {
            return Err(("connection_value_from_caller", Some(name.clone())));
        }
        let rule = crate::cloud_pack::TextRule {
            pattern: Some(spec.pattern.clone()),
            max_length: spec.max_length,
            forbidden: None,
        };
        if crate::cloud_pack_request::check_text(Some(&rule), value).is_err() {
            return Err(("connection_value_invalid", Some(name.clone())));
        }
        bound.insert(name.clone(), value.clone());
    }
    let host = match host_template(host) {
        Some((name, rest)) => {
            let label = bound.get(name).and_then(Value::as_str).unwrap_or_default();
            let host = format!("{label}.{rest}");
            if !dns_label(label) || host.len() > MAX_HOST_LENGTH {
                return Err(("connection_value_invalid", Some(name.to_owned())));
            }
            host
        }
        None => host.to_owned(),
    };
    Ok((Cow::Owned(bound), host))
}

/// One lowercase DNS label: letters, digits and inner hyphens, 1..=63 bytes.
fn dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Each declared value with its bounds, for diffs. The bounds stay
/// structured, so two different declarations never compare equal.
pub fn connection_values(pack: &CloudActionPack) -> BTreeMap<&str, &ConnectionValue> {
    pack.connection
        .iter()
        .flat_map(|connection| connection.values.iter())
        .map(|(name, value)| (name.as_str(), value))
        .collect()
}
