//! The Guard Cloud agent identity a harness launch carries: the service
//! runtime profile Guard Cloud synced into `guard.db`, when it names this
//! runtime.

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Map, Value};

use super::files::text;
use super::Ctx;
use crate::pyjson::PyVal;

const PROFILE_FIELDS: [&str; 9] = [
    "runtime",
    "label",
    "workspace",
    "surface",
    "client_name",
    "client_title",
    "client_version",
    "agent_id",
    "principal_id",
];

const ENV_FIELDS: [(&str, &str); 5] = [
    ("runtime", "RUNTIME"),
    ("label", "LABEL"),
    ("workspace", "WORKSPACE"),
    ("agent_id", "AGENT_ID"),
    ("principal_id", "PRINCIPAL_ID"),
];

/// The stored profile, read-only; any read or decode failure is no profile.
fn service_runtime_profile(ctx: &Ctx) -> Option<Map<String, Value>> {
    let db = ctx.absolute(&ctx.guard_home.join("guard.db"));
    if !db.exists() {
        return None;
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(ctx.resolved(&db), flags).ok()?;
    let payload = connection
        .query_row(
            "select payload_json from sync_state where state_key = ?1",
            ["service_runtime_profile"],
            |row| {
                Ok(match row.get_ref(0)? {
                    ValueRef::Text(bytes) => String::from_utf8(bytes.to_vec()).ok(),
                    ValueRef::Integer(_) | ValueRef::Real(_) => None,
                    ValueRef::Null | ValueRef::Blob(_) => None,
                })
            },
        )
        .optional()
        .ok()??;
    match serde_json::from_str(&payload?).ok()? {
        Value::Object(profile) => Some(profile),
        _ => None,
    }
}

fn string_field<'a>(profile: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    profile
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// `cloud_agent_identity_hints(context, runtime=runtime)`, in field order.
pub(crate) fn hints(ctx: &Ctx, runtime: &str) -> Option<Vec<(String, String)>> {
    let profile = service_runtime_profile(ctx)?;
    if string_field(&profile, "runtime") != Some(runtime) {
        return None;
    }
    let hints: Vec<(String, String)> = PROFILE_FIELDS
        .iter()
        .filter_map(|field| {
            string_field(&profile, field).map(|value| ((*field).to_owned(), value.to_owned()))
        })
        .collect();
    (!hints.is_empty()).then_some(hints)
}

pub(crate) fn hints_value(hints: &[(String, String)]) -> PyVal {
    PyVal::Dict(
        hints
            .iter()
            .map(|(field, value)| (field.clone(), text(value.clone())))
            .collect(),
    )
}

/// `cloud_agent_identity_environment(hints, prefix=prefix)`.
pub(crate) fn environment(hints: Option<&[(String, String)]>, prefix: &str) -> Map<String, Value> {
    let mut env = Map::new();
    for (field, suffix) in ENV_FIELDS {
        let value = hints.and_then(|hints| hints.iter().find(|(name, _)| name == field));
        if let Some((_, value)) = value {
            env.insert(
                format!("{prefix}_GUARD_CLOUD_{suffix}"),
                Value::String(value.clone()),
            );
        }
    }
    env
}
