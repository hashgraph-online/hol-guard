//! OAuth identity binding of Review outbox events: loading the active
//! binding, binding new events inside the writer's transaction, refreshing
//! same-subject machine metadata, and explicit quarantine reassignment.

use serde_json::Value;

use crate::guard_store_db::{exec, int, query_all, query_one, text, value_error, StoreResult};
use crate::guard_store_json::py_strip;
use crate::guard_store_outbox_identity::{oauth_subject_hash, payload_digest_text};
use rusqlite::Connection;

/// A complete delivery identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub subject_hash: String,
    pub workspace_id: String,
    pub machine_id: String,
    pub installation_id: String,
}

impl Binding {
    pub(crate) fn tuple(&self) -> [&str; 4] {
        [
            &self.subject_hash,
            &self.workspace_id,
            &self.machine_id,
            &self.installation_id,
        ]
    }

    pub(crate) fn values(&self) -> Vec<Value> {
        self.tuple()
            .iter()
            .map(|text| Value::String((*text).to_owned()))
            .collect()
    }

    pub(crate) fn digest(&self, source: &str, payload_json: &str) -> String {
        payload_digest_text(
            payload_json,
            [
                source,
                &self.subject_hash,
                &self.workspace_id,
                &self.machine_id,
                &self.installation_id,
            ],
        )
    }
}

/// `normalized_delivery_binding`: every part stripped and non-empty.
pub(crate) fn normalized_binding(parts: [&str; 4]) -> StoreResult<Binding> {
    let [subject, workspace, machine, installation] = parts.map(|part| py_strip(part).to_owned());
    if [&subject, &workspace, &machine, &installation]
        .iter()
        .any(|part| part.is_empty())
    {
        return value_error("complete Cloud Review OAuth binding is required");
    }
    Ok(Binding {
        subject_hash: subject,
        workspace_id: workspace,
        machine_id: machine,
        installation_id: installation,
    })
}

fn state_key(source: &str) -> String {
    if source == "default" {
        "oauth_local_credentials".to_owned()
    } else {
        format!("oauth_local_credentials:{source}")
    }
}

fn nonblank(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    let stripped = py_strip(text);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// The OAuth binding persisted by the local credential flow, or `None`.
pub(crate) fn load_binding(connection: &Connection, source: &str) -> StoreResult<Option<Binding>> {
    let Some(row) = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::String(state_key(source))],
    )?
    else {
        return Ok(None);
    };
    let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(text(&row, "payload_json"))
    else {
        return Ok(None);
    };
    let subject = payload
        .get("grant_id")
        .and_then(Value::as_str)
        .and_then(oauth_subject_hash);
    let device = query_one(
        connection,
        "select installation_id from guard_devices where device_key = 'local-device'",
        &[],
    )?;
    let installation = device.as_ref().and_then(|row| row.get("installation_id"));
    let (Some(subject), Some(workspace), Some(machine), Some(installation)) = (
        subject,
        nonblank(payload.get("workspace_id")),
        nonblank(payload.get("machine_id")),
        nonblank(installation),
    ) else {
        return Ok(None);
    };
    Ok(Some(Binding {
        subject_hash: subject,
        workspace_id: workspace,
        machine_id: machine,
        installation_id: installation,
    }))
}

fn rebind_event(
    connection: &Connection,
    sequence: i64,
    source: Option<&str>,
    binding: &Binding,
    payload_hash: &str,
) -> StoreResult<()> {
    let mut sql = String::from("update guard_review_outbox_events set payload_hash = ?, ");
    let mut params = vec![Value::from(payload_hash)];
    if let Some(source) = source {
        sql.push_str("oauth_source = ?, ");
        params.push(Value::from(source));
    }
    sql.push_str(
        "oauth_subject_hash = ?, workspace_id = ?, machine_id = ?, machine_installation_id = ?, \
         binding_status = 'ready', quarantine_reason = null where stream_sequence = ?",
    );
    params.extend(binding.values());
    params.push(Value::from(sequence));
    exec(connection, &sql, &params)?;
    Ok(())
}

/// Bind the first event of a request inside the approval write transaction.
pub(crate) fn bind_events_for_request(
    connection: &Connection,
    request_id: &str,
    source: &str,
) -> StoreResult<bool> {
    let Some(binding) = load_binding(connection, source)? else {
        return Ok(false);
    };
    let Some(candidate) = query_one(
        connection,
        "select stream_sequence, payload_json from guard_review_outbox_events \
         where local_request_id = ? and request_sequence = 1 and oauth_source = ? \
         and binding_status = 'quarantined' and oauth_subject_hash is null \
         and workspace_id is null and machine_id is null and machine_installation_id is null \
         and not exists (select 1 from guard_review_outbox_events as later \
           where later.local_request_id = guard_review_outbox_events.local_request_id \
           and later.request_sequence > 1)",
        &[Value::from(request_id), Value::from(source)],
    )?
    else {
        return Ok(false);
    };
    let digest = binding.digest(source, text(&candidate, "payload_json"));
    exec(
        connection,
        "update guard_review_outbox_events set payload_hash = ?, oauth_subject_hash = ?, \
         workspace_id = ?, machine_id = ?, machine_installation_id = ?, \
         binding_status = 'ready', quarantine_reason = null where stream_sequence = ?",
        &[
            Value::from(digest),
            Value::from(binding.subject_hash.clone()),
            Value::from(binding.workspace_id.clone()),
            Value::from(binding.machine_id.clone()),
            Value::from(binding.installation_id.clone()),
            Value::from(int(&candidate, "stream_sequence")),
        ],
    )?;
    let mut params = vec![Value::from(source)];
    params.extend(binding.values());
    params.push(Value::from(request_id));
    exec(
        connection,
        "update guard_review_outbox_request_sequences set oauth_source = ?, oauth_subject_hash = ?, \
         workspace_id = ?, machine_id = ?, machine_installation_id = ? where local_request_id = ?",
        &params,
    )?;
    Ok(true)
}

/// Refresh machine metadata only when the subject and workspace are unchanged;
/// events of any other identity are quarantined.
pub(crate) fn refresh_same_subject(connection: &Connection, source: &str) -> StoreResult<i64> {
    let Some(binding) = load_binding(connection, source)? else {
        return Ok(0);
    };
    let candidates = query_all(
        connection,
        "select stream_sequence, payload_json from guard_review_outbox_events \
         where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ? \
         and binding_status = 'ready' \
         and (machine_id is not ? or machine_installation_id is not ?)",
        &[
            Value::from(source),
            Value::from(binding.subject_hash.clone()),
            Value::from(binding.workspace_id.clone()),
            Value::from(binding.machine_id.clone()),
            Value::from(binding.installation_id.clone()),
        ],
    )?;
    for candidate in &candidates {
        let digest = binding.digest(source, text(candidate, "payload_json"));
        exec(
            connection,
            "update guard_review_outbox_events set payload_hash = ?, machine_id = ?, \
             machine_installation_id = ?, binding_status = 'ready', quarantine_reason = null \
             where stream_sequence = ?",
            &[
                Value::from(digest),
                Value::from(binding.machine_id.clone()),
                Value::from(binding.installation_id.clone()),
                Value::from(int(candidate, "stream_sequence")),
            ],
        )?;
    }
    exec(
        connection,
        "update guard_review_outbox_request_sequences set machine_id = ?, machine_installation_id = ? \
         where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?",
        &[
            Value::from(binding.machine_id.clone()),
            Value::from(binding.installation_id.clone()),
            Value::from(source),
            Value::from(binding.subject_hash.clone()),
            Value::from(binding.workspace_id.clone()),
        ],
    )?;
    let quarantined = exec(
        connection,
        "update guard_review_outbox_events set binding_status = 'quarantined', \
         quarantine_reason = 'identity_changed_requires_confirmation' \
         where oauth_source = ? and binding_status = 'ready' \
         and (oauth_subject_hash is not ? or workspace_id is not ?)",
        &[
            Value::from(source),
            Value::from(binding.subject_hash.clone()),
            Value::from(binding.workspace_id.clone()),
        ],
    )?;
    Ok(candidates.len() as i64 + quarantined.max(0))
}

fn reassignment_filter(
    source: &str,
    binding: &Binding,
    only_unbound: bool,
) -> (String, Vec<Value>) {
    let mut query = String::from(
        " binding_status = 'quarantined' \
         and quarantine_reason in ('identity_incomplete', 'identity_changed_requires_confirmation') \
         and (oauth_source = ? or (oauth_source is null and (workspace_id is null or workspace_id = ?)))",
    );
    let mut params = vec![
        Value::from(source),
        Value::from(binding.workspace_id.clone()),
    ];
    if only_unbound {
        query.push_str(" and quarantine_reason = 'identity_incomplete'");
        let columns = [
            "oauth_subject_hash",
            "workspace_id",
            "machine_id",
            "machine_installation_id",
        ];
        for (column, value) in columns.iter().zip(binding.tuple()) {
            query.push_str(&format!(" and ({column} is null or {column} = ?)"));
            params.push(Value::from(value));
        }
        let all = [
            source,
            &binding.subject_hash,
            &binding.workspace_id,
            &binding.machine_id,
            &binding.installation_id,
        ];
        let names = [
            "oauth_source",
            "oauth_subject_hash",
            "workspace_id",
            "machine_id",
            "machine_installation_id",
        ];
        for table in [
            "guard_review_outbox_request_sequences",
            "guard_review_outbox_events",
        ] {
            let conflicts: Vec<String> = names
                .iter()
                .map(|name| format!("(prior.{name} is not null and prior.{name} != ?)"))
                .collect();
            params.extend(all.iter().map(|value| Value::from(*value)));
            query.push_str(&format!(
                " and not exists (select 1 from {table} prior \
                 where prior.local_request_id = guard_review_outbox_events.local_request_id \
                 and ({}))",
                conflicts.join(" or ")
            ));
        }
    }
    (query, params)
}

/// Count quarantined events that an identity-matching repair could adopt.
pub(crate) fn count_recoverable_unbound(connection: &Connection, source: &str) -> StoreResult<i64> {
    let Some(binding) = load_binding(connection, source)? else {
        return Ok(0);
    };
    let (filter, params) = reassignment_filter(source, &binding, true);
    let row = query_one(
        connection,
        &format!("select count(*) as total from guard_review_outbox_events where{filter}"),
        &params,
    )?;
    Ok(row.map_or(0, |row| int(&row, "total")))
}

/// Adopt quarantined events once the caller confirmed the target binding.
pub(crate) fn reassign_quarantined(
    connection: &Connection,
    source: &str,
    approved_source: &str,
    approved_workspace_id: &str,
    only_unbound: bool,
) -> StoreResult<i64> {
    if py_strip(approved_source) != source {
        return value_error("approved source does not match the active Guard connection source");
    }
    let Some(binding) = load_binding(connection, source)? else {
        return value_error("active OAuth source does not have a complete Review event binding");
    };
    if py_strip(approved_workspace_id) != binding.workspace_id {
        return value_error("approved workspace does not match the active OAuth workspace");
    }
    let (filter, params) = reassignment_filter(source, &binding, only_unbound);
    let candidates = query_all(
        connection,
        &format!(
            "select stream_sequence, local_request_id, payload_json \
             from guard_review_outbox_events where{filter}"
        ),
        &params,
    )?;
    for candidate in &candidates {
        let digest = binding.digest(source, text(candidate, "payload_json"));
        rebind_event(
            connection,
            int(candidate, "stream_sequence"),
            Some(source),
            &binding,
            &digest,
        )?;
    }
    let mut request_ids: Vec<&str> = candidates
        .iter()
        .map(|candidate| text(candidate, "local_request_id"))
        .collect();
    request_ids.sort_unstable();
    request_ids.dedup();
    for request_id in request_ids {
        let mut params = vec![Value::from(source)];
        params.extend(binding.values());
        params.push(Value::from(request_id));
        exec(
            connection,
            "update guard_review_outbox_request_sequences set oauth_source = ?, \
             oauth_subject_hash = ?, workspace_id = ?, machine_id = ?, \
             machine_installation_id = ? where local_request_id = ?",
            &params,
        )?;
        exec(
            connection,
            "update approval_requests set oauth_source = ? \
             where oauth_source is null and request_id = ?",
            &[Value::from(source), Value::from(request_id)],
        )?;
    }
    Ok(candidates.len() as i64)
}

/// Whether a stored row's binding columns equal `binding`.
pub(crate) fn row_matches(row: &crate::guard_store_db::Row, binding: &Binding) -> bool {
    let names = [
        "oauth_subject_hash",
        "workspace_id",
        "machine_id",
        "machine_installation_id",
    ];
    names
        .iter()
        .zip(binding.tuple())
        .all(|(name, expected)| row.get(*name).and_then(Value::as_str) == Some(expected))
}
