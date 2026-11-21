//! `store_mcp_provider_catalog.write_composio_metadata`,
//! `rebuild_provider_authority` and `store_mcp_workflows.write_workflow_proposals`,
//! joined into the one write `record_composio_discovery` performs after the
//! connector observation exists.
//!
//! The two halves share a transaction in Python and have to keep sharing one:
//! a proposal names action slugs, and a catalog that advanced without its
//! proposals, or proposals naming actions that were never stored, would let a
//! reader resolve a requirement against a catalog the proposal never saw.

use std::collections::HashMap;

use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, int, query_all, query_one, text, value_error, StoreResult};
use crate::guard_store_json::dumps_sorted;

/// `_MAX_ACTIONS` / `_MAX_BYTES`.
const MAX_ACTIONS: i64 = 10_000;
const MAX_BYTES: i64 = 2_000_000;
/// `write_workflow_proposals` keeps the newest 50 advisory rows per connection.
const MAX_PROPOSALS: usize = 50;

/// One `ComposioActionSchema` as it crosses the wire.
struct Action<'a> {
    toolkit: &'a str,
    tool_slug: &'a str,
    description: &'a str,
    input_schema: &'a Value,
    full_schema: bool,
}

impl Action<'_> {
    /// `json.dumps(action.input_schema, sort_keys=True, separators=(",", ":"),
    /// ensure_ascii=True, allow_nan=False)`.
    fn schema_text(&self) -> StoreResult<String> {
        match dumps_sorted(self.input_schema) {
            Some(text) => Ok(text),
            // `allow_nan=False` — Python raises `ValueError` on a non-finite
            // number, and the caller sees the same failure it always did.
            None => value_error("provider metadata schema is not representable"),
        }
    }

    /// The digest the grant surface binds: toolkit, slug and schema together,
    /// so renaming a toolkit or widening a schema both move the authority.
    fn authority_hash(&self) -> StoreResult<String> {
        let identity = json!({
            "toolkit": self.toolkit,
            "tool_slug": self.tool_slug,
            "input_schema": self.input_schema,
        });
        match dumps_sorted(&identity) {
            Some(text) => Ok(hex_sha256(text.as_bytes())),
            None => value_error("provider metadata schema is not representable"),
        }
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn actions<'a>(args: &Args<'a>, key: &str) -> StoreResult<Vec<Action<'a>>> {
    let Some(Value::Array(items)) = args.raw(key) else {
        return value_error("invalid provider discovery actions");
    };
    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        let (
            Some(Value::String(toolkit)),
            Some(Value::String(tool_slug)),
            Some(Value::String(description)),
            Some(input_schema),
            Some(Value::Bool(full_schema)),
        ) = (
            item.get("toolkit"),
            item.get("tool_slug"),
            item.get("description"),
            item.get("input_schema"),
            item.get("full_schema"),
        )
        else {
            return value_error("invalid provider discovery actions");
        };
        parsed.push(Action {
            toolkit,
            tool_slug,
            description,
            input_schema,
            full_schema: *full_schema,
        });
    }
    Ok(parsed)
}

/// `write_composio_metadata` + `write_workflow_proposals` under one write.
///
/// `before_authority_change` in Python closes the native policy barrier from
/// inside the transaction. The resident cannot reach the publishers that
/// barrier notifies, so it reports the need instead: a first call that would
/// move the authority writes nothing and answers `need_barrier`, and the
/// caller closes the barrier and calls again with `barrier_closed`. This is
/// the protocol `ensure_local_mcp_observation` already uses for its legacy
/// denial carry.
pub(crate) fn record_composio_discovery(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    let identity_hash = args.str("identity_hash")?;
    let seen_at = args.str("seen_at")?;
    let source_tool = args.str("source_tool")?;
    let actions = actions(args, "actions")?;
    require_matching_observation(
        connection,
        cli_id,
        identity_hash,
        args.str("server_command")?,
    )?;

    let mut prepared = Vec::with_capacity(actions.len());
    let mut authority_changed = false;
    // Python reads a slug's stored row inside the same loop that writes it, so
    // a slug repeated in one batch is measured against the copy before it, not
    // against the row the batch started from. The revisions are settled here
    // before any write so the barrier answer can come first, which means the
    // earlier copy has to be carried rather than read back.
    let mut staged: HashMap<&str, StoredAction> = HashMap::new();
    for action in &actions {
        let authority_hash = action.authority_hash()?;
        let previous = match staged.get(action.tool_slug) {
            Some(staged) => Some(staged.clone()),
            None => previous_revision(connection, cli_id, identity_hash, action.tool_slug)?,
        };
        let revision = match &previous {
            None => 1,
            Some(previous) => {
                previous.revision
                    + i64::from(
                        previous.authority_hash != authority_hash
                            || previous.full_schema != action.full_schema,
                    )
            }
        };
        authority_changed |= previous.is_none_or(|previous| previous.revision != revision);
        staged.insert(
            action.tool_slug,
            StoredAction {
                revision,
                authority_hash: authority_hash.clone(),
                full_schema: action.full_schema,
            },
        );
        prepared.push((action, action.schema_text()?, authority_hash, revision));
    }
    if authority_changed && !args.flag("barrier_closed")? {
        return Ok(json!({ "need_barrier": true }));
    }

    for (action, schema_text, authority_hash, revision) in prepared {
        exec(
            connection,
            "insert into local_mcp_provider_action \
             (cli_id, identity_hash, provider, tool_slug, toolkit, description, input_schema_json, \
              authority_hash, full_schema, source_tool, revision, updated_at) \
             values (?, ?, 'composio', ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             on conflict(cli_id, identity_hash, provider, tool_slug) do update set \
             toolkit = excluded.toolkit, description = excluded.description, \
             input_schema_json = excluded.input_schema_json, authority_hash = excluded.authority_hash, \
             full_schema = excluded.full_schema, source_tool = excluded.source_tool, \
             revision = excluded.revision, updated_at = excluded.updated_at",
            &[
                Value::from(cli_id),
                Value::from(identity_hash),
                Value::from(action.tool_slug),
                Value::from(action.toolkit),
                Value::from(action.description),
                Value::from(schema_text),
                Value::from(authority_hash),
                Value::from(i64::from(action.full_schema)),
                Value::from(source_tool),
                Value::from(revision),
                Value::from(seen_at),
            ],
        )?;
    }
    require_capacity(connection, cli_id, identity_hash)?;
    if authority_changed {
        rebuild_provider_authority(connection, cli_id, identity_hash)?;
    }
    write_workflow_proposals(connection, args, cli_id, identity_hash, seen_at)?;
    Ok(json!({ "authority_changed": authority_changed }))
}

/// `raise ValueError("provider metadata connection changed")` — the cli_id has
/// to still name the connection whose metadata this is.
fn require_matching_observation(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
    server_command: &str,
) -> StoreResult<()> {
    let observation = query_one(
        connection,
        "select identity_hash, server_command from local_cli_observation \
         where cli_id = ? and surface = 'mcp'",
        &[Value::from(cli_id)],
    )?;
    match observation {
        Some(row)
            if text(&row, "identity_hash") == identity_hash
                && text(&row, "server_command") == server_command => {}
        _ => return value_error("provider metadata connection changed"),
    }
    Ok(())
}

#[derive(Clone)]
struct StoredAction {
    revision: i64,
    authority_hash: String,
    full_schema: bool,
}

fn previous_revision(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
    tool_slug: &str,
) -> StoreResult<Option<StoredAction>> {
    let row = query_one(
        connection,
        "select revision, authority_hash, full_schema from local_mcp_provider_action \
         where cli_id = ? and identity_hash = ? and provider = 'composio' and tool_slug = ?",
        &[
            Value::from(cli_id),
            Value::from(identity_hash),
            Value::from(tool_slug),
        ],
    )?;
    Ok(row.map(|row| StoredAction {
        revision: int(&row, "revision"),
        authority_hash: text(&row, "authority_hash").to_owned(),
        full_schema: int(&row, "full_schema") != 0,
    }))
}

/// `raise ValueError("provider metadata catalog capacity exceeded")`. The bound
/// is on stored bytes, so it counts the serialized schema and the description
/// as SQLite stores them rather than their character counts.
fn require_capacity(connection: &Connection, cli_id: &str, identity_hash: &str) -> StoreResult<()> {
    let Some(row) = query_one(
        connection,
        "select count(*) as action_count, \
         coalesce(sum(length(cast(input_schema_json as blob)) \
         + length(cast(description as blob))), 0) as stored_bytes \
         from local_mcp_provider_action where cli_id = ? and identity_hash = ?",
        &[Value::from(cli_id), Value::from(identity_hash)],
    )?
    else {
        return Ok(());
    };
    if int(&row, "action_count") > MAX_ACTIONS || int(&row, "stored_bytes") > MAX_BYTES {
        return value_error("provider metadata catalog capacity exceeded");
    }
    Ok(())
}

/// `rebuild_provider_authority`: one digest over every stored action for this
/// connection, in slug order, seeded with the connection identity.
fn rebuild_provider_authority(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
) -> StoreResult<()> {
    let mut fingerprint = Sha256::new();
    fingerprint.update(identity_hash.as_bytes());
    for row in query_all(
        connection,
        "select tool_slug, authority_hash, full_schema from local_mcp_provider_action \
         where cli_id = ? and identity_hash = ? order by tool_slug",
        &[Value::from(cli_id), Value::from(identity_hash)],
    )? {
        // `json.dumps(tuple(row), separators=(",", ":"))` over the three cells
        // SQLite returned, so the digest commits to their stored types.
        let Some(serialized) = dumps_sorted(&json!([
            text(&row, "tool_slug"),
            text(&row, "authority_hash"),
            int(&row, "full_schema"),
        ])) else {
            return value_error("provider metadata schema is not representable");
        };
        fingerprint.update(serialized.as_bytes());
    }
    exec(
        connection,
        "insert into local_mcp_provider_authority values (?, ?, ?) \
         on conflict(cli_id, identity_hash) do update set digest = excluded.digest",
        &[
            Value::from(cli_id),
            Value::from(identity_hash),
            Value::from(format!("{:x}", fingerprint.finalize())),
        ],
    )?;
    Ok(())
}

/// `write_workflow_proposals`: advisory dependency hints, no authority. Their
/// retention discards only history, never a grant or a stored schema.
fn write_workflow_proposals(
    connection: &Connection,
    args: &Args<'_>,
    cli_id: &str,
    identity_hash: &str,
    seen_at: &str,
) -> StoreResult<()> {
    let proposals = match args.raw("proposals") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => return value_error("invalid provider workflow proposals"),
    };
    if proposals.len() > MAX_PROPOSALS {
        return value_error("provider_workflow_capacity");
    }
    for proposal in &proposals {
        let (Some(primary), Some(supporting), Some(Value::Bool(guidance_present))) = (
            proposal.get("primary"),
            proposal.get("supporting"),
            proposal.get("guidance_present"),
        ) else {
            return value_error("invalid provider workflow proposals");
        };
        let Some(serialized) = dumps_sorted(&json!({
            "primary": primary,
            "supporting": supporting,
            "guidance_present": guidance_present,
        })) else {
            return value_error("invalid provider workflow proposals");
        };
        // The id is the proposal's content under this connection, so the same
        // advice seen again refreshes `seen_at` rather than adding a row.
        let proposal_id = hex_sha256(format!("{identity_hash}\n{serialized}").as_bytes());
        exec(
            connection,
            "insert into local_mcp_workflow_proposal values (?, ?, ?, ?, ?) \
             on conflict(cli_id, identity_hash, proposal_id) do update set seen_at = excluded.seen_at",
            &[
                Value::from(cli_id),
                Value::from(identity_hash),
                Value::from(proposal_id),
                Value::from(serialized),
                Value::from(seen_at),
            ],
        )?;
    }
    exec(
        connection,
        "delete from local_mcp_workflow_proposal where cli_id = ? and proposal_id not in (\
         select proposal_id from local_mcp_workflow_proposal where cli_id = ? and identity_hash = ? \
         order by seen_at desc, proposal_id limit 50)",
        &[
            Value::from(cli_id),
            Value::from(cli_id),
            Value::from(identity_hash),
        ],
    )?;
    Ok(())
}
