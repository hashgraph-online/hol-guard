//! Provider-action and capability choices, written by the continuity
//! writer inside its transaction.

use std::collections::HashSet;

use serde_json::{Map, Value};

use super::{Update, Writer, CAPABILITIES, CAUSE_BY_CAPABILITY, INVALID, MAX_PROVIDER_UPDATES};
use crate::guard_store_db::{exec, query_all, query_one, text, value_error, StoreResult};
use crate::guard_store_json::dumps_sorted;
use crate::guard_store_local_cli_mcp_snapshot::decode_snapshot;
use crate::guard_store_observed_mcp::marker_source;

impl Writer<'_> {
    /// `store_mcp_catalog.acknowledge_catalog_changes`: a saved choice for a
    /// new or changed tool reviews that change, but only on the catalog
    /// revision the choices were made against.
    pub(super) fn acknowledge_catalog_changes(
        &self,
        update: &Update<'_>,
        reviewed: &Map<String, Value>,
        catalog_revision: i64,
    ) -> StoreResult<()> {
        let Some(row) = query_one(
            self.connection,
            "select catalog_json, revision from local_mcp_catalog \
             where cli_id = ? and identity_hash = ?",
            &[
                Value::from(update.cli_id),
                Value::from(update.identity_hash),
            ],
        )?
        else {
            return Ok(());
        };
        if row.get("revision").and_then(Value::as_i64) != Some(catalog_revision) {
            return Ok(());
        }
        let Some(mut payload) = decode_snapshot(row.get("catalog_json")) else {
            return Ok(());
        };
        let Some(changes) = payload.get("changes").and_then(Value::as_object) else {
            return Ok(());
        };
        let is_reviewed = |name: &Value| {
            name.as_str()
                .and_then(|name| self.change_ids?.get(name)?.as_str())
                .is_some_and(|command_id| reviewed.contains_key(command_id))
        };
        let mut updated = changes.clone();
        for key in ["added", "changed"] {
            if let Some(Value::Array(names)) = updated.get_mut(key) {
                names.retain(|name| !is_reviewed(name));
            }
        }
        if &updated == changes {
            return Ok(());
        }
        payload["changes"] = Value::Object(updated);
        let Some(raw) = dumps_sorted(&payload) else {
            return value_error("MCP catalog snapshot is not representable");
        };
        exec(
            self.connection,
            "update local_mcp_catalog set catalog_json = ? where cli_id = ? and identity_hash = ?",
            &[
                Value::from(raw),
                Value::from(update.cli_id),
                Value::from(update.identity_hash),
            ],
        )?;
        Ok(())
    }

    /// `store_mcp_provider_permissions.write_provider_choices`.
    pub(super) fn write_provider_choices(
        &self,
        update: &Update<'_>,
        choices: &[Value],
    ) -> StoreResult<()> {
        let mut parsed = Vec::with_capacity(choices.len());
        for choice in choices {
            let [Value::String(slug), state, revision] =
                choice.as_array().ok_or(INVALID)?.as_slice()
            else {
                return Err(INVALID);
            };
            parsed.push((slug.as_str(), state, revision));
        }
        let slugs: HashSet<&str> = parsed.iter().map(|(slug, _, _)| *slug).collect();
        if parsed.len() > MAX_PROVIDER_UPDATES || slugs.len() != parsed.len() {
            return value_error("invalid provider action choices");
        }
        for (slug, state, revision) in parsed {
            let state = state
                .as_str()
                .filter(|state| matches!(*state, "review" | "block"));
            let revision = revision.as_i64().filter(|revision| *revision >= 1);
            let (Some(state), Some(revision)) = (state, revision) else {
                return value_error("invalid provider action choice");
            };
            let current = query_one(
                self.connection,
                "select a.revision from local_mcp_provider_action a \
                 join local_cli_observation o on o.cli_id = a.cli_id \
                 and o.identity_hash = a.identity_hash \
                 where a.cli_id = ? and a.identity_hash = ? and a.tool_slug = ? and o.surface = 'mcp'",
                &[
                    Value::from(update.cli_id),
                    Value::from(update.identity_hash),
                    Value::from(slug),
                ],
            )?;
            if current.and_then(|row| row.get("revision").and_then(Value::as_i64)) != Some(revision)
            {
                return value_error("provider_action_revision_conflict");
            }
            // Cached metadata cannot invent a different authority namespace.
            let marker = query_one(
                self.connection,
                "select server_command from local_cli_observation where cli_id = ?",
                &[Value::from(update.cli_id)],
            )?;
            let source = marker
                .as_ref()
                .and_then(|row| row.get("server_command"))
                .and_then(Value::as_str)
                .and_then(marker_source)
                .filter(|source| source.identity_hash() == update.identity_hash);
            let Some(source) = source else {
                return value_error("invalid provider authority identity");
            };
            if source.action_selector(slug).is_none() {
                return value_error("invalid provider action identity");
            }
            exec(
                self.connection,
                "insert into local_mcp_provider_grant values (?, ?, ?, ?, ?) \
                 on conflict(cli_id, identity_hash, tool_slug) do update set \
                 state = excluded.state, updated_at = excluded.updated_at",
                &[
                    Value::from(update.cli_id),
                    Value::from(update.identity_hash),
                    Value::from(slug),
                    Value::from(state),
                    Value::from(self.updated_at),
                ],
            )?;
        }
        Ok(())
    }

    /// `store_local_cli_capabilities.write_local_cli_capabilities`. Refusals
    /// are `LocalCliCapabilityError` messages the caller re-raises by name.
    pub(super) fn write_capabilities(
        &self,
        cli_id: &str,
        choices: &Map<String, Value>,
        revision: i64,
    ) -> StoreResult<()> {
        if choices.len() > CAPABILITIES.len() {
            return value_error("invalid_capabilities");
        }
        let mut checked = Vec::with_capacity(choices.len());
        for (name, state) in choices {
            let state = state
                .as_str()
                .filter(|state| matches!(*state, "on" | "off"));
            let Some(state) = state.filter(|_| CAPABILITIES.contains(&name.as_str())) else {
                return value_error("invalid_capabilities");
            };
            checked.push((name.as_str(), state));
        }
        if checked.is_empty() {
            return Ok(());
        }
        if self.surface(cli_id)?.as_deref() != Some("cli") {
            return value_error("capabilities_require_cli_surface");
        }
        if checked.iter().any(|(_, state)| *state == "on") {
            let grant = query_one(
                self.connection,
                "select state from local_cli_grant where cli_id = ?",
                &[Value::from(cli_id)],
            )?;
            if grant.as_ref().map(|row| text(row, "state")) != Some("allowed") {
                return value_error("capabilities_require_allowed_grant");
            }
        }
        // `Map` iterates in key order, matching Python's `sorted(...)`.
        for (name, state) in &checked {
            exec(
                self.connection,
                "insert into local_cli_grant_capability \
                 (cli_id, capability, state, revision, updated_at) values (?, ?, ?, ?, ?) \
                 on conflict(cli_id, capability) do update set state = excluded.state, \
                 revision = excluded.revision, updated_at = excluded.updated_at",
                &[
                    Value::from(cli_id),
                    Value::from(*name),
                    Value::from(*state),
                    Value::from(revision),
                    Value::from(self.updated_at),
                ],
            )?;
        }
        self.clear_resolved_causes(cli_id, &checked)
    }

    /// `_clear_resolved_causes`: drop a blocked cause once the capability it
    /// points at is on.
    fn clear_resolved_causes(&self, cli_id: &str, checked: &[(&str, &str)]) -> StoreResult<()> {
        let causes: Vec<Value> = CAUSE_BY_CAPABILITY
            .iter()
            .filter(|(capability, _)| checked.contains(&(*capability, "on")))
            .map(|(_, cause)| Value::from(*cause))
            .collect();
        if causes.is_empty() {
            return Ok(());
        }
        let has_column = query_all(
            self.connection,
            "select name from pragma_table_info('local_cli_observation')",
            &[],
        )?
        .iter()
        .any(|row| text(row, "name") == "first_blocked_cause");
        if !has_column {
            return Ok(());
        }
        let marks = vec!["?"; causes.len()].join(", ");
        let mut params = vec![Value::from(cli_id)];
        params.extend(causes);
        exec(
            self.connection,
            &format!(
                "update local_cli_observation set first_blocked_cause = null \
                 where cli_id = ? and first_blocked_cause in ({marks})"
            ),
            &params,
        )?;
        Ok(())
    }
}
