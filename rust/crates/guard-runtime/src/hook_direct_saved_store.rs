//! Store shape probes shared by the resident saved-decision paths.

use super::HookDirectDefer;
use crate::local_store_read::{schema_version, table_exists, SUPPORTED_SCHEMA_VERSION};
use crate::policy_bundle_store_identities::{cached_bundle_authority, BundleAuthority};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;

const REMOTE_SOURCES_SQL: &str = "('cloud-sync', 'team-policy', 'policy-bundle', \
     'policy-bundle-canonical', 'cloud-signed-memory')";

/// The store, as the daemon's lookup would read it.
pub(super) struct StoreShape<'a> {
    pub(super) connection: &'a Connection,
    pub(super) harness: &'a str,
    pub(super) artifact_id: &'a str,
}

impl StoreShape<'_> {
    /// Whether the daemon reads this store's decisions as the resident does.
    pub(super) fn supported(&self) -> Result<bool, HookDirectDefer> {
        let unavailable = |_| HookDirectDefer::SavedDecision;
        Ok(matches!(
            schema_version(self.connection).map_err(unavailable)?,
            Some(version) if version <= SUPPORTED_SCHEMA_VERSION
        ))
    }

    /// Whether the store holds any custom grant or block rule.
    pub(super) fn grants(&self) -> Result<bool, HookDirectDefer> {
        let unavailable = |_| HookDirectDefer::SavedDecision;
        for table in ["local_cli_grant", "local_cli_command_grant"] {
            if table_exists(self.connection, table).map_err(unavailable)?
                && self.any(&format!("select 1 from {table} limit 1"), &[])?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The daemon's decision probe for `token`, or for any token when the
    /// resident could not derive one.
    pub(super) fn decided(&self, token: Option<&str>) -> Result<bool, HookDirectDefer> {
        let artifact = "select 1 from policy_decisions where harness in (?1, '*') \
                        and scope = 'artifact' and artifact_id = ?2";
        match token {
            Some(token) => self.any(
                &format!("{artifact} and artifact_hash = ?3 limit 1"),
                &[self.harness, self.artifact_id, token],
            ),
            None => self.any(
                &format!("{artifact} limit 1"),
                &[self.harness, self.artifact_id],
            ),
        }
    }

    /// Whether the store holds a local decision under the published integrity
    /// state. `None` means the state cannot be read or does not match.
    pub(super) fn readable(
        &self,
        integrity_state: &Value,
    ) -> Result<Option<bool>, HookDirectDefer> {
        let has_local_policy = self.any(
            &format!(
                "select 1 from policy_decisions where source not in {REMOTE_SOURCES_SQL} limit 1"
            ),
            &[],
        )?;
        let stored: Option<String> = self
            .connection
            .query_row(
                "select payload_json from sync_state where state_key = 'policy_integrity'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| HookDirectDefer::SavedDecision)?;
        let stored = stored.and_then(|text| serde_json::from_str::<Value>(&text).ok());
        Ok((stored.as_ref() == Some(integrity_state)).then_some(has_local_policy))
    }

    /// The decision identities the cached signed bundle authorizes at `now`.
    pub(super) fn bundle_authority(&self, now: &str) -> Result<BundleAuthority, HookDirectDefer> {
        if !self.any(
            "select 1 from policy_decisions where source = 'policy-bundle' limit 1",
            &[],
        )? {
            return Ok((Vec::new(), None));
        }
        #[cfg(test)]
        if let Some(authority) =
            crate::cloud_exception_lift::VALIDATED_BUNDLE.with(|bundle| bundle.borrow().clone())
        {
            return Ok(authority);
        }
        cached_bundle_authority(self.connection, now).ok_or(HookDirectDefer::SavedDecision)
    }

    fn any(&self, query: &str, values: &[&str]) -> Result<bool, HookDirectDefer> {
        self.connection
            .query_row(query, rusqlite::params_from_iter(values.iter()), |_| Ok(()))
            .optional()
            .map(|found| found.is_some())
            .map_err(|_| HookDirectDefer::SavedDecision)
    }
}
