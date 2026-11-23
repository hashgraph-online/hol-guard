//! The two local-CLI migrations that rebuild authority rows from stored
//! catalogs: version 9 to 10 for provider actions and version 10 to 11 for
//! MCP tools. Both reuse the rebuilds the live catalog writes run.

use rusqlite::Connection;

use crate::guard_store_composio_catalog::rebuild_provider_authority;
use crate::guard_store_db::StoreResult;
use crate::guard_store_local_cli_mcp_snapshot::rebuild_tool_authority;

const PROVIDER_CONNECTIONS: &str =
    "select distinct cli_id, identity_hash from local_mcp_provider_action";
const TOOL_CATALOGS: &str =
    "select cli_id, identity_hash, catalog_json, revision from local_mcp_catalog";

/// Rebuild the provider authority digest of every stored connection.
pub(super) fn provider_authorities(connection: &Connection) -> StoreResult<()> {
    let connections = connection
        .prepare(PROVIDER_CONNECTIONS)?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (cli_id, identity_hash) in connections {
        rebuild_provider_authority(connection, &cli_id, &identity_hash)?;
    }
    Ok(())
}

/// Rebuild the tool authority rows of every stored MCP catalog.
pub(super) fn tool_authorities(connection: &Connection) -> StoreResult<()> {
    let catalogs = connection
        .prepare(TOOL_CATALOGS)?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (cli_id, identity_hash, raw, revision) in catalogs {
        rebuild_tool_authority(connection, &cli_id, &identity_hash, &raw, revision)?;
    }
    Ok(())
}
