//! Package-launcher equivalence for this-device MCP grants: a grant recorded
//! for `npx` still serves the same package launched through its absolute path.

use std::path::Path;

use guard_contracts::LocalMcpGrantRequestV1;
use rusqlite::Connection;

use crate::local_mcp_grant_identity::shlex_split;
use crate::local_mcp_grant_op::{text, Observation, STORE_UNAVAILABLE};

fn normalized_package_version(value: Option<&str>) -> String {
    match value.map(str::trim) {
        Some(version) if !version.is_empty() => version.to_owned(),
        _ => "latest".to_owned(),
    }
}

/// Match a this-device grant for the same package launcher and package.
pub(crate) fn equivalent_package_launcher_observation(
    connection: &Connection,
    request: &LocalMcpGrantRequestV1,
) -> Result<Option<Observation>, &'static str> {
    let server = &request.server;
    let home = request.launcher_home.as_deref().map(Path::new);
    let path_value = request.launcher_path.as_deref().unwrap_or("");
    let resolve = |command: &str| {
        guard_command::mcp_decision::resolved_package_launcher_executable_in(
            command, path_value, home,
        )
    };
    let Some(requested) = resolve(server.command.as_deref().unwrap_or("")) else {
        return Ok(None);
    };
    let runtime_package = server.package_name.as_deref().map_or("", str::trim);
    // Launcher aliases may be compatible, but they cannot substitute for a
    // configured account/environment binding. Exact hashes handle those cases.
    let expected = guard_command::mcp_decision::build_configured_environment_hash(None, None);
    if runtime_package.is_empty() || server.env_values_hash.as_deref() != Some(expected.as_str()) {
        return Ok(None);
    }
    let runtime_version = normalized_package_version(server.package_version.as_deref());
    let Some(runtime_source) = server
        .package_source
        .as_deref()
        .map(str::trim)
        .filter(|source| !source.is_empty())
    else {
        return Ok(None);
    };
    let mut statement = connection
        .prepare(
            "select o.cli_id, o.identity_hash, o.server_command, o.example_label \
             from local_cli_observation as o \
             join local_cli_grant as g on g.cli_id = o.cli_id and g.identity_hash = o.identity_hash \
             where o.surface = 'mcp' \
             order by case when g.state = 'blocked' then 0 else 1 end, o.last_seen_at desc, o.cli_id asc",
        )
        .map_err(|_| STORE_UNAVAILABLE)?;
    let mut rows = statement.query([]).map_err(|_| STORE_UNAVAILABLE)?;
    let mut matches = Vec::new();
    while let Some(row) = rows.next().map_err(|_| STORE_UNAVAILABLE)? {
        let (Some(cli_id), Some(identity_hash)) = (text(row, 0), text(row, 1)) else {
            continue;
        };
        let (server_command, example_label) = (text(row, 2), text(row, 3));
        let Some(stored) =
            observation_launch_identity(server_command.as_deref(), example_label.as_deref())
        else {
            continue;
        };
        if stored.identity_hash != identity_hash
            || stored.package_name.as_deref() != Some(runtime_package)
            || normalized_package_version(stored.package_version.as_deref()) != runtime_version
            || stored.package_source != runtime_source
        {
            continue;
        }
        if resolve(server_command.as_deref().unwrap_or("")).as_ref() == Some(&requested) {
            matches.push(Observation {
                cli_id,
                identity_hash,
            });
        }
    }
    Ok(if matches.len() == 1 {
        matches.pop()
    } else {
        None
    })
}

fn observation_launch_identity(
    server_command: Option<&str>,
    example_label: Option<&str>,
) -> Option<guard_command::mcp_decision::McpServerIdentity> {
    let label = example_label.filter(|label| !label.trim().is_empty())?;
    let parts = shlex_split(label)?;
    let first = parts.first()?;
    let command = server_command
        .filter(|command| !command.is_empty())
        .unwrap_or(first);
    Some(guard_command::mcp_decision::build_mcp_server_identity(
        "",
        command,
        &parts[1..],
        "stdio",
        None,
        &[],
    ))
}
