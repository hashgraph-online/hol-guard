//! The local CLI grant a contained run is widened by.
//!
//! The sink never trusts a grant it was handed: it asks this device's store
//! itself when it prepares the plan, admits only a plan widened by exactly
//! that grant, and asks again after the second receipt. A blocked CLI stops
//! the run; a grant that changed in between, in any field, stops it too. A
//! store that cannot be asked decides no grant, and the run keeps the base
//! sandbox, which a grant only ever widens: the Python sink does the same.
//!
//! The direct lane needs no grant routing: it sends a workspace sandbox
//! requirement here as before. An outside-roots review is never answered
//! there, because it is not a workspace requirement: it defers, and the daemon
//! routes a granted one to the Python sink after it turns the review into the
//! workspace requirement. Linux plans carry no capability.

use std::collections::BTreeMap;

use guard_contracts::{LocalCliHookRequestV1, LOCAL_CLI_HOOK_REQUEST_SCHEMA};

use super::*;
use crate::contained_workspace_grant_plan::ExpectedGrant;
use crate::local_cli_hook_contained::{grant_capabilities, ALLOW_CONTAINED_WITH_GRANT};

pub(super) const GRANT_CHANGED: &str = "The local CLI grant changed before launch.";
const GRANT_BLOCKED: &str = "This device blocked the local CLI this command launches.";
const STORE_BUSY_MILLISECONDS: u64 = 2_000;

/// The store question the hook asked, asked again for a sandbox requirement.
pub(super) fn request(
    guard_home: &Path,
    home: &str,
    workspace: &str,
    command: &str,
) -> Outcome<LocalCliHookRequestV1> {
    let guard_home = path_text(guard_home)?;
    let env: BTreeMap<String, String> = environment().into_iter().collect();
    Ok(LocalCliHookRequestV1 {
        schema: LOCAL_CLI_HOOK_REQUEST_SCHEMA.to_owned(),
        request_id: SINK_COMMAND.to_owned(),
        store_path: format!("{}/guard.db", guard_home.trim_end_matches('/')),
        guard_home,
        // Nothing is recorded here, so the store's source is never read.
        source: String::new(),
        busy_timeout_ms: STORE_BUSY_MILLISECONDS,
        command: command.to_owned(),
        cwd: workspace.to_owned(),
        home_dir: Some(home.to_owned()),
        user_home: home.to_owned(),
        env,
        current_action: "sandbox-required".to_owned(),
        current_reason_code: Some(WORKSPACE_REASON.to_owned()),
        grant_allowed: true,
    })
}

/// The grant the store decides for `request` now: `None` runs the base
/// sandbox, as it does when the store cannot be asked; a blocked CLI stops
/// the run.
pub(super) fn decided(request: &LocalCliHookRequestV1) -> Outcome<Option<Value>> {
    let Ok(refined) = crate::local_cli_hook_op::decide_refined(request) else {
        return Ok(None);
    };
    match (refined.action.as_str(), refined.contained_grant) {
        (ALLOW_CONTAINED_WITH_GRANT, Some(grant)) => Ok(Some(grant)),
        ("block", _) => Err(Failure::new(AUTHORIZATION_FAILED, GRANT_BLOCKED)),
        ("sandbox-required", None) => Ok(None),
        _ => Err(Failure::unauthorized()),
    }
}

/// The `grant` field of the prepare input: `GrantInput`.
pub(super) fn prepare_input(grant: &Value) -> Value {
    json!({
        "identity_hash": grant["identity_hash"],
        "name": grant["name"],
        "capabilities": grant["capabilities"],
    })
}

/// What the plan must carry for `grant`; the state directory is the one the
/// command crate derives, `<canonical home>/.<name>`.
pub(super) fn expected(grant: &Value, home: &str) -> Outcome<ExpectedGrant> {
    let invalid = || Failure::invalid(INVALID_PLAN);
    let identity_hash = grant["identity_hash"]
        .as_str()
        .ok_or_else(invalid)?
        .to_owned();
    let capabilities = grant_capabilities(&grant["capabilities"]).map_err(|()| invalid())?;
    let stateful = capabilities
        .iter()
        .any(|name| name.starts_with("state-dir-"));
    let state_dir = match (stateful, grant["name"].as_str()) {
        (false, _) => None,
        (true, Some(name)) => std::fs::canonicalize(home)
            .ok()
            .and_then(|home| home.join(format!(".{name}")).to_str().map(str::to_owned)),
        (true, None) => return Err(invalid()),
    };
    Ok(ExpectedGrant {
        identity_hash,
        capabilities,
        state_dir,
    })
}

/// Make the CLI's state directory reachable where it looks for it, under the
/// private home the run's `HOME` names: a link to the one directory the grant
/// opened, so the CLI finds its saved state and the rest of the real home
/// stays out of reach. Nothing is linked without a state capability in the
/// plan, or for a directory that does not exist yet or is itself a link.
pub(super) fn link_state(
    private: &Path,
    expected: Option<&ExpectedGrant>,
    capabilities: &Value,
) -> Outcome<()> {
    let stateful = capabilities.as_array().is_some_and(|names| {
        names.iter().any(|name| {
            name.as_str()
                .is_some_and(|name| name.starts_with("state-dir-"))
        })
    });
    let Some(state) = expected
        .filter(|_| stateful)
        .and_then(|expected| expected.state_dir.as_deref())
        .map(Path::new)
    else {
        return Ok(());
    };
    let name = state
        .file_name()
        .ok_or_else(|| Failure::invalid(INVALID_PLAN))?;
    if !std::fs::symlink_metadata(state).is_ok_and(|meta| meta.file_type().is_dir()) {
        return Ok(());
    }
    std::os::unix::fs::symlink(state, private.join("home").join(name)).map_err(|_| {
        Failure::new(
            SANDBOX_UNAVAILABLE,
            "The workspace sandbox directory is unavailable.",
        )
    })
}

/// Records a loopback denial as the latest cause, so Protect points at the
/// access the most recent denied run lacked.
const REPLACEABLE_CAUSE_SQL: &str = "update local_cli_observation \
     set first_blocked_cause = 'connect_loopback' \
     where cli_id = ?1 and identity_hash = ?2 and surface = 'cli' \
     and first_blocked_cause is not 'connect_loopback'";

/// Remembers that a granted run failed on a blocked connection to this
/// machine, so Protect can suggest local network access. It changes no
/// grant and turns on nothing: only an admin preview and apply does that.
pub(super) struct LoopbackNote<'a> {
    store_path: &'a str,
    grant: Option<(&'a str, &'a str)>,
}

impl<'a> LoopbackNote<'a> {
    pub(super) fn new(store: &'a LocalCliHookRequestV1, grant: Option<&'a Value>) -> Self {
        // A grant that already has local network access needs no suggestion.
        let grant = grant
            .filter(|grant| {
                grant["capabilities"]
                    .as_array()
                    .is_none_or(|names| !names.iter().any(|name| name == "loopback-network"))
            })
            .and_then(|grant| Some((grant["cli_id"].as_str()?, grant["identity_hash"].as_str()?)));
        Self {
            store_path: &store.store_path,
            grant,
        }
    }

    /// Best effort: the run's own result never depends on this write.
    pub(super) fn keep(&self) {
        let Some((cli_id, identity_hash)) = self.grant else {
            return;
        };
        let Ok(connection) = rusqlite::Connection::open_with_flags(
            self.store_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) else {
            return;
        };
        let _ = keep_loopback_cause(&connection, cli_id, identity_hash);
    }
}

fn keep_loopback_cause(
    connection: &rusqlite::Connection,
    cli_id: &str,
    identity_hash: &str,
) -> rusqlite::Result<usize> {
    connection.busy_timeout(Duration::from_millis(STORE_BUSY_MILLISECONDS))?;
    connection.execute(
        REPLACEABLE_CAUSE_SQL,
        rusqlite::params![cli_id, identity_hash],
    )
}

/// Fails unless the store still decides `first` for the command.
pub(super) fn unchanged(first: &Option<Value>, now: Outcome<Option<Value>>) -> Outcome<()> {
    match now {
        Ok(now) if now == *first => Ok(()),
        _ => Err(Failure::invalid(GRANT_CHANGED)),
    }
}

#[cfg(test)]
#[path = "contained_workspace_sink_grant_tests.rs"]
mod tests;
