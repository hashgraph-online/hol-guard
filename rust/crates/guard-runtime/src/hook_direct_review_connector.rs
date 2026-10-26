//! The connector a queued review waits on (`native_review_connector.py`).
//!
//! A review due only to non-recognition of a command that launches a local
//! CLI this device never allowed or blocked is a setup decision. The daemon
//! asks the resident's `local_cli_hook` operation for that connector
//! (`native_review_setup_connector`), which records the launch as it answers,
//! and then queues the row differently:
//!
//! - the row is grouped under the connector's `queue_group_id`, and its
//!   `extension_allow_hint` is the connector setup hint
//!   (`connector_setup_hint`, `extension_allow_hint.py`) instead of the
//!   extension hints;
//! - the agent is told the CLI is not set up on this device
//!   (`connector_agent_reason`), in the silent block and in the pause;
//! - once the row is stored, the review's context is recorded with the
//!   connector (`record_native_review_connector_context`, best effort), and
//!   the desktop setup notice is raised (`raise_connector_setup_notice`). The
//!   resident cannot raise a desktop notice, so it hands the stored request id
//!   and the CLI name to the evidence drain, which raises it.
//!
//! The lookup records an observation, so everything that could still leave
//! the review to the daemon is checked before it runs: a lookup the daemon
//! repeats would count the launch twice. Any shape whose request or text the
//! resident cannot reproduce byte for byte defers before the lookup, and a
//! lookup that fails defers after it.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use guard_command::hook_responses::Object;
use guard_contracts::{
    ConnectorSetupContextRequestV1, LocalCliHookRequestV1, CONNECTOR_SETUP_CONTEXT_REQUEST_SCHEMA,
    LOCAL_CLI_HOOK_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};

use super::super::consume::{repair_store_permissions, storage_gate};
use super::super::query::pre_tool_command;
use super::super::review_request::expanded_home;
use super::super::{Context, HookDirectDefer};
use crate::blocked_request_mode::connector_setup_reason;
use crate::guard_store_connector_context::{scrub_context_text, MAX_LABEL_CHARS};
use crate::local_cli_hook_contained::Refined;
use crate::local_store_read::STORE_FILE_NAME;
use hint::{observed_risk_classes, setup_hint};

/// `_CONNECTOR_FIELDS` (`local_cli_hook.py`).
const CONNECTOR_FIELDS: [&str; 5] = [
    "cli_id",
    "identity_hash",
    "name",
    "surface",
    "queue_group_id",
];
/// `_CONNECTOR_SURFACES` and `LOCAL_CONNECTOR_SURFACES`: a local CLI or
/// script, whose setup review is an ordinary approvable review.
const LOCAL_SURFACES: [&str; 2] = ["cli", "package-scripts"];
/// `CONNECTOR_SETUP_SURFACES` (`extension_allow_hint.py`).
const HINT_SURFACES: [&str; 3] = ["cli", "package-scripts", "mcp"];
const HINT_SCHEMA: &str = "guard.connector-setup-hint.v1";
/// `_MAX_CONNECTOR_TEXT`.
const MAX_HINT_TEXT: usize = 128;
/// `_MAX_RISK_CLASSES`.
const MAX_RISK_CLASSES: usize = 16;
/// The longest name `_SAFE_NAME` admits.
const MAX_NAME_CHARS: usize = 64;
/// `connector_display_name` for a name that is not a plain one.
const FALLBACK_NAME: &str = "this local CLI";
/// The lookup's surface whose label is longest, for the worst-case render.
const LONGEST_SURFACE: &str = "package-scripts";
/// A hook waits this long for a busy store before the daemon takes over.
const BUSY_TIMEOUT_MS: u64 = 250;
/// `_CONTEXT_SAFETY_MARGIN_SECONDS` and `_MIN_CONTEXT_BUDGET_SECONDS`.
const CONTEXT_SAFETY_MARGIN: Duration = Duration::from_millis(350);
const MIN_CONTEXT_BUDGET: Duration = Duration::from_millis(250);
/// The `local_cli_hook` action the lookup refines.
const REVIEW_ACTION: &str = "review";

/// `SetupConnector`: the connector the resident's lookup named.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Connector {
    cli_id: String,
    identity_hash: String,
    name: String,
    surface: String,
    queue_group_id: String,
}

impl Connector {
    /// `_setup_connector`: exactly the connector fields, each a non-empty
    /// string, a local surface, and a group under the connector's identity.
    fn parse(value: &Value) -> Option<Self> {
        let fields = value.as_object()?;
        if fields.len() != CONNECTOR_FIELDS.len() {
            return None;
        }
        let text = |key: &str| -> Option<String> {
            match fields.get(key)? {
                Value::String(text) if !text.is_empty() => Some(text.clone()),
                _ => None,
            }
        };
        let connector = Self {
            cli_id: text("cli_id")?,
            identity_hash: text("identity_hash")?,
            name: text("name")?,
            surface: text("surface")?,
            queue_group_id: text("queue_group_id")?,
        };
        let group = format!("connector:{}:", connector.identity_hash);
        (LOCAL_SURFACES.contains(&connector.surface.as_str())
            && connector.queue_group_id.starts_with(&group))
        .then_some(connector)
    }

    /// `connector_display_name`.
    fn display_name(&self) -> String {
        let name = crate::guard_store_json::py_strip(&self.name);
        if safe_name(name) {
            name.to_owned()
        } else {
            FALLBACK_NAME.to_owned()
        }
    }

    /// `connector_is_local`.
    fn is_local(&self) -> bool {
        LOCAL_SURFACES.contains(&self.surface.as_str())
    }

    /// The setup text the agent sees instead of the review's, or `None` when
    /// the ordinary review text applies: only an exact-action Always allow
    /// can release a local row without a retry binding, and that text says
    /// so.
    fn reason(&self, ask: bool, bound: bool, exact: bool) -> Option<String> {
        if self.is_local() && !bound && exact {
            return None;
        }
        Some(connector_setup_reason(
            &self.display_name(),
            &self.surface,
            ask && (bound || exact),
            &[],
            bound,
        ))
    }
}

/// `_SAFE_NAME.fullmatch`: `[A-Za-z0-9@][A-Za-z0-9._@+/-]{0,63}`.
fn safe_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric() || first == '@')
        && name.chars().count() <= MAX_NAME_CHARS
        && chars.all(|item| item.is_ascii_alphanumeric() || "._@+/-".contains(item))
}

/// The setup reason the agent could be shown before the lookup names the
/// connector: the longest any local connector yields for these flags, so a
/// review whose render fits it fits the real one.
pub(super) fn longest_reason(ask: bool, bound: bool, exact: bool) -> Option<String> {
    Connector {
        cli_id: String::new(),
        identity_hash: String::new(),
        name: "@".repeat(MAX_NAME_CHARS),
        surface: LONGEST_SURFACE.to_owned(),
        queue_group_id: String::new(),
    }
    .reason(ask, bound, exact)
}

/// Whether the agent text links the queued row: only when the user's
/// approval can release it, and in the default mode never for an MCP setup
/// review; a local CLI or script one links like any other review.
pub(super) fn links(setup: Option<&Setup>, ask: bool, bound: bool, exact: bool) -> bool {
    let setup_reason = setup.and_then(|setup| setup.reason(ask, bound, exact));
    links_connector(
        setup.map(|setup| &setup.connector),
        setup_reason.as_deref(),
        ask,
        bound,
        exact,
    )
}

fn links_connector(
    connector: Option<&Connector>,
    setup_reason: Option<&str>,
    ask: bool,
    bound: bool,
    exact: bool,
) -> bool {
    (bound || exact)
        && (ask || setup_reason.is_none() || connector.is_some_and(Connector::is_local))
}

/// A prepared lookup: the `local_cli_hook` request the daemon would send, and
/// the facts the queue needs once it names a connector.
pub(super) struct Lookup {
    request: LocalCliHookRequestV1,
    risk_classes: Vec<String>,
    cause: &'static str,
    harness: Option<String>,
    workspace_label: Option<String>,
}

/// The connector a queued review waits on, with what its row and context
/// record carry.
pub(super) struct Setup {
    connector: Connector,
    hint: Value,
    cause: &'static str,
    harness: Option<String>,
    workspace_label: Option<String>,
}

/// The lookup `native_review_setup_connector` would make for this review, or
/// `None` when the review is not a setup candidate. Every request field is
/// checked to be the daemon's spelling; anything else defers.
pub(super) fn prepare(
    context: &Context<'_>,
    result: &Object,
    environment: &BTreeMap<String, String>,
    oauth_source: &str,
) -> Result<Option<Lookup>, HookDirectDefer> {
    let defer = HookDirectDefer::ReviewQueue;
    let reason_code = match result.get("reason_code") {
        // `in frozenset` raises on an unhashable code.
        Some(Value::Array(_) | Value::Object(_)) => return Err(defer),
        Some(Value::String(code)) => Some(code.as_str()),
        _ => None,
    };
    if !crate::connector_setup::is_non_recognition(reason_code) {
        return Ok(None);
    }
    let cause = first_blocked_cause(reason_code).ok_or(defer)?;
    let payload = context.recorded_payload;
    // `Path.resolve` raises on an embedded NUL, which the daemon does not catch.
    if matches!(payload.get("cwd"), Some(Value::String(cwd)) if cwd.contains('\0')) {
        return Err(defer);
    }
    let command = pre_tool_command(payload).map_err(|_| defer)?;
    let cwd = crate::hook_direct::local_cli::launch_cwd(payload, context.workspace)
        .map_err(|()| defer)?;
    let (Some(command), Some(cwd)) = (command, cwd) else {
        return Ok(None);
    };
    // A daemon whose drain cannot raise the setup notice keeps every review
    // it would look up; one with no command or launch directory it never does.
    if context.binding.connector_setup_notice != Some(true) {
        return Err(defer);
    }
    // `str(cwd)`, `str(home_dir)` and `str(Path.home())` are pathlib's
    // spellings; a Windows verbatim path or any other spelling defers.
    if !pathlib_normal(&cwd) || !pathlib_normal(context.home_dir) {
        return Err(defer);
    }
    let user_home = expanded_home(environment)
        .filter(|home| pathlib_normal(home))
        .ok_or(defer)?;
    // `_launch_env`: the daemon's environment with the agent's `PATH`.
    let mut env = environment.clone();
    if let Some(path) = launch_path(payload) {
        env.insert("PATH".to_owned(), path.to_owned());
    }
    let risk_classes = observed_risk_classes(result)?;
    let harness = label(context.harness)?;
    if !pathlib_normal(context.workspace) {
        return Err(defer);
    }
    let workspace_label = label(pathlib_name(context.workspace))?;
    let request_id = super::request_id().ok_or(defer)?;
    let guard_home = Path::new(context.guard_home);
    Ok(Some(Lookup {
        request: LocalCliHookRequestV1 {
            schema: LOCAL_CLI_HOOK_REQUEST_SCHEMA.to_owned(),
            request_id: format!("local-cli-hook-{request_id}"),
            store_path: guard_home
                .join(STORE_FILE_NAME)
                .to_string_lossy()
                .into_owned(),
            guard_home: context.guard_home.to_owned(),
            source: oauth_source.to_owned(),
            busy_timeout_ms: BUSY_TIMEOUT_MS,
            command,
            cwd,
            home_dir: Some(context.home_dir.to_owned()),
            user_home,
            env,
            current_action: REVIEW_ACTION.to_owned(),
            current_reason_code: None,
            grant_allowed: true,
        },
        risk_classes,
        cause,
        harness,
        workspace_label,
    }))
}

impl Lookup {
    /// `local_cli_setup_connector`: asks the store under the shared storage
    /// gate, as the daemon's resident call does. The call records the launch,
    /// so it runs only once nothing but the write can defer. A failed lookup
    /// defers.
    pub(super) fn run(self, guard_home: &str) -> Result<Option<Setup>, HookDirectDefer> {
        let home = Path::new(guard_home);
        let gate = storage_gate(home).map_err(|_| HookDirectDefer::ReviewQueue)?;
        let refined = crate::local_cli_hook_op::run_refined(&self.request);
        drop(gate);
        repair_store_permissions(home);
        Ok(from_refined(refined)?.map(|connector| Setup {
            hint: setup_hint(&connector, &self.risk_classes),
            connector,
            cause: self.cause,
            harness: self.harness,
            workspace_label: self.workspace_label,
        }))
    }
}

/// The connector a `review` reply names, as `_native_local_cli_hook_reply`
/// accepts it: a reply that holds a grant or changes the action names none.
fn from_refined(
    refined: Result<Refined, &'static str>,
) -> Result<Option<Connector>, HookDirectDefer> {
    let refined = refined.map_err(|_| HookDirectDefer::ReviewQueue)?;
    if refined.action != REVIEW_ACTION || refined.contained_grant.is_some() {
        return Ok(None);
    }
    Ok(refined.connector.as_ref().and_then(Connector::parse))
}

impl Setup {
    /// `connector_agent_reason`, or `None` for the ordinary review text.
    pub(super) fn reason(&self, ask: bool, bound: bool, exact: bool) -> Option<String> {
        self.connector.reason(ask, bound, exact)
    }

    /// The row as `queue_native_pre_tool_review` writes it for a connector:
    /// its group and its setup hint, in place of the extension hints.
    pub(super) fn apply(&self, mut request: Value) -> Value {
        if let Some(fields) = request.as_object_mut() {
            fields.insert(
                "queue_group_id".to_owned(),
                json!(self.connector.queue_group_id),
            );
            fields.insert("extension_allow_hint".to_owned(), self.hint.clone());
        }
        request
    }

    /// Records the review's context with the connector, best effort, and
    /// returns the desktop notice the evidence drain raises for the stored
    /// row.
    pub(super) fn stored(
        &self,
        context: &Context<'_>,
        oauth_source: &str,
        stored_id: &str,
    ) -> Value {
        record_context(context, self, oauth_source);
        json!({
            "request_id": stored_id,
            "connector_name": self.connector.display_name(),
        })
    }
}

/// `record_native_review_connector_context`: skipped when the hook has too
/// little time left, and any failure only leaves the connector without
/// context. The stored row carries no trigger summary or reason of its own,
/// so neither is sent.
fn record_context(context: &Context<'_>, setup: &Setup, oauth_source: &str) {
    if let Some(scope) = context.hint {
        let left = scope.deadline.saturating_duration_since(Instant::now());
        if left < CONTEXT_SAFETY_MARGIN + MIN_CONTEXT_BUDGET {
            return;
        }
    }
    let (Some(observed_at), Some(request_id)) = (
        super::super::super::lifecycle::utc_now_isoformat(),
        super::request_id(),
    ) else {
        return;
    };
    let guard_home = Path::new(context.guard_home);
    let request = ConnectorSetupContextRequestV1 {
        schema: CONNECTOR_SETUP_CONTEXT_REQUEST_SCHEMA.to_owned(),
        request_id: format!("connector-setup-context-{request_id}"),
        store_path: guard_home
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: context.guard_home.to_owned(),
        source: oauth_source.to_owned(),
        busy_timeout_ms: BUSY_TIMEOUT_MS,
        cli_id: setup.connector.cli_id.clone(),
        identity_hash: setup.connector.identity_hash.clone(),
        first_blocked_cause: Some(setup.cause.to_owned()),
        trigger_summary: None,
        why_now: None,
        harness: setup.harness.clone(),
        workspace_label: setup.workspace_label.clone(),
        observed_at,
    };
    let Ok(gate) = storage_gate(guard_home) else {
        return;
    };
    let _ = crate::connector_setup_context_op::evaluate_connector_setup_context_request(&request);
    drop(gate);
    repair_store_permissions(guard_home);
}

/// `_FIRST_CAUSE_BY_REASON_CODE`.
fn first_blocked_cause(reason_code: Option<&str>) -> Option<&'static str> {
    match reason_code? {
        "native_workspace_containment_executable_outside_roots" => Some("exec_outside_roots"),
        "native_command_review_required" => Some("unrecognised_tool"),
        _ => None,
    }
}

/// `launch_path`: the `PATH` the hook stamped from the agent's environment.
fn launch_path(payload: &Map<String, Value>) -> Option<&str> {
    payload
        .get(crate::hook_direct::EXECUTION_ENVIRONMENT_FIELD)?
        .get("path")?
        .as_str()
        .filter(|path| !path.is_empty() && !path.contains('\0'))
}

/// `scrub_connector_context_text(value, limit=MAX_LABEL_CHARS)`, the scrub
/// the daemon applies before it sends a label. Only printable ASCII is
/// scrubbed here, where Python's and the resident's character classes agree;
/// any other label defers.
fn label(text: &str) -> Result<Option<String>, HookDirectDefer> {
    if !text.chars().all(|item| (' '..='~').contains(&item)) {
        return Err(HookDirectDefer::ReviewQueue);
    }
    Ok(scrub_context_text(text, MAX_LABEL_CHARS))
}

/// Whether `str(Path(path)) == path`: an absolute path with no empty or `.`
/// component and no trailing separator.
#[cfg(not(windows))]
fn pathlib_normal(path: &str) -> bool {
    path == "/"
        || path
            .strip_prefix('/')
            .is_some_and(|rest| rest.split('/').all(|part| !part.is_empty() && part != "."))
}

/// Whether `str(Path(path)) == path` for a drive-letter path: `X:\` and
/// components with no empty or `.` one. A UNC, verbatim or `/` spelling is
/// not reproduced.
#[cfg(windows)]
fn pathlib_normal(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || path.contains('/')
    {
        return false;
    }
    let rest = &path[3..];
    rest.is_empty() || rest.split('\\').all(|part| !part.is_empty() && part != ".")
}

/// `Path(path).name` for a path [`pathlib_normal`] accepts.
fn pathlib_name(path: &str) -> &str {
    let separator = if cfg!(windows) { '\\' } else { '/' };
    path.rsplit(separator).next().unwrap_or_default()
}

#[path = "hook_direct_review_connector_hint.rs"]
mod hint;

#[cfg(test)]
#[path = "hook_direct_review_connector_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "hook_direct_review_connector_prepare_tests.rs"]
mod prepare_tests;
