//! The desktop notices for reviews the resident queued.
//!
//! A connector-setup review's answer names the stored row and the CLI, and the
//! drain raises the notice from the stored row as `notify_connector_setup`
//! does. An MCP call the relay blocks on an approval request it wrote raises
//! that request's notice as soon as the request is written, from the persisted
//! fields `_QueuedNotice` reads, as `_notify_pending_approval` does.
//!
//! Either way a notice is shown only while desktop notifications are on, once
//! per request (once per connector: the store answers a request with its first
//! notified sibling's marker), with the approval link signed in, and is marked
//! on the row once it is shown. A notice is best effort, as the daemon's is:
//! the row is in the Inbox either way, so a notice that cannot be shown is not
//! retried.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use guard_command::local_supply_chain::Timestamp;
use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use crate::hook_direct::CONNECTOR_NOTICE_FIELD;
use crate::local_store_read::STORE_FILE_NAME;
use crate::native_review_link::{approval_browser_url, now_micros, APPROVAL_CENTER_SURFACE};

/// The drain raised the connector-setup notice this record names.
pub(super) const NOTICE_RAISED: &str = "connector_notice_raised";
const BUSY_TIMEOUT_MS: u64 = 250;
const TITLE: &str = "HOL Guard: a connector needs setup";
const APPROVAL_TITLE: &str = "HOL Guard needs approval";
const MAX_MESSAGE_CHARS: usize = 180;

/// `_NOTIFIED_APPROVAL_IDS` and `_NOTIFICATION_ATTEMPTS_IN_FLIGHT`: a
/// request this process has shown or is showing.
static NOTIFIED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// The stored request and CLI a record's notice names, unless the drain
/// already raised it.
pub(super) fn pending(record: &Value) -> Option<(String, String)> {
    if record.get(NOTICE_RAISED) == Some(&Value::Bool(true)) {
        return None;
    }
    let notice = record.get(CONNECTOR_NOTICE_FIELD)?;
    let request_id = text(notice.get("request_id"))?;
    let connector_name = text(notice.get("connector_name"))?;
    Some((request_id, connector_name))
}

/// One notice the drain raises.
pub(super) enum Notice {
    /// A connector-setup review, read from its stored row.
    Connector {
        request_id: String,
        connector_name: String,
    },
    /// A request an MCP call was blocked on, as its record names it.
    Approval(Shown),
}

/// `_QueuedNotice`: the persisted request fields a notice reads.
#[derive(Debug, PartialEq)]
pub(super) struct Shown {
    request_id: String,
    harness: String,
    workspace: Option<String>,
    approval_url: String,
    /// `risk_headline or trigger_summary or artifact_name`.
    subject: String,
    connector: bool,
}

/// Raise the notice of the request an MCP call was just blocked on, from the
/// persisted fields `_QueuedNotice` reads. A notice the daemon could not read
/// is left to the daemon, and says so by returning `false`.
pub(crate) fn raise_approval(guard_home: &str, source: &str, notice: &Value) -> bool {
    raise_approvals(guard_home, source, std::slice::from_ref(notice))
}

/// Raise the notices of the requests one call was just queued on, in order.
/// Unless every notice reads, none is raised and all are left to the daemon.
pub(crate) fn raise_approvals(guard_home: &str, source: &str, notices: &[Value]) -> bool {
    let Some(shown) = approval_notices(notices) else {
        return false;
    };
    raise(
        guard_home,
        source,
        shown.into_iter().map(Notice::Approval).collect(),
    );
    true
}

/// Every notice of one call, in order, or none when any is unreadable.
fn approval_notices(notices: &[Value]) -> Option<Vec<Shown>> {
    notices.iter().map(approval_notice).collect()
}

fn approval_notice(notice: &Value) -> Option<Shown> {
    let field = |key: &str| text(notice.get(key));
    let workspace = match notice.get("workspace") {
        Some(Value::String(workspace)) => Some(workspace.clone()),
        Some(Value::Null) => None,
        _ => return None,
    };
    let subject = field("risk_headline")
        .or_else(|| field("trigger_summary"))
        .or_else(|| field("artifact_name"))
        .unwrap_or_default();
    Some(Shown {
        request_id: field("request_id")?,
        harness: field("harness")?,
        workspace,
        approval_url: field("approval_url")?,
        subject,
        connector: false,
    })
}

/// Raise notices one after another on a thread of their own, so neither the
/// drain nor a blocked call waits on the notifier.
pub(super) fn raise(guard_home: &str, source: &str, notices: Vec<Notice>) {
    if notices.is_empty() {
        return;
    }
    let (guard_home, source) = (guard_home.to_owned(), source.to_owned());
    let _ = std::thread::Builder::new()
        .name("hol-guard-approval-notice".to_owned())
        .spawn(move || {
            for notice in notices {
                notify(&guard_home, &source, notice);
            }
        });
}

fn notify(guard_home: &str, source: &str, notice: Notice) {
    if disabled_by_env() {
        return;
    }
    let shown = match notice {
        Notice::Connector {
            request_id,
            connector_name,
        } => match connector_row(guard_home, source, &request_id, connector_name) {
            Some(shown) => shown,
            None => return,
        },
        Notice::Approval(shown) => shown,
    };
    show(guard_home, source, shown);
}

/// The connector-setup notice of the stored row `request_id`.
fn connector_row(
    guard_home: &str,
    source: &str,
    request_id: &str,
    connector_name: String,
) -> Option<Shown> {
    let queued = store(guard_home, source, "get_approval_request", request_id, None)
        .filter(Value::is_object)?;
    let field = |key: &str| text(queued.get(key));
    Some(Shown {
        request_id: field("request_id")?,
        harness: field("harness")?,
        workspace: field("workspace"),
        approval_url: field("approval_url")?,
        connector: field("queue_group_id")?.starts_with("connector:"),
        subject: connector_name,
    })
}

fn show(guard_home: &str, source: &str, shown: Shown) {
    let Shown {
        request_id,
        harness,
        workspace,
        approval_url,
        subject,
        connector,
    } = shown;
    let home = Path::new(guard_home);
    // A configuration that cannot be read leaves notifications on, as the
    // daemon's `load_guard_config` failure does.
    if crate::guard_config_load::desktop_notifications(home, workspace.as_deref().map(Path::new))
        == Ok(false)
    {
        return;
    }
    // A request already shown, or one the store cannot answer for, is left.
    if store(
        guard_home,
        source,
        "approval_desktop_notified_at",
        &request_id,
        None,
    ) != Some(Value::Null)
    {
        return;
    }
    if !claim(&request_id) {
        return;
    }
    let approval_url = now_micros()
        .and_then(|micros| {
            approval_browser_url(
                &approval_url,
                || crate::daemon_policy_authority::load_guard_daemon_auth_token(home),
                APPROVAL_CENTER_SURFACE,
                micros,
            )
        })
        .unwrap_or(approval_url);
    let title = if connector { TITLE } else { APPROVAL_TITLE };
    let message = message(&harness, &subject, connector);
    let shown =
        crate::desktop_notification::send_approval(&request_id, title, &message, &approval_url);
    settle(&request_id, shown);
    if shown {
        let notified_at = Timestamp::now_utc().isoformat();
        store(
            guard_home,
            source,
            "mark_approval_desktop_notified",
            &request_id,
            Some(notified_at),
        );
    }
}

/// Take the request for this process, unless it was shown or is showing.
fn claim(request_id: &str) -> bool {
    let mut notified = NOTIFIED.lock().unwrap_or_else(PoisonError::into_inner);
    notified
        .get_or_insert_with(HashSet::new)
        .insert(request_id.to_owned())
}

/// A notice that was not shown lets a later record try again.
fn settle(request_id: &str, shown: bool) {
    if shown {
        return;
    }
    let mut notified = NOTIFIED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(notified) = notified.as_mut() {
        notified.remove(request_id);
    }
}

/// `_approval_notification_message`; a connector's subject is the CLI's name.
pub(super) fn message(harness: &str, subject: &str, connector: bool) -> String {
    let harness = title_case(&harness.replace('-', " "));
    let message = if connector {
        format!("{harness} is waiting on a connector Guard has not set up yet: {subject}")
    } else {
        format!("{harness} wants approval: {subject}")
    };
    if message.chars().count() <= MAX_MESSAGE_CHARS {
        return message;
    }
    let head: String = message.chars().take(MAX_MESSAGE_CHARS - 3).collect();
    format!("{}...", head.trim_end())
}

/// `str.title`: a letter after a letter is lowered, any other is raised.
fn title_case(text: &str) -> String {
    let mut after_letter = false;
    let mut titled = String::with_capacity(text.len());
    for character in text.chars() {
        if after_letter {
            titled.extend(character.to_lowercase());
        } else {
            titled.extend(character.to_uppercase());
        }
        after_letter = character.is_alphabetic();
    }
    titled
}

/// `HOL_GUARD_DESKTOP_NOTIFICATIONS` set to an off value.
fn disabled_by_env() -> bool {
    std::env::var("HOL_GUARD_DESKTOP_NOTIFICATIONS").is_ok_and(|value| {
        matches!(
            value.trim().to_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        )
    })
}

fn store(
    guard_home: &str,
    source: &str,
    method: &str,
    request_id: &str,
    notified_at: Option<String>,
) -> Option<Value> {
    let mut args = Map::from_iter([("request_id".to_owned(), json!(request_id))]);
    if let Some(notified_at) = notified_at {
        args.insert("notified_at".to_owned(), json!(notified_at));
    }
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "direct-connector-notice".to_owned(),
        store_path: Path::new(guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: guard_home.to_owned(),
        method: method.to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: BUSY_TIMEOUT_MS,
        args,
    };
    crate::guard_store_op::evaluate(&request)
        .ok()
        .map(|(value, _)| value)
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "hook_direct_evidence_notice_tests.rs"]
mod tests;
