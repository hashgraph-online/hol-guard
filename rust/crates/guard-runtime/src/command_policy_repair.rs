//! Point a tampered command-policy block at the local repair page.
//!
//! `hook_policy_repair.py`. The hook never launches the CLI and never calls
//! authority recovery: a recent authenticator proof can satisfy that call, so
//! the blocked tool call must not rebuild protection. The deny reason carries
//! one signed loopback link instead. The person opens that page and presses
//! Repair protection; this tool call stays denied.
//!
//! The repair runs after the receipt is built, so the receipt keeps the
//! unrepaired reason, exactly as it did while the daemon worker composed this.

use std::path::Path;

use serde_json::{Map, Value};

use crate::native_review_link::{repair_page_url, RepairPage};

const AUTHORITY_BLOCK_REASON: &str = "native_command_control_authority_block";
/// `AuthorityHealth.TAMPERED` and `AuthorityHealth.RECOVERY_REQUIRED`. The
/// `degraded-*` healths keep the `recover-authority` hint the floor appends.
const REPAIRABLE_HEALTH: [&str; 2] = ["tampered", "recovery-required"];
const APPROVAL_REASON_PREFIX: &str = concat!(
    "HOL Guard blocked this action because trusted protection settings need repair. ",
    "Open this local page and press Repair protection: ",
);
const APPROVAL_REASON_WITHOUT_URL: &str = concat!(
    "HOL Guard blocked this action because trusted protection settings need repair. ",
    "Open HOL Guard Extensions and press Repair protection.",
);

/// Rewrite a repairable command-control authority block in place.
///
/// Everything else is left exactly as the native evaluation produced it,
/// including a block this module cannot compose a link for byte for byte.
pub(crate) fn apply(result: &mut Value, health: Option<&str>, guard_home: &Path) {
    let Some(object) = result.as_object() else {
        return;
    };
    if !repairable(object, health) {
        return;
    }
    let url = match repair_url(guard_home) {
        Ok(url) => url,
        Err(Unreproducible) => return,
    };
    let Some(object) = result.as_object_mut() else {
        return;
    };
    match url {
        Some(url) => {
            object.insert(
                "reason".to_owned(),
                Value::String(format!("{APPROVAL_REASON_PREFIX}{url}")),
            );
            object.insert("repair_url".to_owned(), Value::String(url));
        }
        None => {
            object.insert(
                "reason".to_owned(),
                Value::String(APPROVAL_REASON_WITHOUT_URL.to_owned()),
            );
            object.remove("repair_url");
        }
    }
    object.insert(
        "repair_status".to_owned(),
        Value::String("approval_required".to_owned()),
    );
}

fn repairable(object: &Map<String, Value>, health: Option<&str>) -> bool {
    let text = |key: &str| object.get(key).and_then(Value::as_str).unwrap_or_default();
    text("reason_code") == AUTHORITY_BLOCK_REASON
        && text("minimum_action") != "allow"
        && object.get("decision") != Some(&Value::String("allow".to_owned()))
        && health.is_some_and(|health| REPAIRABLE_HEALTH.contains(&health))
}

/// The page shape the daemon never writes, which Python would still sign.
struct Unreproducible;

fn repair_url(guard_home: &Path) -> Result<Option<String>, Unreproducible> {
    let Some(daemon_url) = crate::daemon_policy_authority::approval_center_daemon_url(guard_home)
        .filter(|url| !url.is_empty())
    else {
        return Ok(None);
    };
    let Some(now) = now_micros() else {
        return Ok(None);
    };
    let page = format!("{}/protection/repair", daemon_url.trim_end_matches('/'));
    match repair_page_url(
        &page,
        || crate::daemon_policy_authority::load_guard_daemon_auth_token(guard_home),
        now,
    ) {
        RepairPage::Signed(url) => Ok(Some(url)),
        RepairPage::Absent => Ok(None),
        RepairPage::Unreproducible => Err(Unreproducible),
    }
}

fn now_micros() -> Option<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok()
}

#[cfg(all(test, unix))]
#[path = "command_policy_repair_tests.rs"]
mod tests;
