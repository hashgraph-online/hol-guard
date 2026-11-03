//! Point a tampered command-policy block at the local repair page.
//!
//! `hook_policy_repair.py`. The hook never launches the CLI and never calls
//! authority recovery: a recent authenticator proof can satisfy that call, so
//! the blocked tool call must not rebuild protection. The deny reason carries
//! one signed loopback link instead. The person opens that page and presses
//! Repair protection; this tool call stays denied.
//!
//! There is a link only while the approval center is running, since the
//! locator the page is addressed from names a live process. Without one the
//! reason keeps the `recover-authority` command the floor appended: a page
//! served by a daemon that is not there cannot be opened, so the terminal is
//! the only route left, and naming the page alone would leave the person with
//! nothing that works.
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
/// Without a page to open, the command that needs no daemon comes first.
const APPROVAL_REASON_WITHOUT_URL: &str = concat!(
    "HOL Guard blocked this action because trusted protection settings need repair. ",
    "Run `hol-guard command controls recover-authority` in a terminal to restore protection, ",
    "or open HOL Guard Extensions and press Repair protection.",
);

/// The same reason, with the command told which home to repair when that is
/// not the one it would find on its own.
///
/// The block names the home the blocked runtime read its authority from, and
/// a person who pastes the bare command into a shell pointing somewhere else
/// recovers a different install while this one stays blocked. So the home is
/// named whenever it is not `<home_dir>/.hol-guard`, quoted for the shell it
/// is pasted into, exactly as
/// [`crate::blocked_request_mode::approval_wait_hint_for_home`] names it on
/// the approval hint. The default home is left out: the short command is the
/// one almost everyone needs, and a path that adds nothing only invites
/// editing. An empty `home_dir` names nothing either, since a runtime that
/// does not know where the person lives cannot tell the two apart.
///
/// The flag goes on `command`, which is the parser that carries it; after
/// `recover-authority` argparse hands it to the leaf, which takes no options
/// and would reject the whole line. It is `--guard-home`, the flag that names
/// the Guard home itself, and the one `extension_controls_commands`
/// (`_recovery_command`) prints for the same recovery, so a person who meets
/// the block and a person who meets the CLI's own message are told to run the
/// same thing. `--home` names the directory the person lives in and only
/// stands in for the Guard home when none was given; handing it a Guard home
/// reaches the right store but resolves every other home-dependent value
/// against a directory nobody lives in.
/// `test_recover_authority_accepts_the_home_the_block_names` pins that this
/// spelling parses.
fn reason_without_url(guard_home: &Path, home_dir: &str) -> String {
    if home_dir.is_empty() || Path::new(home_dir).join(".hol-guard") == guard_home {
        return APPROVAL_REASON_WITHOUT_URL.to_owned();
    }
    let quoted = crate::mcp_proxy_shlex::quote(&guard_home.to_string_lossy());
    APPROVAL_REASON_WITHOUT_URL.replace(
        "command controls recover-authority",
        &format!("command --guard-home {quoted} controls recover-authority"),
    )
}

/// Rewrite a repairable command-control authority block in place.
///
/// Everything else is left exactly as the native evaluation produced it,
/// including a block this module cannot compose a link for byte for byte.
/// The repair as the edge reaches it. The health lives in the admitted
/// snapshot's compiled command extensions and both paths in the request's own
/// source, so the edge hands over what it holds rather than taking those
/// pieces apart at the call.
pub(crate) fn apply_at_edge(
    result: &mut Value,
    snapshot: Option<&crate::policy_enforcement::AdmittedPolicySnapshot>,
    source: &guard_contracts::GuardHookSourceMetadataV2,
) {
    apply(
        result,
        snapshot
            .and_then(|snapshot| snapshot.command_extensions.as_ref())
            .map(guard_command::native_command_controls::CompiledNativeCommandControls::health),
        Path::new(&source.guard_home),
        &source.home_dir,
    );
}

pub(crate) fn apply(result: &mut Value, health: Option<&str>, guard_home: &Path, home_dir: &str) {
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
                Value::String(reason_without_url(guard_home, home_dir)),
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
