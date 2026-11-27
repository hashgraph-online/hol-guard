//! R-SURFACE: where an automatic approval page may open while an agent drives
//! a browser.
//!
//! An agent that drives the user's own browser profile, or a browser reached
//! through a debugging port, would see an approval page Guard opens there, and
//! could click it. While such a session is live, Guard opens no approval page
//! automatically. The request still reaches every other surface (Desktop, the
//! native harness prompt, Pulse), and the approval link is printed for the user
//! to open themselves. Sessions in an isolated or dedicated profile do not hold
//! the page: the page opens in the user's default browser, which the agent does
//! not drive.
//!
//! The check only ever withholds an automatic page. It never approves, denies
//! or changes what is reviewed, and an explicit request to open a page still
//! opens it.

use std::io::Write;
use std::path::Path;

use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::browser_session_store::BROWSER_SESSION_IDLE_SECONDS;
use crate::local_store_read::{open_read_only, table_exists, STORE_FILE_NAME};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SESSIONS_TABLE: &str = "guard_browser_sessions";

/// Profile modes whose live session holds the automatic approval page. A mode
/// Guard could not read counts as one the agent may share with the user.
const HOLDING_MODES: [&str; 3] = ["shared", "remote-debugging", "unknown"];

/// Whether a session in `connection` that holds the page was seen within the
/// idle bound.
pub(crate) fn holding_session_live(connection: &Connection, now_unix: i64) -> bool {
    let cutoff = now_unix.saturating_sub(BROWSER_SESSION_IDLE_SECONDS);
    connection
        .prepare_cached(
            "select 1 from guard_browser_sessions \
             where last_seen_unix >= ?1 and profile_mode in (?2, ?3, ?4) limit 1",
        )
        .and_then(|mut statement| {
            statement.exists(params![
                cutoff,
                HOLDING_MODES[0],
                HOLDING_MODES[1],
                HOLDING_MODES[2]
            ])
        })
        .unwrap_or(false)
}

/// Whether a live browser session under `guard_home` holds the automatic
/// approval page. A store that is absent, has no session table, or cannot be
/// read holds nothing, so the page opens as the surface policy says.
pub(crate) fn approval_page_held(guard_home: &Path, now_unix: i64) -> bool {
    let Ok(Some(connection)) = open_read_only(&guard_home.join(STORE_FILE_NAME)) else {
        return false;
    };
    table_exists(&connection, SESSIONS_TABLE).unwrap_or(false)
        && holding_session_live(&connection, now_unix)
}

/// What the person reads when a live browser session held the page.
pub(crate) const HELD_NOTICE: &str = "HOL Guard is waiting for approval. An agent is driving a \
    shared browser, so Guard did not open the approval page there. Approve from HOL Guard \
    Desktop or your harness, or open the approval link yourself in a browser the agent does \
    not use.";

/// Withholds the automatic page when a live browser session holds it: writes
/// the notice and the approval link for the person and answers `true`. A write
/// that fails is ignored, as the caller's answer to the agent is unchanged.
pub(crate) fn withheld(guard_home: &Path, approval_url: &str, out: &mut impl Write) -> bool {
    if !approval_page_held(guard_home, now_unix()) {
        return false;
    }
    let _ = writeln!(out, "{HELD_NOTICE}\nApproval link: {approval_url}");
    true
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    guard_home: String,
}

/// Runner authority kind `approval_browser_surface`: `{"guard_home"}` answers
/// `{"approval_page_held": bool}` for the Python approval surfaces.
pub(crate) fn dispatch(args: &Value) -> KindResult {
    let request: Request = serde_json::from_value(args.clone()).map_err(|_| ERR_INVALID)?;
    if request.guard_home.trim().is_empty() {
        return Err(ERR_INVALID);
    }
    let held = approval_page_held(Path::new(&request.guard_home), now_unix());
    Ok(json!({ "approval_page_held": held }))
}
