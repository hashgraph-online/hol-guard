//! Whether the resident can decide a relay session's calls at all.
//!
//! Some deferrals do not depend on the call: they follow from the config the
//! lane binds or from what the store holds. A session under such a binding
//! would defer, and refuse, every call the proxy would prompt for or read
//! remote policy for. The relay asks before it starts the MCP server and
//! hands such a session to the Python proxy, which decides those calls as it
//! does without the relay:
//!
//! - an unparsable view, an unbound harness or unverified extension layers;
//! - a blocked-request mode the bound configs do not resolve to one the queue
//!   route answers natively, or a receipt redaction level the configs do not
//!   agree on. The route is native under `safe-alternative`, and under `ask`
//!   (`mcp_relay_decide_ask.rs`), which also needs the approval center and the
//!   review OAuth source the daemon binds with it. Under `ask`
//!   `mode = "observe"` still hands off: the proxy prompts before it observes
//!   a call, which the resident cannot answer;
//! - a store holding a policy bundle with a row this harness's lookups reach,
//!   remote policy rows, or saved rows whose integrity state is not the
//!   protected one the daemon published. A bundle whose rows are all bound to
//!   other harnesses hands nothing off: no lookup here reads one.
//!
//! `mode = "observe"` alone hands nothing off: the resident takes its
//! observe-forward route and its downgrade of a pending saved approval
//! (`mcp_relay_decide_observe.rs`).
//!
//! This only steers which launcher runs. Each call is still admitted by
//! `mcp_relay_decide`, which repeats every check and refuses whatever it does
//! not decide, so a binding or store that changes mid-session still fails
//! closed.

use std::path::Path;

use super::{store, view, ASK_MODE};
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;

/// `blocked_request_mode`, under which the queue route blocks natively.
const SAFE_ALTERNATIVE_MODE: &str = "safe-alternative";
/// `mode`, under which the proxy prompts before it observes a call.
const OBSERVE_MODE: &str = "observe";
const SESSION_REVIEW_MODE: &str = "mcp_relay_session_review_mode";
const SESSION_REDACTION_UNBOUND: &str = "mcp_relay_session_redaction_unbound";

/// `Ok` when the binding and store leave every call to the resident.
pub(crate) fn session_decidable(
    binding: &DirectLaneBinding,
    guard_home: &str,
    harness: &str,
) -> Result<(), &'static str> {
    let view = view::harness_view(binding.mcp_relay.as_ref(), harness)?;
    let review = &binding.review;
    let queue_native = match review.blocked_request_mode.as_deref() {
        Some(SAFE_ALTERNATIVE_MODE) => true,
        // The `ask` branch writes the call's approval request itself, so it
        // needs the center it links and the OAuth source the row is written
        // with.
        Some(ASK_MODE) => {
            view.mode != OBSERVE_MODE
                && review.approval_center_origin.is_some()
                && review.review_oauth_source.is_some()
        }
        _ => false,
    };
    if !queue_native {
        return Err(SESSION_REVIEW_MODE);
    }
    if view.receipt_redaction_level.is_none() {
        return Err(SESSION_REDACTION_UNBOUND);
    }
    if let Some(connection) = store::open(Path::new(guard_home))? {
        store::saved(&connection, binding, guard_home, harness)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "mcp_relay_decide_session_tests.rs"]
mod tests;
