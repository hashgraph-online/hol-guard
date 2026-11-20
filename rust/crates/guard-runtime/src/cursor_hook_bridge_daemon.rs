//! How the native Cursor bridge gets a daemon answer: the live resident
//! first, then the loopback daemon, then, when the daemon is down, did not
//! answer or answered with a body the client's `_daemon_hook_result`
//! refuses, the daemon again after the client's install-time
//! `GUARD_RECOVERY_COMMAND` ran. The client recovered the daemon the same
//! way with `_run_guard_recovery` and then asked it once more.
//!
//! An overloaded daemon is never restarted, as the client never recovers
//! one. A daemon the hook was posted to may already have seen it, so after
//! the start the hook is sent only to a daemon that came up since. Every
//! other outcome, and an answer the bridge cannot render, is the client's
//! `_cursor_unavailable_response`; the client's
//! CLI fallback, which reviewed the hook in Python, is never run.

use std::path::Path;
use std::time::Instant;

use guard_command::hook_adapter_value::OValue;

use super::{answer, fail_closed, Client, Kind, Reply, Request, DAEMON_HARNESS};
use crate::bounded_hook_bridge::{
    daemon_target, post_hook_reply_missed, transport_deadline, DaemonTarget, PostFailure,
    DAEMON_BUDGET, PROMPT_DAEMON_BUDGET,
};
use crate::claude_hook_bridge_http::remaining;
use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_bridge_direct_resident::DirectMiss;
use crate::cursor_hook_bridge_response::python_document;
use crate::hook_bridge_daemon_start::{await_daemon, start_daemon, Attempt};

/// `GUARD_ACTIONS`: the policy actions the client accepts from the daemon.
const GUARD_ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
/// `FROZEN_DAEMON_RECOVER_ARG`: a frozen runtime's recovery command reads
/// its failure kind from `HOL_GUARD_HOOK_FAILURE_KIND` and takes no
/// further argument.
const FROZEN_RECOVER_ARG: &str = "--_hol-guard-codex-daemon-recover";

/// What one answer from the resident or the daemon settles.
enum Settled {
    /// The client's reply.
    Reply(Reply),
    /// A body `_daemon_hook_result` refuses as a daemon failure.
    Refused,
}

/// Whether `_daemon_hook_result` accepts `body`: a JSON object once
/// stripped, whose `policy_action` is one of `GUARD_ACTIONS` unless the
/// hook is an observer.
fn accepted(kind: Kind, body: &str) -> bool {
    let Some((OValue::Map(response), _)) = python_document(py_strip(body)) else {
        return false;
    };
    kind == Kind::After
        || response
            .get_str("policy_action")
            .is_some_and(|action| GUARD_ACTIONS.contains(&action))
}

/// The reply for a body the resident or the daemon answered: the client's
/// own answer, or the fail-closed answer when the bridge cannot render it.
fn settle(client: &Client, request: &Request, body: &str) -> Settled {
    if !accepted(request.kind, body) {
        return Settled::Refused;
    }
    let guard_home = Path::new(&client.guard_home);
    if let Some((stdout, code)) = answer(request.kind, &request.event, body, guard_home) {
        return Settled::Reply(Reply::Answered(stdout, code));
    }
    Settled::Reply(fail_closed(&request.event))
}

/// The deadline for one daemon request inside the bridge's share of the
/// hook deadline, or `None` when no time is left for one.
pub(super) fn request_deadline(client: &Client, request: &Request) -> Option<Instant> {
    let budget = match request.kind {
        Kind::Prompt => PROMPT_DAEMON_BUDGET,
        Kind::PreToolUse | Kind::After => DAEMON_BUDGET,
    };
    transport_deadline(client.deadline, remaining(client.deadline), budget)
}

/// The body `_daemon_hook_result` reads from the daemon for `request`,
/// stripped as the client strips it. The client also sends `hook_env`,
/// which the daemon drops unread. `miss` names why the resident did not
/// answer, so the daemon can count it.
pub(super) fn post(
    target: &DaemonTarget,
    request: &Request,
    deadline: Instant,
    miss: DirectMiss,
) -> Result<String, PostFailure> {
    let path = format!("/v1/hooks/{DAEMON_HARNESS}?{}", request.query);
    post_hook_reply_missed(target, &path, &request.data, deadline, Some(miss))
        .map(|body| py_strip(&body).to_owned())
}

/// The client's `[*GUARD_RECOVERY_COMMAND, failure_kind]`; a frozen
/// runtime's command is told the kind through the environment alone.
pub(super) fn recovery_argv(command: &[String], failure_kind: &str) -> Vec<String> {
    let mut argv = command.to_vec();
    let frozen = argv.len() == 3 && argv[1] == FROZEN_RECOVER_ARG;
    if !argv.is_empty() && !frozen {
        argv.push(failure_kind.to_owned());
    }
    argv
}

/// The bridge's reply to `request`, given what a live resident answered or
/// why it did not.
pub(super) fn daemon_reply(
    client: &Client,
    request: &Request,
    resident: Result<String, DirectMiss>,
) -> Reply {
    let miss = match resident {
        // The resident answered, and queued the hook's evidence, for the
        // daemon: asking the daemon would forward the hook to it again.
        Ok(body) => {
            return match settle(client, request, &body) {
                Settled::Reply(reply) => reply,
                Settled::Refused => fail_closed(&request.event),
            }
        }
        Err(miss) => miss,
    };
    let Some(target) = daemon_target(Path::new(&client.guard_home), DAEMON_HARNESS) else {
        return restarted_reply(client, request, PostFailure::Transport, None, miss);
    };
    // Too little time for a request means the deadline is all but spent.
    let Some(deadline) = request_deadline(client, request) else {
        return fail_closed(&request.event);
    };
    let failure = match post(&target, request, deadline, miss) {
        Ok(body) => match settle(client, request, &body) {
            Settled::Reply(reply) => return reply,
            Settled::Refused => PostFailure::ControlPlane,
        },
        Err(PostFailure::Overload) => return fail_closed(&request.event),
        Err(failure) => failure,
    };
    restarted_reply(client, request, failure, Some(&target), miss)
}

/// Start the daemon for `failure` and send the hook once to a daemon that
/// came up since. The daemon that `failed` already saw the hook, so it is
/// never sent to again; a second refusal is not restarted again.
fn restarted_reply(
    client: &Client,
    request: &Request,
    failure: PostFailure,
    failed: Option<&DaemonTarget>,
    miss: DirectMiss,
) -> Reply {
    let failure_kind = failure.failure_kind();
    let command = recovery_argv(&client.recovery_command, failure_kind);
    let guard_home = Path::new(&client.guard_home);
    if !start_daemon(&command, failure_kind, client.deadline, Some(guard_home)) {
        return fail_closed(&request.event);
    }
    let started = await_daemon(client.deadline, || {
        match daemon_target(guard_home, DAEMON_HARNESS) {
            Some(target) if failed.is_none_or(|old| !old.same_daemon(&target)) => {
                Attempt::Settled(target)
            }
            _ => Attempt::NotUp,
        }
    });
    let body = started.and_then(|target| {
        let deadline = request_deadline(client, request)?;
        post(&target, request, deadline, miss).ok()
    });
    match body.map(|body| settle(client, request, &body)) {
        Some(Settled::Reply(reply)) => reply,
        Some(Settled::Refused) | None => fail_closed(&request.event),
    }
}
