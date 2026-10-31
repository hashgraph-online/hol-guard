//! A `git worktree add <checkout> && cd <checkout> && <checks>` chain.
//!
//! Native authority answers this chain with the workspace sandbox and the
//! worktree reason only when the add passes as a command of its own and the
//! checks would pass, or run contained, from the repository root the
//! checkout copies. The checkout does not exist until the add runs, so the
//! sandbox cannot take the chain whole. The sink proves the add again and
//! runs it on the host, then asks about `cd <checkout> && <checks>` once
//! more against the real checkout: it runs on the host when it passes on its
//! own, and otherwise takes the contained route, which judges it again.
//! Nothing in the checkout runs unless that answer holds. This replays the
//! steps Guard's own sink takes for the chain.

use guard_command::pretool::contained_wrapper_plan;

use super::*;

const UNSPLIT: &str = "Guard could not split this command again; nothing ran.";
const NO_CHECKOUT: &str = "Guard could not read the new checkout from this command; nothing ran.";
const ADD_UNPROVEN: &str = "Guard could not prove the `git worktree add` again; nothing ran.";

/// Run the chain `first` authorized for `payload` from `workspace`.
pub(super) fn run(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    first: &Map<String, Value>,
    signals: &process::Signals,
) -> Outcome<i32> {
    let command = payload
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::invalid("Invalid workspace sandbox request."))?;
    let root = path_text(workspace)?;
    let parts = contained_wrapper_plan(
        command,
        &root,
        Some(&root),
        authority.arguments.home.to_str(),
        None,
    )
    .worktree_add
    .ok_or_else(|| Failure::invalid(UNSPLIT))?;
    // The checkout is left out of the host steps' search path; a spelling
    // naming a home the request did not declare leaves nothing to leave out.
    let checkout = parts
        .checkout
        .ok_or_else(|| Failure::invalid(NO_CHECKOUT))?;
    let ask = |asked: &Map<String, Value>| {
        split::settled(|| authority.authorize(asked), std::thread::sleep)
    };
    // The chain must still carry the receipt it was routed here with.
    if !ask(payload).is_some_and(|again| same_chain(&again, first)) {
        return Err(Failure::invalid(
            "The command evidence changed before launch.",
        ));
    }
    let add = wrapper::with_text(payload, &parts.add);
    if !ask(&add).as_ref().is_some_and(split::proven) {
        return Err(Failure::invalid(ADD_UNPROVEN));
    }
    let excluded = [checkout.as_path()];
    let exit_code = split::run_on_host(
        &parts.add,
        "The `git worktree add`",
        workspace,
        &excluded,
        signals,
    )?;
    if exit_code != 0 {
        return Ok(exit_code);
    }
    let rest = wrapper::with_text(payload, &parts.entered);
    let answer = ask(&rest).ok_or_else(Failure::unauthorized)?;
    if split::proven(&answer) {
        return split::run_on_host(
            &parts.entered,
            "The rest of the command",
            workspace,
            &excluded,
            signals,
        );
    }
    wrapper::contained(&rest, workspace, authority, &answer, signals).map_err(|failure| Failure {
        message: format!(
            "{} The worktree was created first; run `{}` as a command of its own to retry the rest.",
            failure.message, parts.entered
        ),
        ..failure
    })
}

/// Whether `receipt` is still the worktree chain's own sandbox requirement,
/// bound to the evidence `first` was.
fn same_chain(receipt: &Map<String, Value>, first: &Map<String, Value>) -> bool {
    let text = |name: &str| receipt.get(name).and_then(Value::as_str);
    text("decision") == Some("deny")
        && text("policy_action") == Some("sandbox-required")
        && host_split(receipt.get("reason"))
        && receipt.get("observe_mode") != Some(&Value::Bool(true))
        && text("command_binding_digest").is_some_and(|digest| {
            first.get("command_binding_digest").and_then(Value::as_str) == Some(digest)
        })
}

#[cfg(test)]
#[path = "contained_workspace_sink_worktree_tests.rs"]
mod tests;
