//! `hol-guard-runtime mcp-relay <python proxy argv>`: native MCP stdio relay.
//!
//! The relay owns the MCP server child end to end: it parses the installed
//! `guard <harness>-mcp-proxy` command line, launches the verified executable
//! with the scrubbed environment, and relays JSON-RPC between the host on
//! stdio and the child without a Python process or per-frame resident round
//! trips. Every `tools/call` is decided in one round trip to the resident's
//! `mcp_relay_decide` op, and anything it does not decide is blocked. A
//! session the native lane cannot serve never reaches that point: at startup
//! the relay hands it to the Python proxy (`mcp_relay_lane`), so installers
//! select the relay wherever the runtime advertises it. A lane the daemon
//! has only not prepared yet keeps the session native.
//!
//! The child session runs in its own process group on unix and in a
//! kill-on-close JobObject on Windows.

/// `hol-guard-runtime` subcommand that runs the relay.
pub(crate) const RELAY_COMMAND: &str = "mcp-relay";

/// Capability string installers gate relay selection on.
pub(crate) const RELAY_FEATURE: &str = "mcp-stdio-relay-v1";

/// Run the relay; returns the process exit status.
pub(crate) fn run(python_argv: &[String]) -> i32 {
    session::run(python_argv)
}

mod session {
    use std::io;

    use crate::guard_config_load::approval_wait_timeout_seconds;
    use crate::mcp_relay_args::parse;
    use crate::mcp_relay_core::{
        child_response_timeout, inline_approval_timeout, ChildLink, Relay, RelayExit,
    };
    use crate::mcp_relay_host::LineHost;
    use crate::mcp_relay_lane::{
        hand_off, hands_off, note, startup, DaemonKick, Gate, STARTUP_BUDGET,
    };
    use crate::mcp_relay_launch::{inherited_environment, prepare, spawn};
    use crate::mcp_relay_resident::{ProcessFacts, ResidentRelayAuthority};

    fn fail(reason: &str, status: i32) -> i32 {
        eprintln!("hol-guard mcp-relay: {reason}");
        status
    }

    pub(super) fn run(python_argv: &[String]) -> i32 {
        // The host reads this relay's stdio to EOF, so no child the relay
        // starts (a detached daemon launch included) may hold it open.
        #[cfg(windows)]
        guard_runtime_windows_process::disinherit_standard_handles();
        let args = match parse(python_argv) {
            Ok(args) => args,
            Err(reason) => return fail(&reason, 2),
        };
        let configured =
            match approval_wait_timeout_seconds(&args.guard_home, args.workspace.as_deref()) {
                Ok(seconds) => seconds,
                Err(reason) => return fail(&reason, 1),
            };
        let cwd = match args.workspace.clone() {
            Some(workspace) => workspace,
            None => match std::env::current_dir() {
                Ok(cwd) => cwd,
                Err(_) => return fail("mcp_relay_cwd_unavailable", 1),
            },
        };
        let launch = match prepare(&args, &inherited_environment(), &cwd) {
            Ok(launch) => launch,
            Err(reason) => return fail(&reason, 1),
        };
        let mut authority = ResidentRelayAuthority::new(&args, &launch, &ProcessFacts::current());
        // Before any stdin byte is read or the child exists: a session the
        // lane cannot serve runs as the Python proxy, on untouched stdio.
        let workspace = authority.lane_workspace().unwrap_or_default().to_owned();
        let mut kick = DaemonKick::new(&args, python_argv, std::path::Path::new(&workspace));
        let gate = startup(
            &mut |deadline| authority.lane_ready(deadline),
            &mut kick,
            STARTUP_BUDGET,
        );
        note(&gate);
        let warming = match gate {
            Gate::NotReady(code) if hands_off(&code) => return hand_off(python_argv),
            Gate::NotReady(_) => true,
            Gate::Relay { .. } => false,
        };
        let authority = authority.with_kick(Box::new(kick)).warming(warming);
        let mut child = match spawn(&args, &launch) {
            Ok(child) => child,
            Err(reason) => return fail(&reason, 1),
        };
        let host = match LineHost::spawn(io::stdin(), io::stdout()) {
            Ok(host) => host,
            Err(reason) => {
                child.quarantine();
                return fail(&reason, 1);
            }
        };
        let timeout = child_response_timeout(configured);
        let inline_timeout = inline_approval_timeout(configured);
        let mut relay = Relay::new(child, host, authority, timeout, inline_timeout);
        let outcome = relay.serve();
        let mut child = relay.into_child();
        match outcome {
            Ok(RelayExit::HostClosed | RelayExit::TimedOut) => child.shutdown(),
            Err(reason) => {
                child.quarantine();
                fail(&reason, 1)
            }
        }
    }
}

#[cfg(all(test, unix))]
#[path = "mcp_relay_tests.rs"]
mod tests;
