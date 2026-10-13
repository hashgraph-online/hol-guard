//! `hol-guard-runtime mcp-relay <python proxy argv>`: native MCP stdio relay.
//!
//! The relay owns the MCP server child end to end: it parses the installed
//! `guard <harness>-mcp-proxy` command line, launches the verified executable
//! with the scrubbed environment, and relays JSON-RPC between the host on
//! stdio and the child without a Python process or per-frame resident round
//! trips. Every `tools/call` is decided by a `RelayAuthority`; the authority
//! wired here fails closed until the native decision op is connected, and the
//! relay feature is not advertised in the runtime capabilities until then, so
//! installers keep launching the Python proxy.
//!
//! Unix only: the child session relies on process groups.

/// `hol-guard-runtime` subcommand that runs the relay.
pub(crate) const RELAY_COMMAND: &str = "mcp-relay";

/// Capability string installers will gate relay selection on. It is not
/// advertised until `tools/call` decisions are native.
#[cfg_attr(not(all(test, unix)), allow(dead_code))]
pub(crate) const RELAY_FEATURE: &str = "mcp-stdio-relay-v1";

/// Run the relay; returns the process exit status.
pub(crate) fn run(python_argv: &[String]) -> i32 {
    #[cfg(unix)]
    {
        unix::run(python_argv)
    }
    #[cfg(not(unix))]
    {
        let _ = python_argv;
        eprintln!("hol-guard mcp-relay: the native MCP relay is not supported on this platform");
        2
    }
}

#[cfg(unix)]
mod unix {
    use std::io;

    use crate::guard_config_load::approval_wait_timeout_seconds;
    use crate::mcp_relay_args::parse;
    use crate::mcp_relay_authority::PendingNativeAuthority;
    use crate::mcp_relay_core::{child_response_timeout, ChildLink, Relay, RelayExit};
    use crate::mcp_relay_host::LineHost;
    use crate::mcp_relay_launch::{inherited_environment, prepare, spawn};

    fn fail(reason: &str, status: i32) -> i32 {
        eprintln!("hol-guard mcp-relay: {reason}");
        status
    }

    pub(super) fn run(python_argv: &[String]) -> i32 {
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
        let mut relay = Relay::new(child, host, PendingNativeAuthority, timeout);
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
