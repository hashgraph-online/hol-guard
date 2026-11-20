//! CIGAR hosted by Guard's own executable, with no Python.
//!
//! Guard starts its runtime binary in one of three private modes:
//!
//! - `__guard-cigar-bridge` speaks `guard-cigar-bridge.v1` to the supervisor.
//!   It owns graphs and brokers and starts each one as a worker child of this
//!   same executable.
//! - `__guard-cigar-client` is one agent's broker client. It receives its grant
//!   over stdin, never in arguments or the environment.
//! - `__guard-cigar-worker [--broker]` is the `cigar.context-worker.v1`
//!   protocol itself, from the `cigar-context` crate.
//!
//! The bridges keep the request and reply shapes of the Python SDK adapters
//! they replace, so the supervisor's transport, deadlines and error mapping do
//! not change.

mod bridge;
mod broker_host;
mod channel;
mod client;
mod frames;
mod graph;

/// Mode that serves the supervisor's graph and broker requests.
pub const BRIDGE_COMMAND: &str = "__guard-cigar-bridge";
/// Mode that serves one agent's broker client requests.
pub const CLIENT_COMMAND: &str = "__guard-cigar-client";
/// Mode that runs the `cigar-context` worker protocol.
pub const WORKER_COMMAND: &str = "__guard-cigar-worker";
/// The `cigar-context` release compiled into this executable.
pub const CORE_VERSION: &str = cigar_context::worker::CORE_VERSION;
/// The worker protocol compiled into this executable.
pub const WORKER_PROTOCOL: &str = cigar_context::worker::PROTOCOL;
/// The broker protocol compiled into this executable.
pub const BROKER_PROTOCOL: &str = cigar_context::broker::protocol::BROKER_PROTOCOL;

/// True when `args` (without the program name) select one of these modes.
pub fn is_command(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some(BRIDGE_COMMAND | CLIENT_COMMAND | WORKER_COMMAND)
    )
}

/// Run the selected mode and return the process exit code.
pub fn main(args: &[String]) -> i32 {
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        Some(WORKER_COMMAND) => match cigar_context::worker::main(rest) {
            Ok(()) => 0,
            Err(_) => 1,
        },
        Some(BRIDGE_COMMAND) if rest.is_empty() => bridge::run(),
        Some(CLIENT_COMMAND) if rest.is_empty() => client::run(),
        _ => 2,
    }
}

#[cfg(test)]
mod tests;
