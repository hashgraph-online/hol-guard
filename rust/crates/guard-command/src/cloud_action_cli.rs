//! Local JSON-lines interface for a hosting service's cloud action decisions.
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = guard_command::cloud_action_serve::serve("guard-cloud-action", &args);
    ExitCode::from(u8::try_from(code).unwrap_or(2))
}
