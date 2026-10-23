//! Read-only status probe of the isolated Rust worker's own VM journal.

use gauntlet_contracts::WorkerState;
use gauntlet_host_state::VmRustShadowPlan;
use serde_json::json;

fn state_name(state: WorkerState) -> &'static str {
    match state {
        WorkerState::Unavailable => "unavailable",
        WorkerState::NotStarted => "not-started",
        WorkerState::Staged => "staged",
        WorkerState::Running => "running",
        WorkerState::Unknown => "unknown",
        WorkerState::Terminal => "terminal",
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 6 {
        return Err("usage: gauntlet-host-shadow-rust-worker SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_GENERATION_SHA256 SHADOW_BINARY_SHA256".to_owned());
    }
    let text = |index: usize| {
        args[index]
            .to_str()
            .ok_or_else(|| "outside pins must be UTF-8".to_owned())
    };
    let operations = serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
        .map_err(|_| "compiled public operations defaults are invalid".to_owned())?;
    let plan = VmRustShadowPlan::new(
        &operations,
        text(1)?,
        text(2)?,
        text(3)?,
        text(4)?,
        text(5)?,
    )
    .map_err(|error| format!("Rust VM shadow plan unavailable: {error}"))?;
    let response = plan
        .execute_read_only()
        .map_err(|error| format!("Rust VM shadow unavailable: {error}"))?;
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-rust-worker-shadow.v1",
            "job_id":text(2)?,
            "source_sha":text(1)?,
            "state":state_name(response.state()),
            "rust_worker_journal_only":true,
            "compiled_public_defaults":true,
            "binary_pin_verified":false,
            "read_only":true,
            "execution_eligible":false,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
