//! Root-only, read-only reopening of a completed Rust deterministic diagnostic.
//! The response carries its exact canonical terminal and summary as JSON
//! objects for an independently retained macOS host key-pin comparison.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<(), String> {
    use gauntlet_worker_state::{verify_running_binary, RunReservationJournal};
    use std::path::Path;

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: gauntlet-deterministic-readback SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_GENERATION_SHA256 READBACK_BINARY_SHA256".to_owned());
    }
    verify_running_binary(&args[5]).map_err(|error| error.to_string())?;
    let journal = RunReservationJournal::open_root_owned(Path::new(
        "/var/lib/hol-gauntlet-rust/worker-state",
    ))
    .map_err(|error| error.to_string())?;
    let result = journal
        .read_deterministic_diagnostic_root_owned(&args[2], &args[1], &args[3], &args[4])
        .map_err(|error| error.to_string())?;
    println!("{result}");
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<(), String> {
    Err("Linux ARM64 Root deterministic readback artifact required".to_owned())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("deterministic readback unavailable: {error}");
        std::process::exit(2);
    }
}
