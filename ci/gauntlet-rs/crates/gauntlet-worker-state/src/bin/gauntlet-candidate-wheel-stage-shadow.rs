//! One-use Root diagnostic that only materializes inert wheel data.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: gauntlet-candidate-wheel-stage-shadow JOB_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 ARCHIVE_SHA256 VERSION".to_owned());
    }
    gauntlet_worker_state::materialize_captured_candidate_wheel_ineligible(
        &args[1], &args[2], &args[3], &args[4], &args[5],
    )
    .map(|proof| proof.to_json().to_string())
    .map_err(|error| error.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("candidate wheel staging unavailable: {error}");
            std::process::exit(2);
        }
    }
}
