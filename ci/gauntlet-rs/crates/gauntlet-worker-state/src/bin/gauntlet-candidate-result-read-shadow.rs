//! Read-only diagnostic for a retained local candidate build result.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        return Err("usage: gauntlet-candidate-result-read-shadow JOB_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 RESULT_SHA256 EXPORT_ARCHIVE_SHA256 VERSION".to_owned());
    }
    gauntlet_worker_state::read_fixed_candidate_result_ineligible(
        &args[1], &args[2], &args[3], &args[4], &args[5], &args[6],
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
            eprintln!("candidate result unavailable: {error}");
            std::process::exit(2);
        }
    }
}
