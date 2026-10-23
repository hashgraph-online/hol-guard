//! One-use Root diagnostic for an inert, unadmitted candidate prefix clone.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 9 {
        return Err("usage: gauntlet-candidate-prefix-clone-shadow JOB_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 ARCHIVE_SHA256 VERSION BASELINE_PREFIX BASELINE_TREE_SHA256 STAGED_WHEEL_TREE_SHA256".to_owned());
    }
    let pins = gauntlet_worker_state::CandidatePrefixClonePins {
        job_id: &args[1],
        source_sha: &args[2],
        source_archive_sha256: &args[3],
        archive_sha256: &args[4],
        version: &args[5],
        baseline_path: std::path::Path::new(&args[6]),
        baseline_tree_sha256: &args[7],
        stage_tree_sha256: &args[8],
    };
    gauntlet_worker_state::clone_captured_candidate_prefix_ineligible(&pins)
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
            eprintln!("candidate prefix clone unavailable: {error}");
            std::process::exit(2);
        }
    }
}
