//! Read-only Root diagnostic for candidate requirements in an inert prefix.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 9 {
        return Err("usage: gauntlet-candidate-dependencies-shadow JOB_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 ARCHIVE_SHA256 VERSION NATIVE_SHA256 PREFIX_TREE_SHA256 PYTHON_FULL_VERSION".to_owned());
    }
    let pins = gauntlet_worker_state::CandidateDependencyLivePins {
        job_id: &args[1],
        source_sha: &args[2],
        source_archive_sha256: &args[3],
        archive_sha256: &args[4],
        version: &args[5],
        native_sha256: &args[6],
        prefix_tree_sha256: &args[7],
        python_full_version: &args[8],
    };
    gauntlet_worker_state::verify_cloned_candidate_dependencies_ineligible(&pins)
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
            eprintln!("candidate dependencies unavailable: {error}");
            std::process::exit(2);
        }
    }
}
