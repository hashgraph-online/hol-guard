//! One-use Root diagnostic for a source-pinned local Podman candidate run.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 14 {
        return Err("usage: gauntlet-local-candidate-run-shadow ABSOLUTE_CONTROLLER_ROOT CONTROLLER_TREE_SHA256 JOB_ID UV_IMAGE_ID RUST_IMAGE_ID BUILDER_IMAGE_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 LOCAL_VERSION PODMAN_SHA256 SLIRP_SHA256 APPARMOR_PARSER_SHA256 SECCOMP_SHA256".to_owned());
    }
    let runtime = gauntlet_worker_state::CandidateRuntimePins::parse(
        &args[10], &args[11], &args[12], &args[13],
    )
    .map_err(|error| error.to_string())?;
    gauntlet_worker_state::run_fixed_local_candidate_ineligible(
        std::path::Path::new(&args[1]),
        &args[2],
        &args[3],
        &args[4],
        &args[5],
        &args[6],
        &args[7],
        &args[8],
        &args[9],
        runtime,
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
            eprintln!("local candidate run unavailable: {error}");
            std::process::exit(2);
        }
    }
}
