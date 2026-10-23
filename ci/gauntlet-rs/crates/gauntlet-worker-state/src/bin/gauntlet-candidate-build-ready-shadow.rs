//! Read-only Root probe before a host spends its one-use candidate build pin.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 16 {
        return Err("usage: gauntlet-candidate-build-ready-shadow CONTROLLER_ROOT CONTROLLER_TREE_SHA256 JOB_ID UV_IMAGE_ID RUST_IMAGE_ID BUILDER_IMAGE_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 VERSION TAG PODMAN_SHA256 SLIRP_SHA256 APPARMOR_PARSER_SHA256 SECCOMP_SHA256 POLICY_SHA256".to_owned());
    }
    const PREFIX: &str = "/opt/hol-gauntlet/rust-candidate-build-ready-shadow-";
    let digest = args[0]
        .strip_prefix(PREFIX)
        .ok_or("exact hashed Root readiness binary path required")?;
    gauntlet_worker_state::verify_running_binary(digest)
        .map_err(|_| "running readiness binary differs from path digest".to_owned())?;
    let runtime = gauntlet_worker_state::CandidateRuntimePins::parse(
        &args[11], &args[12], &args[13], &args[14],
    )
    .map_err(|error| error.to_string())?;
    gauntlet_worker_state::probe_fixed_candidate_build_ready_ineligible(
        std::path::Path::new(&args[1]),
        &args[2],
        &args[3],
        &args[4],
        &args[5],
        &args[6],
        &args[7],
        &args[8],
        &args[9],
        &args[10],
        &runtime,
        &args[15],
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
            eprintln!("candidate build readiness unavailable: {error}");
            std::process::exit(2);
        }
    }
}
