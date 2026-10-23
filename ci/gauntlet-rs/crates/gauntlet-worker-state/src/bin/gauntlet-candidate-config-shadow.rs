//! Read-only installed-template projection; output is never a deployment.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 10 {
        return Err("usage: gauntlet-candidate-config-shadow TEMPLATE_PATH TEMPLATE_RAW_SHA256 TEMPLATE_CANONICAL_SHA256 SOURCE_SHA VERSION NATIVE_SHA256 ROOT_PREFIX_DIGEST RUNTIME_TREE_DIGEST WHEEL_SHA256".to_owned());
    }
    let pins = gauntlet_worker_state::CandidateConfigProjectionPins {
        source_sha: &args[4],
        package_version: &args[5],
        native_sha256: &args[6],
        root_prefix_digest: &args[7],
        runtime_tree_digest: &args[8],
        wheel_sha256: &args[9],
    };
    gauntlet_worker_state::project_installed_candidate_config_ineligible(
        &args[1], &args[2], &args[3], &pins,
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
            eprintln!("candidate config unavailable: {error}");
            std::process::exit(2);
        }
    }
}
