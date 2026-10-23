//! Read-only preflight for a fixed provisional staging generation. This
//! performs the same source/controller/asset/image checks as the staging
//! worker without reserving a run or authenticating its future effects.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 9 {
        return Err("usage: gauntlet-candidate-staging-readiness JOB_ID SOURCE_SHA VERSION CONFIG_DIGEST PRIVATE_MANIFEST_SHA256 PREFIX_TREE_SHA256 CONTROLLER_PATH CONTROLLER_TREE_SHA256".to_owned());
    }
    let pins = gauntlet_worker_state::CandidateConformanceReadinessPins {
        job_id: &args[1],
        source_sha: &args[2],
        version: &args[3],
        config_digest: &args[4],
        private_manifest_sha256: &args[5],
        prefix_tree_sha256: &args[6],
        controller_path: &args[7],
        controller_tree_sha256: &args[8],
    };
    gauntlet_worker_state::inspect_candidate_staging_readiness_ineligible(&pins)
        .map(|proof| proof.to_json().to_string())
        .map_err(|error| error.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 staging readiness artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("staging readiness unavailable: {error}");
            std::process::exit(2);
        }
    }
}
