//! One-use, inert candidate assets under a separate /opt shadow root.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 9 {
        return Err("usage: gauntlet-candidate-shadow-assets JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 ARCHIVE_SHA256 VERSION NATIVE_SHA256 PREFIX_TREE_SHA256 WHEEL_SHA256".to_owned());
    }
    let pins = gauntlet_worker_state::CandidateShadowAssetsPins {
        job_id: &args[1],
        source_sha: &args[2],
        source_archive_sha256: &args[3],
        archive_sha256: &args[4],
        version: &args[5],
        native_sha256: &args[6],
        prefix_tree_sha256: &args[7],
        wheel_sha256: &args[8],
    };
    gauntlet_worker_state::assemble_candidate_shadow_assets_ineligible(&pins)
        .map(|proof| proof.to_json().to_string())
        .map_err(|error| error.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("candidate shadow assets unavailable: {error}");
            std::process::exit(2);
        }
    }
}
