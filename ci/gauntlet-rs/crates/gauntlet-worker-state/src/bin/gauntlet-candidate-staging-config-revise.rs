//! One-use inert image-ID revision for a retained shadow candidate config.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<serde_json::Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 9 {
        return Err("usage: gauntlet-candidate-staging-config-revise BUILD_JOB SOURCE_SHA VERSION OLD_CONFIG_SHA PRIVATE_MANIFEST_SHA PREFIX_TREE_SHA OLD_IMAGE_ID NEW_IMAGE_ID".to_owned());
    }
    let pins = gauntlet_worker_state::StagingConfigRevisionPins {
        build_job_id: &args[1],
        source_sha: &args[2],
        version: &args[3],
        old_config_digest: &args[4],
        private_manifest_sha256: &args[5],
        prefix_tree_sha256: &args[6],
        old_image_id: &args[7],
        new_image_id: &args[8],
    };
    gauntlet_worker_state::revise_staging_config_ineligible(&pins)
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux ARM64 Root staging config artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("staging config revision unavailable: {error}");
            std::process::exit(2);
        }
    }
}
