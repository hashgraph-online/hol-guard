//! Read-only single-role staging diagnostic. All selectors are fixed pins;
//! the result cannot admit a candidate or issue a benchmark verdict.

use gauntlet_evidence::{observe_staging_control_root_owned_ineligible, StagingEvidencePins};

fn run() -> Result<serde_json::Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 11 {
        return Err("usage: gauntlet-staging-control-open-shadow BUILD_JOB RUN_ID ROLE SOURCE_SHA VERSION CONFIG_SHA PRIVATE_MANIFEST_SHA PREFIX_TREE_SHA RECORD_SHA CONTROLLER_PUBLIC_KEY_HEX".to_owned());
    }
    let pins = StagingEvidencePins {
        build_job_id: &args[1],
        run_id: &args[2],
        role: &args[3],
        source_sha: &args[4],
        version: &args[5],
        config_digest: &args[6],
        private_manifest_sha256: &args[7],
        prefix_tree_sha256: &args[8],
        record_sha256: &args[9],
        controller_public_key_hex: &args[10],
    };
    observe_staging_control_root_owned_ineligible(&pins)
        .map(|proof| proof.to_json())
        .map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("staging control opening unavailable: {error}");
            std::process::exit(2);
        }
    }
}
