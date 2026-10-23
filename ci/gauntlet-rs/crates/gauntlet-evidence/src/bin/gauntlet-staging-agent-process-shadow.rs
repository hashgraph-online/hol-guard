//! Read-only single-role comparison of a signed agent claim with the Rust
//! worker's live kernel container-process samples. Never admits a candidate.

#[cfg(target_os = "linux")]
fn run() -> Result<serde_json::Value, String> {
    use gauntlet_evidence::{
        observe_staging_agent_process_root_owned_ineligible, StagingAgentProcessPins,
        StagingEvidencePins,
    };
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 15 {
        return Err("usage: gauntlet-staging-agent-process-shadow BUILD_JOB RUN_ID ROLE SOURCE_SHA VERSION CONFIG_SHA PRIVATE_MANIFEST_SHA PREFIX_TREE_SHA RECORD_SHA CONTROLLER_PUBLIC_KEY_HEX WORKER_SHA STARTED_MARKER_SHA CONTROLLER_KEY_PIN_SHA REPORT_SHA".to_owned());
    }
    let evidence = StagingEvidencePins {
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
    let pins = StagingAgentProcessPins {
        evidence,
        worker_generation_sha256: &args[11],
        started_marker_sha256: &args[12],
        controller_key_pin_sha256: &args[13],
        report_sha256: &args[14],
    };
    observe_staging_agent_process_root_owned_ineligible(&pins)
        .map(|proof| proof.to_json())
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux Root staging agent process audit required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("staging agent process audit unavailable: {error}");
            std::process::exit(2);
        }
    }
}
