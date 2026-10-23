//! Fixed, read-only Root contained-effect composition under outside pins.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<serde_json::Value, String> {
    use gauntlet_evidence::StagingEvidencePins;
    use gauntlet_worker_state::{
        staging_contained_effect::observe_staging_contained_effect_ineligible,
        verify_running_binary, RunReservationJournal,
    };
    use std::path::Path;
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 15 {
        return Err("usage: gauntlet-staging-contained-effect-shadow BUILD_JOB RUN_ID SOURCE_SHA VERSION CONFIG_SHA PRIVATE_MANIFEST_SHA PREFIX_TREE_SHA WORKER_SHA STARTED_SHA EFFECT_JOURNAL_SHA REPORT_SHA CONTROL_SHA ROLE READER_SHA".to_owned());
    }
    verify_running_binary(&args[14]).map_err(|e| e.to_string())?;
    let journal = RunReservationJournal::open_root_owned(Path::new(
        "/var/lib/hol-gauntlet-rust/staging-state",
    ))
    .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let started = journal
        .started(&args[2], &args[3], &args[5], &args[8])
        .map_err(|e| e.to_string())?
        .ok_or("outside-pinned started marker is absent")?;
    if started.sha256 != args[9] {
        return Err("contained effect started marker differs from outside pin".to_owned());
    }
    let key = started
        .controller_public_key_hex
        .as_deref()
        .ok_or("keyed contained control required")?;
    let pins = StagingEvidencePins {
        build_job_id: &args[1],
        run_id: &args[2],
        source_sha: &args[3],
        version: &args[4],
        config_digest: &args[5],
        private_manifest_sha256: &args[6],
        prefix_tree_sha256: &args[7],
        record_sha256: &args[12],
        role: &args[13],
        controller_public_key_hex: key,
    };
    observe_staging_contained_effect_ineligible(
        &journal, &lease, &started, &pins, &args[10], &args[11],
    )
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux ARM64 Root contained-effect reader required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("contained effect readback unavailable: {error}");
            std::process::exit(2);
        }
    }
}
