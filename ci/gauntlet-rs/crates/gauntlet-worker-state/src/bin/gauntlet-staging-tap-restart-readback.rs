//! Fixed, read-only Root restart audit for one completed staging tap run.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<(), String> {
    use gauntlet_worker_state::{
        read_restarted_staging_tap_ineligible, verify_running_binary, StagingTapReadbackPins,
    };

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 11 {
        return Err("usage: gauntlet-staging-tap-restart-readback RUN_ID SOURCE_SHA CONFIG_SHA WORKER_GENERATION_SHA STARTED_SHA KEY_PIN_SHA TERMINAL_SHA REPORT_SHA TAP_JOURNAL_SHA BINARY_SHA".to_owned());
    }
    verify_running_binary(&args[10]).map_err(|error| error.to_string())?;
    let pins = StagingTapReadbackPins {
        run_id: &args[1],
        source_sha: &args[2],
        config_digest: &args[3],
        worker_generation_sha256: &args[4],
        started_marker_sha256: &args[5],
        controller_key_pin_sha256: &args[6],
        terminal_sha256: &args[7],
        report_sha256: &args[8],
        tap_journal_sha256: &args[9],
    };
    let result = read_restarted_staging_tap_ineligible(&pins)?;
    let raw = gauntlet_contracts::canonicalize(result.to_string().as_bytes())
        .map_err(|error| error.to_string())?;
    println!(
        "{}",
        String::from_utf8(raw).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<(), String> {
    Err("Linux ARM64 Root staging readback artifact required".to_owned())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("staging restart readback uncertain: {error}");
        std::process::exit(2);
    }
}
