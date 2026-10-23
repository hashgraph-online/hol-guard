//! Mac host command for a completed staging tap's Root restart readback.
//! All inputs are pre-existing outside pins; this command remains passive.

use gauntlet_host_state::HostControllerKeyPinJournal;
use serde_json::Value;
use std::path::Path;

fn run() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS Lima host artifact required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        return Err("usage: gauntlet-host-staging-tap-restart-readback PRIVATE_HOST_PIN_DIR RUN_ID SOURCE_SHA CONFIG_SHA WORKER_GENERATION_SHA READBACK_BINARY_SHA".to_owned());
    }
    let journal = HostControllerKeyPinJournal::open(Path::new(&args[1]))
        .map_err(|error| format!("private host pins unavailable: {error}"))?;
    let key = journal
        .read(&args[2])
        .map_err(|error| format!("prelaunch host key pin unavailable: {error}"))?;
    let tap = journal
        .read_sdk_tap_journal_pin(&args[2])
        .map_err(|error| format!("post-run host tap pin unavailable: {error}"))?;
    if key.pins.source_sha != args[3]
        || key.pins.deployment_digest != args[4]
        || key.pins.worker_generation != args[5]
    {
        return Err("host pins differ from outside source/config/worker generation".to_owned());
    }
    let defaults: Value = serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
        .map_err(|_| "compiled Lima defaults are invalid".to_owned())?;
    let limactl = defaults["limactl"]
        .as_str()
        .ok_or("compiled Lima executable unavailable")?;
    let vm = defaults["vm"]
        .as_str()
        .ok_or("compiled Lima VM unavailable")?;
    let observation = key
        .observe_fixed_vm_staging_restart_readback(limactl, vm, &args[6], &tap)
        .map_err(|error| format!("keyed staging restart readback uncertain: {error}"))?;
    if journal
        .read(&args[2])
        .map_err(|error| format!("host key pin changed during readback: {error}"))?
        != key
        || journal
            .read_sdk_tap_journal_pin(&args[2])
            .map_err(|error| format!("host tap pin changed during readback: {error}"))?
            != tap
    {
        return Err("host key or tap pin changed during readback".to_owned());
    }
    let raw = gauntlet_contracts::canonicalize(observation.to_json().to_string().as_bytes())
        .map_err(|error| error.to_string())?;
    println!(
        "{}",
        String::from_utf8(raw).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("staging host restart readback unavailable: {error}");
        std::process::exit(2);
    }
}
