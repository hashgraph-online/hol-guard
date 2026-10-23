//! One-use post-run host digest pin over three private staged guest files.
//! The transfer mechanism is not authenticated by this command; the output
//! remains diagnostic until a reviewed readout binds the live VM identity.

use gauntlet_host_state::HostControllerKeyPinJournal;
use std::path::Path;

fn run() -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS staging host artifact required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 && (args.len() != 4 || args[3] != "--read-vm") {
        return Err(
            "usage: gauntlet-host-sdk-tap-pin PRIVATE_HOST_PIN_DIR RUN_ID [--read-vm]".to_owned(),
        );
    }
    let journal = HostControllerKeyPinJournal::open(Path::new(&args[1]))
        .map_err(|error| error.to_string())?;
    let result = if args.len() == 4 {
        journal.record_sdk_tap_from_lima_ineligible(&args[2])
    } else {
        journal.record_sdk_tap_from_staged_files(&args[2])
    };
    result
        .map(|pin| pin.to_json().to_string())
        .map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("host SDK tap pin unavailable: {error}");
            std::process::exit(2);
        }
    }
}
