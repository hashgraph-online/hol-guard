//! Pin a completed Root effect journal outside the staging VM, ineligible.

use gauntlet_host_state::HostControllerKeyPinJournal;
use std::path::Path;

fn run() -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS staging host artifact required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 && (args.len() != 4 || args[3] != "--verify") {
        return Err(
            "usage: gauntlet-host-effect-events-pin PRIVATE_HOST_PIN_DIR RUN_ID [--verify]"
                .to_owned(),
        );
    }
    let journal = HostControllerKeyPinJournal::open(Path::new(&args[1]))
        .map_err(|error| error.to_string())?;
    let pin = if args.len() == 4 {
        journal.verify_effect_events_from_lima_ineligible(&args[2])
    } else {
        journal.record_effect_events_from_lima_ineligible(&args[2])
    }
    .map_err(|error| error.to_string())?;
    Ok(pin.to_json().to_string())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("host effect-events pin unavailable: {error}");
            std::process::exit(2);
        }
    }
}
