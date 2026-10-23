//! Uninstalled, read-only macOS local model-provider preflight diagnostic.

use gauntlet_host_state::observe_live_provider_preflight_shadow;
use std::path::Path;

fn run() -> Result<(), &'static str> {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.len() != 6 {
        return Err("usage: gauntlet-host-provider-preflight-shadow JOB_ID PROFILE CANDIDATE_SOURCE_SHA TEMPLATE_BINDING_JSON ALLOWANCE_JSON");
    }
    let result = observe_live_provider_preflight_shadow(
        &arguments[1],
        &arguments[2],
        &arguments[3],
        Path::new(&arguments[4]),
        Path::new(&arguments[5]),
    )?;
    println!("{result}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("host provider preflight shadow unavailable: {error}");
        std::process::exit(2);
    }
}
