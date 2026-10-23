//! Uninstalled read-only Linux ARM64 prelaunch diagnostic. Never dispatches.

#[cfg(target_os = "linux")]
use gauntlet_contracts::WorkerRequest;
#[cfg(target_os = "linux")]
use gauntlet_worker_state::{prepare_fixed_prelaunch, PrelaunchPins};
#[cfg(target_os = "linux")]
use std::io::Read;

#[cfg(target_os = "linux")]
fn run() -> Result<String, String> {
    if !cfg!(target_arch = "aarch64") {
        return Err("Linux ARM64 diagnostic artifact required".to_owned());
    }
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 {
        return Err(
            "usage: gauntlet-prelaunch-shadow EXTERNAL_SOURCE_SHA EXTERNAL_DEPLOYMENT_SHA256 EXTERNAL_CONTROLLER_TREE_SHA256 EXTERNAL_INTERPRETER_SHA256"
                .to_owned(),
        );
    }
    let mut pins = Vec::new();
    for item in &args[1..] {
        pins.push(
            item.to_str()
                .ok_or_else(|| "outside pins must be lowercase ASCII".to_owned())?
                .to_owned(),
        );
    }
    let mut raw = Vec::new();
    std::io::stdin()
        .take(1025)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() > 1024 {
        return Err("worker request exceeds 1024 bytes".to_owned());
    }
    let request = WorkerRequest::parse(&raw).map_err(|error| error.to_string())?;
    let pins = PrelaunchPins {
        source_sha: pins.remove(0),
        deployment_digest: pins.remove(0),
        controller_tree_digest: pins.remove(0),
        interpreter_sha256: pins.remove(0),
    };
    prepare_fixed_prelaunch(&request, &pins)
        .map(|prepared| prepared.proof().to_json().to_string())
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("prelaunch shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
