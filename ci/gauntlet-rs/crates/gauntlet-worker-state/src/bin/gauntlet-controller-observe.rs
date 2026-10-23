//! Report an observed whole-tree digest for audit; never treat it as a pin.

#[cfg(target_os = "linux")]
use gauntlet_evidence::{inventory_tree, TreeKind};
#[cfg(target_os = "linux")]
use gauntlet_worker_state::read_fixed_deployment;
#[cfg(target_os = "linux")]
use rustix::process::geteuid;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
fn run() -> Result<String, String> {
    if !cfg!(target_arch = "aarch64") || geteuid().as_raw() != 0 {
        return Err("Linux ARM64 Root diagnostic required".to_owned());
    }
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err(
            "usage: gauntlet-controller-observe EXTERNAL_SOURCE_SHA EXTERNAL_DEPLOYMENT_SHA256"
                .to_owned(),
        );
    }
    let source = args[1]
        .to_str()
        .ok_or_else(|| "source pin must be lowercase ASCII".to_owned())?;
    let manifest = args[2]
        .to_str()
        .ok_or_else(|| "deployment pin must be lowercase ASCII".to_owned())?;
    let deployment = read_fixed_deployment(source, manifest).map_err(|error| error.to_string())?;
    let observed = inventory_tree(Path::new(&deployment.controller_path), TreeKind::Controller)
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "schema":"hol-gauntlet-controller-observation.v1",
        "source_sha":deployment.source_sha,
        "deployment_digest":deployment.deployment_digest,
        "controller_tree_digest_observed":observed.digest,
        "controller_tree_entries":observed.entries,
        "controller_tree_bytes":observed.bytes,
        "outside_controller_pin_verified":false,
        "reviewed_install_anchor":false,
        "execution_eligible":false,
    })
    .to_string())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 Root diagnostic required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("controller observation unavailable: {error}");
            std::process::exit(2);
        }
    }
}
