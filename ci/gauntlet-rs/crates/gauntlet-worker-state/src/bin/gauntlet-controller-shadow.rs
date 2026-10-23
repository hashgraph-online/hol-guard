//! Uninstalled, read-only Linux ARM64 controller source diagnostic.

#[cfg(target_os = "linux")]
use gauntlet_evidence::verify_controller_tree;
#[cfg(target_os = "linux")]
use gauntlet_worker_state::read_fixed_deployment;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
fn run() -> Result<String, String> {
    if !cfg!(target_arch = "aarch64") {
        return Err("Linux ARM64 diagnostic artifact required".to_owned());
    }
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err(
            "usage: gauntlet-controller-shadow EXTERNAL_SOURCE_SHA EXTERNAL_DEPLOYMENT_SHA256 EXTERNAL_CONTROLLER_TREE_SHA256"
                .to_owned(),
        );
    }
    let source = args[1]
        .to_str()
        .ok_or_else(|| "source pin must be UTF-8".to_owned())?;
    let manifest = args[2]
        .to_str()
        .ok_or_else(|| "deployment pin must be UTF-8".to_owned())?;
    let controller = args[3]
        .to_str()
        .ok_or_else(|| "controller pin must be UTF-8".to_owned())?;
    let deployment = read_fixed_deployment(source, manifest).map_err(|error| error.to_string())?;
    let tree = verify_controller_tree(Path::new(&deployment.controller_path), controller)
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "schema":"hol-gauntlet-controller-shadow.v1",
        "source_sha":deployment.source_sha,
        "deployment_digest":deployment.deployment_digest,
        "controller_tree_digest":tree.digest(),
        "controller_tree_entries":tree.entries(),
        "controller_tree_bytes":tree.bytes(),
        "controller_tree_verified":true,
        "reviewed_install_anchor":false,
        "execution_eligible":false,
    })
    .to_string())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("controller shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
