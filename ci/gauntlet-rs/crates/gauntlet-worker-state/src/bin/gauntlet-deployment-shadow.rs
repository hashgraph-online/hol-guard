//! Read-only fixed-path ARM64 deployment declaration diagnostic.

#[cfg(target_os = "linux")]
use gauntlet_worker_state::{read_fixed_deployment, read_fixed_interpreter};
#[cfg(target_os = "linux")]
use serde_json::json;

#[cfg(target_os = "linux")]
fn run() -> Result<String, String> {
    if !cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        return Err("Linux ARM64 diagnostic artifact required".to_owned());
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "usage: gauntlet-deployment-shadow EXTERNAL_SOURCE_SHA EXTERNAL_DEPLOYMENT_SHA256 EXTERNAL_INTERPRETER_SHA256"
                .to_owned(),
        );
    }
    let declaration =
        read_fixed_deployment(&args[1], &args[2]).map_err(|error| error.to_string())?;
    let interpreter =
        read_fixed_interpreter(&declaration, &args[3]).map_err(|error| error.to_string())?;
    Ok(json!({
        "schema":"hol-gauntlet-deployment-shadow.v1",
        "source_sha":declaration.source_sha,
        "deployment_digest":declaration.deployment_digest,
        "config_digest":declaration.config_digest,
        "root_owned_declaration_and_config_verified":true,
        "controller_files_verified":false,
        "interpreter_target_path":interpreter.target_path,
        "interpreter_target_sha256":interpreter.sha256,
        "interpreter_target_verified":true,
        "interpreter_execution_bound":false,
        "full_asset_inventory_verified":false,
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
            eprintln!("deployment shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
