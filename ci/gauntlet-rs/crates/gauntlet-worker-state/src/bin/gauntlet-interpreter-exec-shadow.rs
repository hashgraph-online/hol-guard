//! Uninstalled inert probe for one outside-pinned Root-owned Python binary.

#[cfg(target_os = "linux")]
use gauntlet_worker_state::{
    probe_verified_interpreter_exec, read_fixed_deployment, read_fixed_interpreter_held,
};
#[cfg(target_os = "linux")]
use serde_json::json;

#[cfg(target_os = "linux")]
fn run() -> Result<String, String> {
    if !cfg!(target_arch = "aarch64") {
        return Err("Linux ARM64 diagnostic artifact required".to_owned());
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "usage: gauntlet-interpreter-exec-shadow EXTERNAL_SOURCE_SHA EXTERNAL_DEPLOYMENT_SHA256 EXTERNAL_INTERPRETER_SHA256"
                .to_owned(),
        );
    }
    let deployment =
        read_fixed_deployment(&args[1], &args[2]).map_err(|error| error.to_string())?;
    let interpreter =
        read_fixed_interpreter_held(&deployment, &args[3]).map_err(|error| error.to_string())?;
    let proof = probe_verified_interpreter_exec(&interpreter).map_err(|error| error.to_string())?;
    Ok(json!({
        "probe":proof.to_json(),
        "source_sha":deployment.source_sha,
        "deployment_digest":deployment.deployment_digest,
        "controller_files_verified":false,
        "benchmark_executed":false,
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
            eprintln!("interpreter exec shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
