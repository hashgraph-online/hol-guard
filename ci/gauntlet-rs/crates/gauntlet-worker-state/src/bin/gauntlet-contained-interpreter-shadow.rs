//! Uninstalled Linux ARM64 Root probe for inert descriptor-bound execution
//! inside the fixed cgroup, after dropping the child to nobody.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    use gauntlet_worker_state::{
        read_fixed_deployment, read_fixed_interpreter_held, run_fixed_contained_interpreter_probe,
    };
    use serde_json::json;

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: gauntlet-contained-interpreter-shadow EXTERNAL_SOURCE_SHA EXTERNAL_DEPLOYMENT_SHA256 EXTERNAL_INTERPRETER_SHA256".to_owned());
    }
    let deployment =
        read_fixed_deployment(&args[1], &args[2]).map_err(|error| error.to_string())?;
    let interpreter =
        read_fixed_interpreter_held(&deployment, &args[3]).map_err(|error| error.to_string())?;
    let proof =
        run_fixed_contained_interpreter_probe(&interpreter).map_err(|error| error.to_string())?;
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

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("contained interpreter shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
