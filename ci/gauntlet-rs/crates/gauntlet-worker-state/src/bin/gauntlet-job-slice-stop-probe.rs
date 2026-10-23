//! Uninstalled Linux ARM64 probe. It can stop only the fixed inert test slice;
//! it never runs a controller or writes a worker receipt.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<serde_json::Value, String> {
    if std::env::args_os().len() != 1 {
        return Err("usage: gauntlet-job-slice-stop-probe".to_owned());
    }
    let proof = gauntlet_worker_state::stop_rust_job_slice("fedcba9876543210")
        .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "schema": "hol-gauntlet-rust-job-slice-stop-probe.v1",
        "job_id": "fedcba9876543210",
        "slice": proof.slice_name,
        "stop_invoked": proof.stop_invoked,
        "slice_absent": proof.slice_absent,
        "execution_eligible": false,
    }))
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("job slice stop probe unavailable: {error}");
            std::process::exit(2);
        }
    }
}
