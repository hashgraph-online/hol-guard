//! Uninstalled, read-only Linux ARM64 check for one Rust job's slice absence.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<serde_json::Value, String> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("usage: gauntlet-job-slice-shadow JOB_ID".to_owned());
    }
    let job_id = args[1]
        .to_str()
        .ok_or_else(|| "job ID must be lowercase ASCII".to_owned())?;
    gauntlet_worker_state::require_rust_job_slice_absent(job_id)
        .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "schema": "hol-gauntlet-rust-job-slice-shadow.v1",
        "job_id": job_id,
        "slice_absent": true,
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
            eprintln!("job slice shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
