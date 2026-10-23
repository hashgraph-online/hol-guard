//! Uninstalled Linux ARM64 probe of one fixed, inert job-derived cgroup.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    if std::env::args_os().len() != 1 {
        return Err("usage: gauntlet-job-cgroup-probe".to_owned());
    }
    gauntlet_worker_state::run_fixed_job_cgroup_probe()
        .map(|proof| proof.to_json().to_string())
        .map_err(|error| error.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("job cgroup probe unavailable: {error}");
            std::process::exit(2);
        }
    }
}
