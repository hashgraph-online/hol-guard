//! Uninstalled Linux ARM64 Root diagnostic for one inert source capture.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: gauntlet-builder-source-capture-shadow JOB_ID SOURCE_ARCHIVE_SHA256".to_owned(),
        );
    }
    gauntlet_worker_state::capture_fixed_guest_source_archive(&args[1], &args[2])
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
            eprintln!("builder source capture unavailable: {error}");
            std::process::exit(2);
        }
    }
}
