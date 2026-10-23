//! One-use Root diagnostic for the exact job AppArmor load/remove cycle.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        return Err("usage: gauntlet-builder-policy-shadow ABSOLUTE_CONTROLLER_ROOT CONTROLLER_TREE_SHA256 JOB_ID UV_IMAGE_ID RUST_IMAGE_ID IMAGE_ID".to_owned());
    }
    gauntlet_worker_state::prove_fixed_builder_policy_ineligible(
        std::path::Path::new(&args[1]),
        &args[2],
        &args[3],
        &args[4],
        &args[5],
        &args[6],
    )
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
            eprintln!("builder policy unavailable: {error}");
            std::process::exit(2);
        }
    }
}
