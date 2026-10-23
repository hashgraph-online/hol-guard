//! One-use Root diagnostic that writes only the trusted builder image context.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: gauntlet-builder-image-context-shadow ABSOLUTE_CONTROLLER_ROOT CONTROLLER_TREE_SHA256 JOB_ID UV_IMAGE_ID RUST_IMAGE_ID".to_owned());
    }
    gauntlet_worker_state::materialize_fixed_builder_image_context(
        std::path::Path::new(&args[1]),
        &args[2],
        &args[3],
        &args[4],
        &args[5],
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
            eprintln!("builder image context unavailable: {error}");
            std::process::exit(2);
        }
    }
}
