//! Uninstalled Linux ARM64 Root diagnostic for local-only base image custody.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: gauntlet-builder-image-shadow ABSOLUTE_CONTROLLER_ROOT CONTROLLER_TREE_SHA256 JOB_ID UV_IMAGE_ID RUST_IMAGE_ID".to_owned());
    }
    let context = gauntlet_worker_state::inspect_fixed_builder_context(
        std::path::Path::new(&args[1]),
        &args[2],
        &args[3],
    )
    .map_err(|error| error.to_string())?;
    let plan =
        gauntlet_worker_state::fixed_builder_image_plan(&context, &args[3], &args[4], &args[5])
            .map_err(|error| error.to_string())?;
    gauntlet_worker_state::inspect_fixed_builder_base_images(&plan)
        .map_err(|error| error.to_string())?;
    let mut report = plan.to_json();
    report["base_images_verified"] = true.into();
    Ok(report.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("builder image plan unavailable: {error}");
            std::process::exit(2);
        }
    }
}
