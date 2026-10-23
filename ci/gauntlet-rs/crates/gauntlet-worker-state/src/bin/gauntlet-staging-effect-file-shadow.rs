//! Read-only, ineligible held-file/writer diagnostic for a completed run.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<serde_json::Value, String> {
    use gauntlet_worker_state::staging_effect_file::observe_staging_fixed_provider_effect_ineligible;
    use gauntlet_worker_state::RunReservationJournal;
    use std::path::Path;

    let args: Vec<String> = std::env::args().collect();
    let signed_control = args.len() == 14 && args[13] == "--signed-control";
    let pinned_reader = (args.len() == 13 || signed_control) && args[11] == "--reader-sha";
    let kernel_report = (args.len() == 11 || pinned_reader) && args[9] == "--kernel-report-sha";
    if args.len() != 10 && !kernel_report {
        return Err("usage: gauntlet-staging-effect-file-shadow RUN_ID SOURCE_SHA DEPLOYMENT_SHA WORKER_SHA STARTED_SHA EFFECT_JOURNAL_SHA ROLE PROVIDER_SURFACE {OUTSIDE_PRODUCT_CGROUP | --kernel-report-sha HOST_PINNED_REPORT_SHA [--reader-sha READER_SHA [--signed-control]]}".to_owned());
    }
    if pinned_reader {
        gauntlet_worker_state::verify_running_binary(&args[12]).map_err(|e| e.to_string())?;
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(
        "/var/lib/hol-gauntlet-rust/staging-state",
    ))
    .map_err(|error| error.to_string())?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|error| error.to_string())?;
    let started = journal
        .started(&args[1], &args[2], &args[3], &args[4])
        .map_err(|error| error.to_string())?
        .ok_or("outside-pinned started marker is absent")?;
    if started.sha256 != args[5] || started.controller_public_key_hex.is_none() {
        return Err("effect file lacks the keyed outside started pin".to_owned());
    }
    if kernel_report {
        if signed_control {
            return gauntlet_worker_state::staging_product_effect::observe_signed_kernel_bound_provider_effect_ineligible(
                &journal, &lease, &started, &args[6], &args[10], &args[7], &args[8],
            );
        }
        return gauntlet_worker_state::staging_product_effect::observe_kernel_bound_provider_effect_ineligible(
            &journal, &lease, &started, &args[6], &args[10], &args[7], &args[8],
        );
    }
    observe_staging_fixed_provider_effect_ineligible(
        &journal, &lease, &started, &args[6], &args[7], &args[8], &args[9],
    )
    .map(|proof| proof.to_json())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux ARM64 Root effect-file diagnostic required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("staging effect-file diagnostic unavailable: {error}");
            std::process::exit(2);
        }
    }
}
