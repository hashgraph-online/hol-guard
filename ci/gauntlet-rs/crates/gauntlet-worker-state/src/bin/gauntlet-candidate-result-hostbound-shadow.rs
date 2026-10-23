//! Read-only Root reconciliation of a retained, host-bound candidate result.
//! A matching host journal remains necessary before any artifact admission.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 18 && args.len() != 19 {
        return Err("usage: gauntlet-candidate-result-hostbound-shadow JOB_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 RESULT_SHA256 EXPORT_ARCHIVE_SHA256 VERSION [TAG] CONTROLLER_TREE_SHA256 BUILDER_IMAGE_ID POLICY_SHA256 PODMAN_SHA256 SLIRP_SHA256 APPARMOR_PARSER_SHA256 SECCOMP_SHA256 RUNNER_BINARY_SHA256 READER_BINARY_SHA256 HOST_PIN_SHA256 HOST_NONCE_HEX".to_owned());
    }
    let offset = usize::from(args.len() == 19);
    const PREFIX: &str = "/opt/hol-gauntlet/rust-candidate-result-hostbound-shadow-";
    let path_sha256 = args[0]
        .strip_prefix(PREFIX)
        .ok_or("exact hashed Root result reader path required")?;
    if path_sha256 != args[15 + offset] {
        return Err("reader path differs from outside binary pin".to_owned());
    }
    let runtime = gauntlet_worker_state::CandidateRuntimePins::parse(
        &args[10 + offset],
        &args[11 + offset],
        &args[12 + offset],
        &args[13 + offset],
    )
    .map_err(|error| error.to_string())?;
    let anchor = if offset == 1 {
        gauntlet_worker_state::HostCandidateRunAnchor::parse_with_tag(
            &args[9 + offset],
            &args[15 + offset],
            &args[16 + offset],
            &args[17 + offset],
            &args[14 + offset],
            &args[7],
        )
    } else {
        gauntlet_worker_state::HostCandidateRunAnchor::parse(
            &args[9], &args[15], &args[16], &args[17], &args[14],
        )
    }
    .ok_or("exact host candidate build anchor required")?;
    let pins = gauntlet_worker_state::HostBoundCandidateResultPins {
        job_id: args[1].clone(),
        source_sha: args[2].clone(),
        source_archive_sha256: args[3].clone(),
        result_sha256: args[4].clone(),
        archive_sha256: args[5].clone(),
        version: args[6].clone(),
        tag: if offset == 1 {
            Some(args[7].clone())
        } else {
            None
        },
        controller_tree_sha256: args[7 + offset].clone(),
        image_id: args[8 + offset].clone(),
        policy_sha256: args[9 + offset].clone(),
        runtime,
        anchor,
    };
    gauntlet_worker_state::read_fixed_hostbound_candidate_result_ineligible(&pins)
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
            eprintln!("host-bound candidate result unavailable: {error}");
            std::process::exit(2);
        }
    }
}
