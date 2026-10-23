//! Root-only local candidate compile tied to a one-use outside host intent.
//! The result stays unadmitted until a separate host terminal reconciliation.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 19 {
        return Err("usage: gauntlet-local-candidate-hostbound-shadow CONTROLLER_ROOT CONTROLLER_TREE_SHA256 JOB_ID UV_IMAGE_ID RUST_IMAGE_ID BUILDER_IMAGE_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 VERSION TAG PODMAN_SHA256 SLIRP_SHA256 APPARMOR_PARSER_SHA256 SECCOMP_SHA256 POLICY_SHA256 RESULT_READER_BINARY_SHA256 HOST_PIN_SHA256 HOST_NONCE_HEX".to_owned());
    }
    const PREFIX: &str = "/opt/hol-gauntlet/rust-candidate-run-hostbound-shadow-";
    let runner_sha256 = args[0]
        .strip_prefix(PREFIX)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("exact hashed Root runner path required")?;
    let runtime = gauntlet_worker_state::CandidateRuntimePins::parse(
        &args[11], &args[12], &args[13], &args[14],
    )
    .map_err(|error| error.to_string())?;
    let anchor = gauntlet_worker_state::HostCandidateRunAnchor::parse_with_tag(
        &args[15],
        &args[16],
        &args[17],
        &args[18],
        runner_sha256,
        &args[10],
    )
    .ok_or("exact host candidate build anchor required")?;
    gauntlet_worker_state::run_fixed_local_candidate_hostbound_ineligible(
        std::path::Path::new(&args[1]),
        &args[2],
        &args[3],
        &args[4],
        &args[5],
        &args[6],
        &args[7],
        &args[8],
        &args[9],
        &args[10],
        runtime,
        anchor,
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
            eprintln!("host-bound candidate run unavailable: {error}");
            std::process::exit(2);
        }
    }
}
