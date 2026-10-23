//! Explicit v2 SDK tap diagnostic. This binary is separate from the v1
//! staging control and always finishes with invalid-evidence.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use gauntlet_worker_state::{
    read_run_request_pipe, run_fixed_candidate_staging_control_sdk_tap_pidns_ineligible,
    run_fixed_candidate_staging_control_sdk_tap_root_relay_ineligible,
    run_fixed_candidate_staging_control_sdk_tap_v2_ineligible, verify_running_binary,
    BoottimeDeadline, CandidateSdkTapPins, CandidateStagingRunPins, StagingRole,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
static CANCELLED: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
extern "C" fn request_cancel(_signal: libc::c_int) {
    CANCELLED.store(true, Ordering::Release);
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let pidns = args.len() == 18 && args[17] == "--pidns";
    let root_relay = args.len() == 18 && args[17] == "--root-relay";
    if args.len() != 17 && !pidns && !root_relay {
        return Err("usage: gauntlet-candidate-staging-control-tap BUILD_JOB RUN_ID SOURCE_SHA VERSION CONFIG_SHA PRIVATE_MANIFEST_SHA PREFIX_TREE_SHA CONTROLLER_PATH CONTROLLER_TREE_SHA PYTHON_PATH INTERPRETER_SHA WORKER_GENERATION_SHA BINARY_SHA ROLE TAP_CHILD_PATH TAP_CHILD_SHA [--pidns|--root-relay]".to_owned());
    }
    if args[12] != args[13] {
        return Err("outside worker generation must equal installed binary digest".to_owned());
    }
    verify_running_binary(&args[13]).map_err(|error| error.to_string())?;
    if args[16].len() != 64
        || !args[16]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || args[15] != format!("/opt/hol-gauntlet/rust-sdk-tap-child-{}", &args[16][..16])
    {
        return Err("fixed outside-pinned SDK tap child installation required".to_owned());
    }
    let role = args[14]
        .parse::<StagingRole>()
        .map_err(|error| error.to_string())?;
    // SAFETY: the handler only sets one lock-free atomic flag.
    unsafe {
        if libc::signal(libc::SIGTERM, request_cancel as libc::sighandler_t) == libc::SIG_ERR
            || libc::signal(libc::SIGINT, request_cancel as libc::sighandler_t) == libc::SIG_ERR
        {
            return Err("staging cancellation handler unavailable".to_owned());
        }
    }
    let deadline = BoottimeDeadline::start(1800).map_err(|error| error.to_string())?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let request =
        read_run_request_pipe(&stdin, &deadline, &CANCELLED).map_err(|error| error.to_string())?;
    let pins = CandidateStagingRunPins {
        build_job_id: &args[1],
        run_id: &args[2],
        source_sha: &args[3],
        version: &args[4],
        config_digest: &args[5],
        private_manifest_sha256: &args[6],
        prefix_tree_sha256: &args[7],
        controller_path: &args[8],
        controller_tree_sha256: &args[9],
        python_path: &args[10],
        interpreter_sha256: &args[11],
        worker_generation_sha256: &args[12],
        role,
    };
    let tap_pins = CandidateSdkTapPins {
        executable_path: &args[15],
        executable_sha256: &args[16],
    };
    let result = if root_relay {
        run_fixed_candidate_staging_control_sdk_tap_root_relay_ineligible(
            &pins, &tap_pins, &request, &deadline, &CANCELLED, &stdout, &stdin,
        )
    } else if pidns {
        run_fixed_candidate_staging_control_sdk_tap_pidns_ineligible(
            &pins, &tap_pins, &request, &deadline, &CANCELLED, &stdout, &stdin,
        )
    } else {
        run_fixed_candidate_staging_control_sdk_tap_v2_ineligible(
            &pins, &tap_pins, &request, &deadline, &CANCELLED, &stdout, &stdin,
        )
    }
    .map_err(|error| format!("staging tap control remains unresolved: {error}"))?;
    println!("{}", result.to_json());
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<(), String> {
    Err("Linux ARM64 Root staging tap worker artifact required".to_owned())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("staging tap control unavailable: {error}");
        std::process::exit(2);
    }
}
