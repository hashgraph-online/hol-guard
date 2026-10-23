//! One Linux ARM64 deterministic run under the Rust Root worker. The keyed
//! terminal is always invalid-evidence until independent controls are scored.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use gauntlet_worker_state::{
    read_run_request_pipe, run_fixed_deterministic_controller_pipe_ineligible,
    verify_running_binary, BoottimeDeadline, PrelaunchPins,
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
    if args.len() != 7 {
        return Err("usage: gauntlet-deterministic-run-diagnostic SOURCE_SHA DEPLOYMENT_SHA256 CONTROLLER_TREE_SHA256 INTERPRETER_SHA256 WORKER_GENERATION_SHA256 BINARY_SHA256".to_owned());
    }
    if args[5] != args[6] {
        return Err("outside worker generation must equal installed binary digest".to_owned());
    }
    verify_running_binary(&args[6]).map_err(|error| error.to_string())?;
    // SAFETY: the handler sets only one lock-free atomic flag.
    unsafe {
        if libc::signal(libc::SIGTERM, request_cancel as libc::sighandler_t) == libc::SIG_ERR
            || libc::signal(libc::SIGINT, request_cancel as libc::sighandler_t) == libc::SIG_ERR
        {
            return Err("controller cancellation handler unavailable".to_owned());
        }
    }
    let deadline = BoottimeDeadline::start(1800).map_err(|error| error.to_string())?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let request =
        read_run_request_pipe(&stdin, &deadline, &CANCELLED).map_err(|error| error.to_string())?;
    let pins = PrelaunchPins {
        source_sha: args[1].clone(),
        deployment_digest: args[2].clone(),
        controller_tree_digest: args[3].clone(),
        interpreter_sha256: args[4].clone(),
    };
    let result = run_fixed_deterministic_controller_pipe_ineligible(
        &pins, &request, &args[5], 1800, &CANCELLED, &stdout, &stdin,
    )?;
    println!("{result}");
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<(), String> {
    Err("Linux ARM64 Root deterministic worker artifact required".to_owned())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("deterministic run unresolved: {error}");
        std::process::exit(2);
    }
}
