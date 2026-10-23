//! Inert ARM64 wire probe: an ephemeral key and hashes, with no job marker,
//! sidecar, controller, product cell or benchmark execution.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<(), String> {
    use gauntlet_contracts::PrelaunchPrepared;
    use gauntlet_worker_state::{exchange_prelaunch_pipe, read_run_request_pipe, BoottimeDeadline};
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::AtomicBool;

    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 {
        return Err("usage: gauntlet-prelaunch-wire-shadow SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_GENERATION_SHA256".to_owned());
    }
    let text = |index: usize| {
        args[index]
            .to_str()
            .ok_or_else(|| "outside pins must be UTF-8".to_owned())
    };
    let deadline = BoottimeDeadline::start(10).map_err(|error| error.to_string())?;
    let cancellation = AtomicBool::new(false);
    let request = read_run_request_pipe(&std::io::stdin(), &deadline, &cancellation)
        .map_err(|error| error.to_string())?;
    if request.job_id() != text(2)? || !request.matches_deployment(text(1)?, text(3)?) {
        return Err("wire probe request differs from outside pins".to_owned());
    }
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| "wire probe randomness unavailable".to_owned())?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| "wire probe key unavailable".to_owned())?;
    let mut started_hash = Sha256::new();
    started_hash.update(b"inert-started:");
    started_hash.update(seed);
    let mut key_hash = Sha256::new();
    key_hash.update(b"inert-key:");
    key_hash.update(seed);
    let prepared = PrelaunchPrepared {
        source_sha: text(1)?.to_owned(),
        job_id: text(2)?.to_owned(),
        deployment_digest: text(3)?.to_owned(),
        worker_generation: text(4)?.to_owned(),
        started_marker_sha256: format!("{:x}", started_hash.finalize()),
        controller_key_pin_sha256: format!("{:x}", key_hash.finalize()),
        controller_public_key_hex: pair
            .public_key()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    };
    let raw = prepared.to_bytes().map_err(|error| error.to_string())?;
    exchange_prelaunch_pipe(
        &raw,
        &std::io::stdout(),
        &std::io::stdin(),
        &deadline,
        &cancellation,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<(), String> {
    Err("Linux ARM64 wire probe required".to_owned())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("prelaunch wire shadow unavailable: {error}");
        std::process::exit(2);
    }
}
