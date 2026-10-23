//! Read-only Linux ARM shadow entrypoint. It cannot start a benchmark job.

use gauntlet_contracts::WorkerRequest;
use gauntlet_worker_state::RunReservationJournal;
use std::io::{Read, Write};
use std::path::Path;

const STATE_ROOT: &str = "/var/lib/hol-gauntlet-rust/worker-state";
const MAX_REQUEST_BYTES: u64 = 1024;

fn run() -> Result<Vec<u8>, String> {
    if !cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        return Err("Linux ARM64 worker artifact required".to_owned());
    }
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 4 {
        return Err(
            "usage: gauntlet-vm-worker-shadow EXTERNAL_SOURCE_SHA EXTERNAL_DEPLOYMENT_SHA256 EXTERNAL_WORKER_GENERATION_SHA256"
                .to_owned(),
        );
    }
    let source = arguments[1]
        .to_str()
        .ok_or_else(|| "source pin must be lowercase ASCII".to_owned())?;
    let deployment = arguments[2]
        .to_str()
        .ok_or_else(|| "deployment pin must be lowercase ASCII".to_owned())?;
    let generation = arguments[3]
        .to_str()
        .ok_or_else(|| "worker-generation pin must be lowercase ASCII".to_owned())?;
    let mut raw = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() as u64 > MAX_REQUEST_BYTES {
        return Err("worker request exceeds 1024 bytes".to_owned());
    }
    let request = WorkerRequest::parse(&raw).map_err(|error| error.to_string())?;
    let journal = RunReservationJournal::open_root_owned(Path::new(STATE_ROOT))
        .map_err(|error| error.to_string())?;
    journal
        .project_read_only(&request, source, Some(deployment), generation)
        .map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(response) => {
            let mut stdout = std::io::stdout().lock();
            if stdout.write_all(&response).is_err() || stdout.write_all(b"\n").is_err() {
                eprintln!("failed to write worker shadow response");
                std::process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("worker shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
