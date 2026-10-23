//! Inert macOS-to-Lima prelaunch exchange. The guest emits ephemeral values
//! without reserving a job or launching a controller.

use gauntlet_contracts::{canonicalize, is_git_sha, WorkerRequest};
use gauntlet_host_state::{HostControllerKeyPinJournal, HostPrelaunchIdentity};
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn run() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS Lima host artifact required".to_owned());
    }
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 7 {
        return Err("usage: gauntlet-host-prelaunch-wire-shadow PRIVATE_0700_PIN_DIRECTORY SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_GENERATION_SHA256 GUEST_BINARY_SHA256".to_owned());
    }
    let text = |index: usize| {
        args[index]
            .to_str()
            .ok_or_else(|| "outside pins must be UTF-8".to_owned())
    };
    let source = text(2)?;
    let job = text(3)?;
    let deployment = text(4)?;
    let generation = text(5)?;
    let binary = text(6)?;
    if !is_git_sha(source)
        || !lower_hex(job, 16)
        || !lower_hex(deployment, 64)
        || !lower_hex(generation, 64)
        || !lower_hex(binary, 64)
    {
        return Err("outside wire-probe pins are invalid".to_owned());
    }
    let journal = HostControllerKeyPinJournal::open(Path::new(&args[1]))
        .map_err(|error| format!("private host pin directory unavailable: {error}"))?;
    let request_json = json!({
        "schema":"hol-gauntlet-worker-request.v1",
        "action":"run",
        "source_sha":source,
        "job_id":job,
        "deployment_digest":deployment,
    });
    let request_raw = canonicalize(request_json.to_string().as_bytes())
        .map_err(|_| "wire probe request could not be encoded".to_owned())?;
    let request = WorkerRequest::parse(&request_raw)
        .map_err(|_| "wire probe request is invalid".to_owned())?;
    let defaults: Value =
        serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
            .map_err(|_| "compiled public operations defaults are invalid".to_owned())?;
    let limactl = defaults["limactl"]
        .as_str()
        .ok_or_else(|| "compiled Lima path unavailable".to_owned())?;
    let vm = defaults["vm"]
        .as_str()
        .ok_or_else(|| "compiled VM name unavailable".to_owned())?;
    let binary_path = format!("/opt/hol-gauntlet/rust-prelaunch-wire-shadow-{binary}");
    let child = Command::new(limactl)
        .args([
            "shell",
            vm,
            "--",
            binary_path.as_str(),
            source,
            job,
            deployment,
            generation,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Lima wire-probe process unavailable".to_owned())?;
    let expected = HostPrelaunchIdentity {
        source_sha: source.to_owned(),
        job_id: job.to_owned(),
        deployment_digest: deployment.to_owned(),
        worker_generation: generation.to_owned(),
    };
    let mut accepted = journal
        .send_run_request_and_accept_prepared_child(
            child,
            &request,
            &expected,
            Duration::from_secs(10),
        )
        .map_err(|failure| {
            format!(
                "Lima prelaunch exchange refused: {}; host pin recorded or uncertain: {}",
                failure.reason, failure.pin_recorded_or_uncertain
            )
        })?;
    let status = accepted
        .wait_bounded(Duration::from_secs(10))
        .map_err(|error| format!("Lima child exit uncertain after host pin: {error}"))?;
    if !status.success() {
        return Err("Lima child exited unsuccessfully after host pin".to_owned());
    }
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-inert-prelaunch-wire-proof.v1",
            "job_id":job,
            "source_sha":source,
            "host_record_sha256":accepted.record().raw_sha256,
            "guest_ephemeral_public_key_hex":accepted.record().pins.controller_public_key_hex,
            "synthetic_guest_values":true,
            "bounded_run_request_exchanged":true,
            "durable_guest_started_marker":false,
            "controller_executed":false,
            "execution_eligible":false,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
