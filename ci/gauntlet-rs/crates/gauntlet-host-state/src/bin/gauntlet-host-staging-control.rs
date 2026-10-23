//! Fixed Mac-to-Lima transport for one diagnostic Rust-owned staging role.
//! The host pins the guest key before acknowledgement. No PR gate, candidate
//! deployment or conformance package is created by this command.

use gauntlet_contracts::{canonicalize, is_git_sha, WorkerRequest};
use gauntlet_evidence::valid_package_version;
use gauntlet_host_state::{HostControllerKeyPinJournal, HostPrelaunchIdentity};
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn run() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS Lima staging host artifact required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 15 {
        return Err("usage: gauntlet-host-staging-control PRIVATE_HOST_PIN_DIR BUILD_JOB RUN_ID SOURCE_SHA VERSION CONFIG_SHA PRIVATE_MANIFEST_SHA PREFIX_TREE_SHA CONTROLLER_GENERATION CONTROLLER_TREE_SHA PYTHON_DATE INTERPRETER_SHA GUEST_BINARY_SHA ROLE".to_owned());
    }
    let pin_dir = &args[1];
    let build_job = &args[2];
    let run_id = &args[3];
    let source = &args[4];
    let version = &args[5];
    let config = &args[6];
    let private_manifest = &args[7];
    let prefix = &args[8];
    let controller_generation = &args[9];
    let controller_tree = &args[10];
    let python_date = &args[11];
    let interpreter = &args[12];
    let binary = &args[13];
    let role = &args[14];
    if !lower_hex(build_job, 16)
        || !lower_hex(run_id, 16)
        || !is_git_sha(source)
        || !valid_package_version(version)
        || ![
            config,
            private_manifest,
            prefix,
            controller_tree,
            interpreter,
            binary,
        ]
        .iter()
        .all(|value| lower_hex(value, 64))
        || !lower_hex(controller_generation, 16)
        || python_date.len() != 8
        || !python_date.bytes().all(|byte| byte.is_ascii_digit())
        || !matches!(
            role.as_str(),
            "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
        )
    {
        return Err("fixed staging host pins are invalid".to_owned());
    }
    let controller_path = format!("/opt/hol-gauntlet/controller-{controller_generation}");
    let python_path = format!("/opt/hol-benchmark-controller-{python_date}/.venv/bin/python");
    let guest_binary = format!("/opt/hol-gauntlet/rust-staging-control-{binary}");
    let request_json = json!({
        "schema":"hol-gauntlet-worker-request.v1",
        "action":"run",
        "source_sha":source,
        "job_id":run_id,
        "deployment_digest":config,
    });
    let raw = canonicalize(request_json.to_string().as_bytes())
        .map_err(|_| "staging request could not be encoded".to_owned())?;
    let request = WorkerRequest::parse(&raw).map_err(|error| error.to_string())?;
    let defaults: Value = serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
        .map_err(|_| "compiled Lima defaults are invalid".to_owned())?;
    let limactl = defaults["limactl"]
        .as_str()
        .ok_or("compiled Lima executable is unavailable")?;
    let vm = defaults["vm"]
        .as_str()
        .ok_or("compiled Lima VM is unavailable")?;
    let journal = HostControllerKeyPinJournal::open(Path::new(pin_dir))
        .map_err(|error| format!("private host pin directory unavailable: {error}"))?;
    let child = Command::new(limactl)
        .args([
            "shell",
            vm,
            "--",
            "sudo",
            "-n",
            guest_binary.as_str(),
            build_job,
            run_id,
            source,
            version,
            config,
            private_manifest,
            prefix,
            controller_path.as_str(),
            controller_tree,
            python_path.as_str(),
            interpreter,
            binary,
            binary,
            role,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("Lima staging transport unavailable: {error}"))?;
    let expected = HostPrelaunchIdentity {
        source_sha: source.clone(),
        job_id: run_id.clone(),
        deployment_digest: config.clone(),
        worker_generation: binary.clone(),
    };
    let mut accepted = journal
        .send_run_request_and_accept_prepared_child(
            child,
            &request,
            &expected,
            Duration::from_secs(60),
        )
        .map_err(|failure| {
            format!(
                "staging prelaunch refused: {}; host pin recorded or uncertain: {}",
                failure.reason, failure.pin_recorded_or_uncertain
            )
        })?;
    let status = accepted
        .wait_bounded(Duration::from_secs(1850))
        .map_err(|error| {
            format!("staging guest exit unknown after host pin; reconcile VM: {error}")
        })?;
    if !status.success() {
        return Err(
            "staging guest failed after host pin; reconcile VM terminal and cleanup".to_owned(),
        );
    }
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-staging-control-diagnostic.v1",
            "run_id":run_id,
            "source_sha":source,
            "host_record_sha256":accepted.record().raw_sha256,
            "controller_public_key_hex":accepted.record().pins.controller_public_key_hex,
            "host_key_pinned_before_spawn":true,
            "guest_terminal_requires_readback":true,
            "execution_eligible":false,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("staging host unavailable: {error}");
        std::process::exit(2);
    }
}
