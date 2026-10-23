//! Fixed Mac-to-Lima transport for one Rust-owned deterministic diagnostic.
//! The host key is durable before the controller starts; the resulting worker
//! terminal is deliberately invalid-evidence, never a PR gate verdict.

use gauntlet_contracts::{canonicalize, is_git_sha, WorkerRequest};
use gauntlet_host_state::{HostControllerKeyPinJournal, HostKeyPinRecord, HostPrelaunchIdentity};
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

fn validate_guest_result(raw: &[u8], pin: &HostKeyPinRecord) -> Result<Value, String> {
    let line = raw
        .strip_suffix(b"\n")
        .ok_or("guest final result has no newline")?;
    if line.is_empty() || line.contains(&b'\n') {
        return Err("guest final result is not one line".to_owned());
    }
    if canonicalize(line).map_err(|_| "guest final result is invalid JSON")? != line {
        return Err("guest final result is not canonical".to_owned());
    }
    let value: Value =
        serde_json::from_slice(line).map_err(|_| "guest final result is invalid JSON")?;
    let fields = value
        .as_object()
        .ok_or("guest final result must be an object")?;
    if fields.len() != 14
        || value["schema"] != "hol-gauntlet-rust-deterministic-run-result.v1"
        || value["job_id"] != pin.pins.job_id
        || value["source_sha"] != pin.pins.source_sha
        || value["started_marker_sha256"] != pin.pins.started_marker_sha256
        || value["controller_key_pin_sha256"] != pin.pins.controller_key_pin_sha256
        || value["controller_public_key_hex"] != pin.pins.controller_public_key_hex
        || !value["deterministic_report_sha256"]
            .as_str()
            .is_some_and(|hash| lower_hex(hash, 64))
        || !value["diagnostic_report_sha256"]
            .as_str()
            .is_some_and(|hash| lower_hex(hash, 64))
        || !value["terminal_sha256"]
            .as_str()
            .is_some_and(|hash| lower_hex(hash, 64))
        || !value["exit_code"]
            .as_i64()
            .is_some_and(|code| (-128..=255).contains(&code))
        || !matches!(
            value["producer_status_claim"].as_str(),
            Some("passed" | "failed" | "invalid-evidence")
        )
        || !value["signed_openings_observed"].is_boolean()
        || value["independent_control_verdict"] != false
        || value["execution_eligible"] != false
    {
        return Err("guest final result differs from the durable host pin".to_owned());
    }
    Ok(value)
}

fn run() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS Lima host artifact required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 9 {
        return Err("usage: gauntlet-host-deterministic-run-diagnostic PRIVATE_HOST_PIN_DIR SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 CONTROLLER_TREE_SHA256 INTERPRETER_SHA256 GUEST_BINARY_SHA256 READBACK_BINARY_SHA256".to_owned());
    }
    let pin_dir = &args[1];
    let source = &args[2];
    let job = &args[3];
    let deployment = &args[4];
    let controller = &args[5];
    let interpreter = &args[6];
    let binary = &args[7];
    let readback_binary = &args[8];
    if !is_git_sha(source)
        || !lower_hex(job, 16)
        || ![deployment, controller, interpreter, binary, readback_binary]
            .iter()
            .all(|value| lower_hex(value, 64))
    {
        return Err("outside deterministic-run pins are invalid".to_owned());
    }
    let journal = HostControllerKeyPinJournal::open(Path::new(pin_dir))
        .map_err(|error| format!("private host pin directory unavailable: {error}"))?;
    let request_json = json!({
        "schema":"hol-gauntlet-worker-request.v1",
        "action":"run",
        "source_sha":source,
        "job_id":job,
        "deployment_digest":deployment,
    });
    let raw = canonicalize(request_json.to_string().as_bytes())
        .map_err(|_| "deterministic request could not be encoded".to_owned())?;
    let request = WorkerRequest::parse(&raw).map_err(|error| error.to_string())?;
    let defaults: Value = serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
        .map_err(|_| "compiled Lima defaults are invalid".to_owned())?;
    let limactl = defaults["limactl"]
        .as_str()
        .ok_or("compiled Lima executable is unavailable")?;
    let vm = defaults["vm"]
        .as_str()
        .ok_or("compiled Lima VM is unavailable")?;
    let guest_binary = format!("/opt/hol-gauntlet/rust-deterministic-run-{binary}");
    let child = Command::new(limactl)
        .args([
            "shell",
            vm,
            "--",
            "sudo",
            "-n",
            guest_binary.as_str(),
            source,
            deployment,
            controller,
            interpreter,
            binary,
            binary,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("Lima deterministic transport unavailable: {error}"))?;
    let expected = HostPrelaunchIdentity {
        source_sha: source.clone(),
        job_id: job.clone(),
        deployment_digest: deployment.clone(),
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
                "deterministic prelaunch refused: {}; host pin recorded or uncertain: {}",
                failure.reason, failure.pin_recorded_or_uncertain
            )
        })?;
    let guest_raw = accepted
        .wait_bounded_result(Duration::from_secs(1850), 4096)
        .map_err(|error| format!("guest result unknown after host pin; reconcile VM: {error}"))?;
    let guest = validate_guest_result(&guest_raw, accepted.record())?;
    let retained = journal
        .read(job)
        .map_err(|error| format!("host pin changed before readback: {error}"))?;
    if retained != *accepted.record() {
        return Err("host pin changed before readback".to_owned());
    }
    let readback = retained
        .observe_fixed_vm_deterministic_readback(
            limactl,
            vm,
            readback_binary,
            guest["terminal_sha256"]
                .as_str()
                .ok_or("guest terminal hash unavailable")?,
            guest["diagnostic_report_sha256"]
                .as_str()
                .ok_or("guest diagnostic report hash unavailable")?,
            guest["deterministic_report_sha256"]
                .as_str()
                .ok_or("guest deterministic report hash unavailable")?,
        )
        .map_err(|error| format!("keyed VM terminal readback refused: {error}"))?;
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-deterministic-run-diagnostic.v1",
            "job_id":job,
            "source_sha":source,
            "host_record_sha256":accepted.record().raw_sha256,
            "controller_public_key_hex":accepted.record().pins.controller_public_key_hex,
            "host_key_pinned_before_spawn":true,
            "keyed_guest_readback":readback.to_json(),
            "guest_terminal_readback_verified":true,
            "deterministic_report_digest_reopened_in_vm":true,
            "independent_control_verdict":false,
            "execution_eligible":false,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("deterministic host run unavailable: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gauntlet_host_state::HostControllerKeyPins;

    fn pin() -> HostKeyPinRecord {
        HostKeyPinRecord {
            pins: HostControllerKeyPins {
                job_id: "a".repeat(16),
                source_sha: "b".repeat(40),
                deployment_digest: "c".repeat(64),
                worker_generation: "d".repeat(64),
                started_marker_sha256: "e".repeat(64),
                controller_key_pin_sha256: "f".repeat(64),
                controller_public_key_hex: "0".repeat(64),
            },
            raw_sha256: "1".repeat(64),
        }
    }

    fn result(pin: &HostKeyPinRecord) -> Vec<u8> {
        let value = json!({
            "schema":"hol-gauntlet-rust-deterministic-run-result.v1",
            "job_id":pin.pins.job_id,
            "source_sha":pin.pins.source_sha,
            "started_marker_sha256":pin.pins.started_marker_sha256,
            "controller_key_pin_sha256":pin.pins.controller_key_pin_sha256,
            "controller_public_key_hex":pin.pins.controller_public_key_hex,
            "deterministic_report_sha256":"2".repeat(64),
            "diagnostic_report_sha256":"3".repeat(64),
            "terminal_sha256":"4".repeat(64),
            "exit_code":0,
            "producer_status_claim":"passed",
            "signed_openings_observed":true,
            "independent_control_verdict":false,
            "execution_eligible":false,
        });
        let mut raw = canonicalize(value.to_string().as_bytes()).unwrap();
        raw.push(b'\n');
        raw
    }

    #[test]
    fn final_result_must_match_the_durable_prelaunch_key() {
        let pin = pin();
        let raw = result(&pin);
        assert!(validate_guest_result(&raw, &pin).is_ok());
        let mut other = pin.clone();
        other.pins.controller_key_pin_sha256 = "9".repeat(64);
        assert!(validate_guest_result(&raw, &other).is_err());
        let mut extra = raw.clone();
        extra.push(b'\n');
        assert!(validate_guest_result(&extra, &pin).is_err());
    }
}
