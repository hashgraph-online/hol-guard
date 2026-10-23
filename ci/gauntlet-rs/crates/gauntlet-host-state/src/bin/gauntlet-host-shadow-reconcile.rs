//! Read-only comparison of one historical host job and its retained VM receipt.

use gauntlet_host_state::{read_private_jobs, read_private_operations, VmReconcilePlan};
use serde_json::json;
use std::path::Path;

fn run() -> Result<String, String> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err(
            "usage: gauntlet-host-shadow-reconcile ABSOLUTE_STATE_DIRECTORY JOB_ID".to_owned(),
        );
    }
    let requested_id = args[2]
        .to_str()
        .ok_or_else(|| "job ID is invalid".to_owned())?;
    let state = Path::new(&args[1]);
    let operations = read_private_operations(state).map_err(|error| error.to_string())?;
    // This historical reader does not take Python's observer lease. Its result
    // is diagnostic only, even if the remote terminal receipt matches it.
    let jobs = read_private_jobs(state).map_err(|error| error.to_string())?;
    let job = jobs
        .iter()
        .find(|job| job["id"].as_str() == Some(requested_id))
        .ok_or_else(|| "retained job is unavailable".to_owned())?;
    let source_sha = job["sha"]
        .as_str()
        .ok_or_else(|| "retained job source SHA is unavailable".to_owned())?;
    let deployment_digest = match job.get("deployment_digest") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| "retained job deployment digest is invalid".to_owned())?,
        ),
    };
    let plan = VmReconcilePlan::new(&operations, source_sha, requested_id, deployment_digest)
        .map_err(|error| error.to_string())?;
    let response = plan
        .execute_read_only()
        .map_err(|error| error.to_string())?;
    let classification = if response["status"] == "unknown" {
        None
    } else {
        Some(
            plan.classify_terminal(&response)
                .map_err(|error| error.to_string())?,
        )
    };
    let host_state = job["state"].as_str();
    Ok(json!({
        "schema":"hol-gauntlet-host-reconcile-shadow.v1",
        "job_id":requested_id,
        "source_sha":source_sha,
        "host_state":host_state,
        "vm_receipt_state":response["status"],
        "python_finish_projection":classification,
        "host_state_matches_projection":classification.as_ref().and_then(|value| value["state"].as_str()).zip(host_state).map(|(vm, host)| vm == host),
        "historical_host_read":true,
        "vm_receipt_independently_authenticated":false,
        "read_only":true,
        "admission_eligible":false,
    })
    .to_string())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("host reconcile shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
