//! Uninstalled summary-only read of one retained Python VM worker's progress.

use gauntlet_host_state::{read_private_jobs, read_private_operations, VmProgressPlan};
use serde_json::json;
use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        eprintln!("usage: gauntlet-host-shadow-progress ABSOLUTE_STATE_DIRECTORY JOB_ID");
        std::process::exit(2);
    }
    let Some(requested_id) = args[2].to_str() else {
        eprintln!("job ID is invalid");
        std::process::exit(2);
    };
    let state = Path::new(&args[1]);
    let operations = match read_private_operations(state) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("private host operations unavailable: {error}");
            std::process::exit(2);
        }
    };
    let jobs = match read_private_jobs(state) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("private host jobs unavailable: {error}");
            std::process::exit(2);
        }
    };
    let Some(job) = jobs
        .iter()
        .find(|job| job["id"].as_str() == Some(requested_id))
    else {
        eprintln!("retained job is unavailable");
        std::process::exit(2);
    };
    let Some(source_sha) = job["sha"].as_str() else {
        eprintln!("retained job source SHA is unavailable");
        std::process::exit(2);
    };
    let deployment_digest = match job.get("deployment_digest") {
        None => None,
        Some(value) => match value.as_str() {
            Some(digest) => Some(digest),
            None => {
                eprintln!("retained job deployment digest is invalid");
                std::process::exit(2);
            }
        },
    };
    let plan = match VmProgressPlan::new(&operations, source_sha, requested_id, deployment_digest) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("VM progress plan unavailable: {error}");
            std::process::exit(2);
        }
    };
    let progress = match plan.execute_read_only() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("VM progress unavailable: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-progress-shadow.v1",
            "job_id":requested_id,
            "source_sha":source_sha,
            "checked_at":progress["checked_at"],
            "phase":progress["phase"],
            "current_control":progress.get("current_control"),
            "completed_controls":progress["completed_controls"].as_array().map(Vec::len),
            "producer_reported_process_alive":progress.get("process_alive"),
            "read_only":true,
            "admission_eligible":false,
        })
    );
}
