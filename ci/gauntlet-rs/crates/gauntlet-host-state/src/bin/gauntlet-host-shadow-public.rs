//! Uninstalled read-only summary of Python's public-job projection.

use gauntlet_contracts::canonical_sha256;
use gauntlet_host_state::{project_public_jobs, read_private_jobs};
use serde_json::json;
use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 && (args.len() != 4 || args[2] != "--field-hashes") {
        eprintln!(
            "usage: gauntlet-host-shadow-public ABSOLUTE_STATE_DIRECTORY [--field-hashes JOB_ID]"
        );
        std::process::exit(2);
    }
    let jobs = match read_private_jobs(Path::new(&args[1])) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("private host jobs unavailable: {error}");
            std::process::exit(2);
        }
    };
    let projection = match project_public_jobs(&jobs) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("public job projection unavailable: {error}");
            std::process::exit(2);
        }
    };
    if args.len() == 4 {
        let Some(requested_id) = args[3].to_str() else {
            eprintln!("public job ID is invalid");
            std::process::exit(2);
        };
        let Some(job) = projection
            .jobs
            .iter()
            .find(|job| job["id"].as_str() == Some(requested_id))
        else {
            eprintln!("public job ID is unavailable");
            std::process::exit(2);
        };
        let mut hashes = serde_json::Map::new();
        for (name, value) in job.as_object().expect("validated public job") {
            let bytes = serde_json::to_vec(value).expect("validated public field");
            hashes.insert(
                name.clone(),
                json!(canonical_sha256(&bytes).expect("bounded public field")),
            );
        }
        println!("{}", json!({"job_id":requested_id,"field_sha256":hashes}));
        return;
    }
    let public_ids: Vec<_> = projection
        .jobs
        .iter()
        .filter_map(|job| job["id"].as_str())
        .collect();
    let public_bytes = serde_json::to_vec(&json!({
        "jobs":&projection.jobs,
        "archived_jobs":projection.archived_jobs,
    }))
    .expect("validated public projection");
    let public_sha256 = canonical_sha256(&public_bytes).expect("bounded public projection");
    let job_sha256: Vec<_> = projection
        .jobs
        .iter()
        .map(|job| {
            let bytes = serde_json::to_vec(job).expect("validated public job");
            json!({
                "id":job["id"],
                "sha256":canonical_sha256(&bytes).expect("bounded public job"),
            })
        })
        .collect();
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-public-shadow.v1",
            "private_jobs":jobs.len(),
            "visible_jobs":projection.jobs.len(),
            "archived_jobs":projection.archived_jobs,
            "public_ids":public_ids,
            "public_projection_sha256":public_sha256,
            "public_job_sha256":job_sha256,
            "read_only":true,
            "publication_eligible":projection.publication_eligible,
        })
    );
}
