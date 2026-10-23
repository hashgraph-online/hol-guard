//! Uninstalled read-only host, VM and exact-release diagnostic.

use gauntlet_host_state::{
    read_private_operations, resource_admission_reasons, sample_host, TagLookupPlan, VmProbePlan,
};
use serde_json::{json, Value};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        eprintln!("usage: gauntlet-host-shadow-doctor ABSOLUTE_STATE_DIRECTORY");
        std::process::exit(2);
    }
    let state = Path::new(&args[1]);
    let operations = match read_private_operations(state) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("host doctor unavailable: {error}");
            std::process::exit(2);
        }
    };
    if operations["discovery_mode"] != "release-tags"
        || operations["release_build_backend"] != "local-vm"
    {
        eprintln!("host doctor requires the passive local release mode");
        std::process::exit(2);
    }
    let host = sample_host(state).unwrap_or_else(
        |error| json!({"status":"unavailable","checked_at":0,"error":error.to_string()}),
    );
    let vm = VmProbePlan::new(&operations)
        .and_then(|plan| plan.execute_read_only())
        .unwrap_or_else(
            |error| json!({"status":"unavailable","checked_at":0,"error":error.to_string()}),
        );
    let mut releases = Vec::new();
    let mut source_error = None;
    let tags = operations["release_tags"]
        .as_array()
        .expect("validated release tags");
    for tag in tags {
        let tag = tag.as_str().expect("validated release tag");
        let result = TagLookupPlan::new(&operations, tag).and_then(|plan| plan.execute_read_only());
        match result {
            Ok(value) => releases.push(value),
            Err(error) => {
                source_error = Some(error.to_string());
                break;
            }
        }
    }
    let release_source = if let Some(error) = source_error {
        json!({"status":"disconnected","error":error})
    } else {
        json!({
            "status":"connected",
            "repository":operations["repository"],
            "release_tags":releases,
        })
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value.as_secs_f64(),
        Err(_) => {
            eprintln!("host doctor clock unavailable");
            std::process::exit(2);
        }
    };
    let resources: Value = json!({"host":host,"vm":vm});
    let reasons = match resource_admission_reasons(&resources, &operations, now) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("host doctor admission calculation unavailable: {error}");
            std::process::exit(2);
        }
    };
    let healthy = reasons.is_empty() && release_source["status"] == "connected";
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-doctor-shadow.v1",
            "host":host,
            "vm":vm,
            "release_source":release_source,
            "admission_reasons":reasons,
            "resource_healthy":healthy,
            "execution_eligible":false,
        })
    );
}
