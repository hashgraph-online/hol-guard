//! Uninstalled summary-only diagnostic for retained Python host jobs.

use gauntlet_host_state::{read_private_jobs, read_private_operations};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

fn is_archived(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        eprintln!("usage: gauntlet-host-shadow ABSOLUTE_STATE_DIRECTORY");
        std::process::exit(2);
    }
    let jobs = match read_private_jobs(Path::new(&args[1])) {
        Ok(jobs) => jobs,
        Err(error) => {
            eprintln!("host shadow unavailable: {error}");
            std::process::exit(2);
        }
    };
    let operations = match read_private_operations(Path::new(&args[1])) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("host config shadow unavailable: {error}");
            std::process::exit(2);
        }
    };
    let mut states = BTreeMap::<String, usize>::new();
    let mut archived = 0usize;
    for job in &jobs {
        let state = job["state"].as_str().expect("validated job state");
        *states.entry(state.to_owned()).or_default() += 1;
        if is_archived(job.get("archived_at")) {
            archived += 1;
        }
    }
    println!(
        "{}",
        json!({
            "schema": "hol-gauntlet-host-shadow.v1",
            "source": "python-private-jobs",
            "config_verified": true,
            "discovery_mode": operations["discovery_mode"],
            "release_tags": operations["release_tags"],
            "release_build_backend": operations["release_build_backend"],
            "jobs": jobs.len(),
            "states": states,
            "archived": archived,
            "unknown_blocks_admission": states.get("unknown").copied().unwrap_or(0) > 0,
            "read_only": true,
            "admission_eligible": false,
        })
    );
}
