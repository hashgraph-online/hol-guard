//! Uninstalled, read-only exact-tag source diagnostic. It never queues a job.

use gauntlet_host_state::{read_private_operations, TagLookupPlan};
use serde_json::json;
use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        eprintln!("usage: gauntlet-host-shadow-tags ABSOLUTE_STATE_DIRECTORY");
        std::process::exit(2);
    }
    let operations = match read_private_operations(Path::new(&args[1])) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("host tag shadow unavailable: {error}");
            std::process::exit(2);
        }
    };
    if operations["discovery_mode"] != "release-tags"
        || operations["release_build_backend"] != "local-vm"
    {
        eprintln!("host tag shadow requires the passive local release mode");
        std::process::exit(2);
    }
    let tags = operations["release_tags"]
        .as_array()
        .expect("validated release tags");
    let mut releases = Vec::with_capacity(tags.len());
    for tag in tags {
        let tag = tag.as_str().expect("validated release tag");
        let plan = match TagLookupPlan::new(&operations, tag) {
            Ok(plan) => plan,
            Err(error) => {
                eprintln!("host tag shadow unavailable: {error}");
                std::process::exit(2);
            }
        };
        match plan.execute_read_only() {
            Ok(release) => releases.push(release),
            Err(error) => {
                eprintln!("host tag shadow unavailable for {tag}: {error}");
                std::process::exit(2);
            }
        }
    }
    println!(
        "{}",
        json!({
            "schema": "hol-gauntlet-host-tag-shadow.v1",
            "releases": releases,
            "read_only": true,
            "admission_eligible": false,
        })
    );
}
