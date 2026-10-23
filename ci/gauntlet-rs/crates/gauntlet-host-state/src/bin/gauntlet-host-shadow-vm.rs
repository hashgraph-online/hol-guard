//! Uninstalled, read-only Lima health probe for the configured VM.

use gauntlet_host_state::{read_private_operations, VmProbePlan};
use serde_json::json;
use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        eprintln!("usage: gauntlet-host-shadow-vm ABSOLUTE_STATE_DIRECTORY");
        std::process::exit(2);
    }
    let operations = match read_private_operations(Path::new(&args[1])) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("VM telemetry config unavailable: {error}");
            std::process::exit(2);
        }
    };
    let plan = match VmProbePlan::new(&operations) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("VM telemetry plan unavailable: {error}");
            std::process::exit(2);
        }
    };
    let vm = match plan.execute_read_only() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("VM telemetry unavailable: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-vm-shadow.v1",
            "vm":vm,
            "vm_disk_floor_gib":operations["vm_disk_floor_gib"],
            "vm_memory_allocation_gib":operations["vm_memory_gib"],
            "read_only":true,
            "admission_eligible":false,
        })
    );
}
