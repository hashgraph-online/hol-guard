//! Uninstalled read-only check of the exact archive retained in the ARM VM.

use gauntlet_host_state::{read_private_operations, VmSourceArchiveProbePlan};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: gauntlet-host-shadow-vm-source <absolute-state-root> <job-id> <archive-sha256>"
        );
        std::process::exit(2);
    }
    let operations = match read_private_operations(Path::new(&args[1])) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("VM source configuration unavailable: {error}");
            std::process::exit(2);
        }
    };
    let plan = match VmSourceArchiveProbePlan::new(&operations, &args[2], &args[3]) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("VM source probe unavailable: {error}");
            std::process::exit(2);
        }
    };
    match plan.execute_read_only() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("VM source archive unavailable: {error}");
            std::process::exit(2);
        }
    }
}
