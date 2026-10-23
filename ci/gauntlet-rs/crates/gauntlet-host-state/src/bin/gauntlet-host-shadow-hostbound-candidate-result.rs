//! Uninstalled, read-only host journal plus VM retained-result diagnostic.

use gauntlet_host_state::{HostCandidateBuildPinJournal, VmHostBoundCandidateResultPlan};
use serde_json::Value;
use std::path::Path;

fn run() -> Result<Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: gauntlet-host-shadow-hostbound-candidate-result PRIVATE_PIN_DIR JOB_ID RESULT_SHA256 EXPORT_ARCHIVE_SHA256".to_owned());
    }
    let operations: Value = serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
        .map_err(|_| "compiled public VM defaults invalid".to_owned())?;
    let journal = HostCandidateBuildPinJournal::open(Path::new(&args[1]))
        .map_err(|error| error.to_string())?;
    let plan =
        VmHostBoundCandidateResultPlan::new(&operations, &journal, &args[2], &args[3], &args[4])
            .map_err(|error| error.to_string())?;
    plan.execute_read_only().map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("host-bound candidate result unavailable: {error}");
            std::process::exit(2);
        }
    }
}
