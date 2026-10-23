//! Uninstalled read-only Mac-to-VM probe for a retained candidate result.

use gauntlet_host_state::VmCandidateResultPlan;
use serde_json::Value;

fn run() -> Result<Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 8 {
        return Err("usage: gauntlet-host-shadow-candidate-result JOB_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 RESULT_SHA256 EXPORT_ARCHIVE_SHA256 VERSION READER_BINARY_SHA256".to_owned());
    }
    let operations: Value = serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
        .map_err(|_| "compiled public VM defaults invalid".to_owned())?;
    let plan = VmCandidateResultPlan::new(
        &operations,
        &args[1],
        &args[2],
        &args[3],
        &args[4],
        &args[5],
        &args[6],
        &args[7],
    )
    .map_err(|error| error.to_string())?;
    plan.execute_read_only().map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("candidate result shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
