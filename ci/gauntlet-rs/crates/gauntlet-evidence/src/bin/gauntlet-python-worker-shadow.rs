//! Uninstalled, read-only diagnostic for one retained Python VM receipt.

use gauntlet_evidence::read_python_worker_terminal_root_owned;
use serde_json::json;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 5 {
        eprintln!(
            "usage: gauntlet-python-worker-shadow JOB_ID SOURCE_SHA DEPLOYMENT_DIGEST CONFIG_DIGEST"
        );
        return ExitCode::from(2);
    }
    match read_python_worker_terminal_root_owned(
        &arguments[1],
        &arguments[2],
        &arguments[3],
        &arguments[4],
    ) {
        Ok(terminal) => {
            println!(
                "{}",
                json!({
                    "schema":"hol-gauntlet-python-worker-shadow.v1",
                    "job_id":terminal.job_id,
                    "source_sha":terminal.source_sha,
                    "deployment_digest":terminal.deployment_digest,
                    "producer_claimed_status":terminal.status,
                    "producer_exit_code":terminal.exit_code,
                    "report_sha256":terminal.report_sha256,
                    "receipt_consistent":terminal.report_consistent,
                    "execution_eligible":false,
                    "reason":"controller generation and deterministic controls are not independently authenticated",
                })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("retained Python worker receipt unavailable: {error}");
            ExitCode::from(2)
        }
    }
}
