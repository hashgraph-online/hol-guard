//! Uninstalled Root-only fixed-output report reader. It never executes a job
//! or turns a controller's producer status into a trusted Guard verdict.

#[cfg(target_os = "linux")]
fn run() -> Result<String, String> {
    use gauntlet_evidence::read_deterministic_report_root_owned;
    use serde_json::json;

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: gauntlet-deterministic-report-shadow EXTERNAL_SOURCE_SHA JOB_ID EXTERNAL_CONFIG_SHA256 EXTERNAL_REPORT_SHA256 EXPECTED_EXIT_CODE".to_owned());
    }
    let exit_code = args[5]
        .parse::<i32>()
        .map_err(|_| "invalid outside process exit code".to_owned())?;
    let report =
        read_deterministic_report_root_owned(&args[2], &args[1], &args[3], &args[4], exit_code)
            .map_err(|error| error.to_string())?;
    Ok(json!({
        "schema":"hol-gauntlet-deterministic-report-shadow.v1",
        "source_sha":report.source_sha,
        "job_id":args[2],
        "config_digest":report.config_digest,
        "report_sha256":report.raw_sha256,
        "exit_code":report.exit_code,
        "producer_status":report.producer_status,
        "cell_count":report.cell_count,
        "control_verdict_recomputed":false,
        "execution_eligible":false,
    })
    .to_string())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<String, String> {
    Err("Linux diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("deterministic report unavailable: {error}");
            std::process::exit(2);
        }
    }
}
