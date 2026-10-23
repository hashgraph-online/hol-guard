//! Uninstalled Root-only reader of six historical deterministic records.
//! Prints digests, never private record bytes or a Guard verdict.

#[cfg(target_os = "linux")]
fn run() -> Result<String, String> {
    use gauntlet_evidence::read_six_deterministic_controls_root_owned;
    use serde_json::json;

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: gauntlet-control-records-shadow EXTERNAL_SOURCE_SHA JOB_ID EXTERNAL_CONFIG_SHA256 EXTERNAL_REPORT_SHA256 EXPECTED_EXIT_CODE".to_owned());
    }
    let exit_code = args[5]
        .parse::<i32>()
        .map_err(|_| "invalid outside process exit code".to_owned())?;
    let records =
        read_six_deterministic_controls_root_owned(&args[2], &args[1], &args[3], exit_code)
            .map_err(|error| error.to_string())?;
    if records.report.raw_sha256 != args[4] {
        return Err("retained report differs from outside digest".to_owned());
    }
    Ok(json!({
        "schema":"hol-gauntlet-six-control-records-shadow.v1",
        "source_sha":records.report.source_sha,
        "job_id":args[2],
        "config_digest":records.report.config_digest,
        "report_sha256":records.report.raw_sha256,
        "exit_code":records.report.exit_code,
        "producer_status":records.report.producer_status,
        "control_record_sha256":records.digests,
        "control_records_read":6,
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
            eprintln!("control records unavailable: {error}");
            std::process::exit(2);
        }
    }
}
