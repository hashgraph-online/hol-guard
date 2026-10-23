//! Summary-only idle snapshot of Python's private jobs. Never owns admission.

use gauntlet_host_state::read_private_jobs_if_idle;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

fn run() -> Result<String, String> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("usage: gauntlet-host-shadow-idle ABSOLUTE_STATE_DIRECTORY".to_owned());
    }
    let jobs = read_private_jobs_if_idle(Path::new(&args[1])).map_err(|error| error.to_string())?;
    let mut states = BTreeMap::<String, usize>::new();
    for job in &jobs {
        let state = job["state"]
            .as_str()
            .ok_or_else(|| "job state is unavailable".to_owned())?;
        *states.entry(state.to_owned()).or_default() += 1;
    }
    Ok(json!({
        "schema":"hol-gauntlet-host-idle-shadow.v1",
        "jobs":jobs.len(),
        "states":states,
        "python_observer_idle_at_snapshot":true,
        "read_only":true,
        "admission_eligible":false,
    })
    .to_string())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("idle host shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}
