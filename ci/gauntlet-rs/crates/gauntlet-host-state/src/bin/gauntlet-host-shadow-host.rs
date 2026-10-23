//! Uninstalled read-only resource summary for the Python observer's host.

use gauntlet_host_state::{read_private_operations, sample_host};
use serde_json::json;
use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        eprintln!("usage: gauntlet-host-shadow-host ABSOLUTE_STATE_DIRECTORY");
        std::process::exit(2);
    }
    let state = Path::new(&args[1]);
    if let Err(error) = read_private_operations(state) {
        eprintln!("private host operations unavailable: {error}");
        std::process::exit(2);
    }
    let sample = match sample_host(state) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("host resource sample unavailable: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-resource-shadow.v1",
            "sample":sample,
            "read_only":true,
            "admission_eligible":false,
        })
    );
}
