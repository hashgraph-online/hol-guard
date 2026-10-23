//! Uninstalled one-use source transfer diagnostic. The destination is published
//! exclusively; any uncertain upload must be inspected before another attempt.

use gauntlet_host_state::{
    read_private_operations, transfer_source_archive_one_use, verify_retained_source_archive_commit,
};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "usage: gauntlet-host-shadow-source-transfer <archive-state-root> <operations-state-root> <job-id> <archive-sha256> <source-sha> <source-ref>"
        );
        std::process::exit(2);
    }
    let archive_state = Path::new(&args[1]);
    let operations = match read_private_operations(Path::new(&args[2])) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("VM source configuration unavailable: {error}");
            std::process::exit(2);
        }
    };
    let proof = match verify_retained_source_archive_commit(
        archive_state,
        &args[3],
        &args[4],
        &args[5],
        &args[6],
    ) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("source Git graph unavailable: {error}");
            std::process::exit(2);
        }
    };
    match transfer_source_archive_one_use(archive_state, &operations, &proof) {
        Ok(value) => println!("{}", value.to_json()),
        Err(error) => {
            eprintln!("source transfer unavailable: {error}");
            std::process::exit(2);
        }
    }
}
