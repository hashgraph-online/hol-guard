//! Uninstalled read-only source archive diagnostic; no fetch or build.

use gauntlet_host_state::verify_retained_source_archive;
use serde_json::json;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: gauntlet-host-shadow-source <absolute-state-root> <job-id> <sha256>");
        std::process::exit(2);
    }
    let inventory = match verify_retained_source_archive(Path::new(&args[1]), &args[2], &args[3]) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("source archive unavailable: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-source-shadow.v1",
            "job_id":args[2],
            "archive_sha256":inventory.archive_sha256,
            "compressed_bytes":inventory.compressed_bytes,
            "entries":inventory.entries,
            "regular_files":inventory.regular_files,
            "directories":inventory.directories,
            "file_bytes":inventory.file_bytes,
            "execution_eligible":inventory.execution_eligible
        })
    );
}
