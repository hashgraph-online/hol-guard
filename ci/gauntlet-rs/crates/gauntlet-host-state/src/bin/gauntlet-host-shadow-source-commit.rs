//! Uninstalled read-only Git-graph diagnostic; no fetch, checkout or build.

use gauntlet_host_state::verify_retained_source_archive_commit;
use serde_json::json;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: gauntlet-host-shadow-source-commit <absolute-state-root> <job-id> <archive-sha256> <source-sha> <source-ref>"
        );
        std::process::exit(2);
    }
    let proof = match verify_retained_source_archive_commit(
        Path::new(&args[1]),
        &args[2],
        &args[3],
        &args[4],
        &args[5],
    ) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("source Git graph unavailable: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-source-commit-shadow.v1",
            "job_id":args[2],
            "archive_sha256":proof.archive().archive_sha256,
            "source_sha":proof.source_sha(),
            "source_ref":proof.source_ref(),
            "ref_object_id":proof.ref_object_id(),
            "git_graph_verified":proof.git_graph_verified(),
            "execution_eligible":proof.execution_eligible()
        })
    );
}
