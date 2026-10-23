//! Uninstalled read-only archive and exact-tag recheck; never queues a job.

use gauntlet_host_state::{
    read_private_operations, verify_retained_source_archive_commit, TagLookupPlan,
};
use serde_json::json;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: gauntlet-host-shadow-source-tag-recheck <absolute-state-root> <job-id> <archive-sha256> <source-sha> <tag>"
        );
        std::process::exit(2);
    }
    let state = Path::new(&args[1]);
    let operations = match read_private_operations(state) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("release configuration unavailable: {error}");
            std::process::exit(2);
        }
    };
    if operations["discovery_mode"] != "release-tags"
        || operations["release_build_backend"] != "local-vm"
    {
        eprintln!("passive local release mode required");
        std::process::exit(2);
    }
    let plan = match TagLookupPlan::new(&operations, &args[5]) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("fixed tag lookup unavailable: {error}");
            std::process::exit(2);
        }
    };
    let reference = format!("refs/tags/{}", args[5]);
    let archive = match verify_retained_source_archive_commit(
        state, &args[2], &args[3], &args[4], &reference,
    ) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("source archive Git graph unavailable: {error}");
            std::process::exit(2);
        }
    };
    let recheck = match plan.recheck_archive_commit_read_only(&archive) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("release tag recheck unavailable: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "{}",
        json!({
            "schema":"hol-gauntlet-host-source-tag-recheck-shadow.v1",
            "job_id":args[2],
            "tag":args[5],
            "source_sha":archive.source_sha(),
            "source_archive_sha256":archive.archive().archive_sha256,
            "git_graph_verified":archive.git_graph_verified(),
            "tag_unchanged":recheck["tag_unchanged"],
            "execution_eligible":false,
        })
    );
}
