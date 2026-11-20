//! Maintainer-only protected-tree performance probe; never installs or launches.
use guard_cigar_install::{verify_python_tree, PreparationControl};
use guard_cigar_release::TrustedCatalog;
use std::{
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("expected INTERPRETER_BUILD_ID PLATFORM EXISTING_PRIVATE_ROOT".into());
    }
    let catalog = TrustedCatalog::bundled()?;
    let build = catalog.prepare_interpreter(&args[0], &args[1])?;
    let cancel = Arc::new(AtomicBool::new(false));
    let control = PreparationControl::new(Arc::clone(&cancel), Duration::from_secs(120))?;
    let started = Instant::now();
    let bundle = verify_python_tree(&build, Path::new(&args[2]), &control)?;
    let complete_us = started.elapsed().as_micros();
    let mut cached_us = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        bundle.snapshot().recheck(Some(&cancel))?;
        cached_us.push(started.elapsed().as_micros());
    }
    println!(
        "{}",
        serde_json::json!({"schema":"guard-cigar-python-tree-check-timing.v1",
        "scope":"local-source-protected-tree-check-only", "build_id":build.build().build_id,
        "tree_sha256":bundle.tree_sha256(), "files":bundle.files(), "bytes":bundle.bytes(),
        "metadata_cache_supported":bundle.snapshot().metadata_cache_supported(),"full_verification_us":complete_us,"cached_checks_us":cached_us})
    );
    Ok(())
}
