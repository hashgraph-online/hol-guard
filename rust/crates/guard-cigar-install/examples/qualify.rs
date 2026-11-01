//! Maintainer-only real-artifact proof, not an enrollment or activation command.
//! Run with BUILD_ID PYTHON FRESH_PRIVATE_HOME SDK_WHEEL DEPENDENCY_WHEEL [...].
use guard_cigar_install::{prepare_locked, PreparationControl};
use guard_cigar_release::{Feature, TrustedCatalog};
use guard_context_assistance::{inspect_release_bundle, RuntimeSelection, VerifiedRuntime};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{Duration, Instant};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() < 5 {
        return Err(
            "expected BUILD_ID PYTHON FRESH_PRIVATE_HOME SDK_WHEEL DEPENDENCY_WHEEL [...]".into(),
        );
    }
    let catalog = TrustedCatalog::bundled()?;
    let build_id = args[0].to_str().ok_or("build ID is not UTF-8")?;
    let release = catalog.prepare(build_id, "darwin-arm64", false)?;
    let mut inputs = BTreeMap::new();
    for path in &args[3..] {
        let path = PathBuf::from(path);
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("invalid wheel name")?
            .to_owned();
        if inputs.insert(name, path).is_some() {
            return Err("duplicate input wheel".into());
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let control = PreparationControl::new(Arc::clone(&cancel), Duration::from_secs(120))?;
    let start = Instant::now();
    let plan = prepare_locked(&release, &inputs, &control)?;
    let home = PathBuf::from(&args[2]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&home)?;
    }
    #[cfg(not(unix))]
    {
        return Err("private installation is not qualified on this platform".into());
    }
    let packages = home.join("site-packages");
    let work = home.join("work");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&packages)?;
        fs::DirBuilder::new().mode(0o700).create(&work)?;
    }
    plan.write_into(&packages, &control)?;
    let selection = RuntimeSelection {
        verified_python: None,
        python_bundle: None,
        python: PathBuf::from(&args[1]),
        site_packages: packages,
        work_dir: work,
    };
    let approval = inspect_release_bundle(&selection, &release)?;
    let status = VerifiedRuntime::verify_release_candidate_with_features(
        selection.clone(),
        &approval,
        &release,
        &home,
        &[
            Feature::Graph,
            Feature::Sharing,
            Feature::Persistence,
            Feature::ExecutionContext,
        ],
        cancel,
    )?;
    let value = json!({"schema":"guard-cigar-prepared-qualification.v1","scope":"local-macos-arm64-source-build",
        "build":release.build().identity,"catalog_checkpoint":catalog.checkpoint(),
        "selection":selection,"approval":approval,"status":status,
        "elapsed_ms":start.elapsed().as_millis(),"files":plan.files(),"bytes":plan.bytes(),
        "installed":false,"selected":false,"enabled":false,"qualification_promoted":false});
    let bytes = serde_json::to_vec_pretty(&value)?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let receipt_path = home.join("qualification.json");
    let mut file = options.open(&receipt_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!(
        "{}",
        json!({"receipt":receipt_path,"status":status,"elapsed_ms":start.elapsed().as_millis()})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("CIGAR preparation/qualification failed: {error}");
        std::process::exit(1);
    }
}
