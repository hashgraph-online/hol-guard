//! Maintainer proof: exact private interpreter, final SDK and all four features.
//! No registration, selection, enablement, production trust or system writes.
use guard_cigar_install::{prepare_locked, prepare_python, verify_python_tree, PreparationControl};
use guard_cigar_release::{Feature, TrustedCatalog};
use guard_context_assistance::{
    inspect_release_bundle, probe_interpreter_cancellable, RuntimeSelection, VerifiedRuntime,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{Duration, Instant};

fn directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::other("platform unqualified"))
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() < 6 {
        return Err("expected PYTHON_BUILD_ID SDK_BUILD_ID FRESH_PRIVATE_HOME PYTHON_ARCHIVE SDK_WHEEL DEPENDENCY_WHEEL [...]".into());
    }
    let catalog = TrustedCatalog::bundled()?;
    let python_build = catalog.prepare_interpreter(
        args[0].to_str().ok_or("invalid interpreter ID")?,
        "darwin-arm64",
    )?;
    let sdk = catalog.prepare(
        args[1].to_str().ok_or("invalid SDK ID")?,
        "darwin-arm64",
        false,
    )?;
    let cancel = Arc::new(AtomicBool::new(false));
    let control = PreparationControl::new(Arc::clone(&cancel), Duration::from_secs(120))?;
    let started = Instant::now();
    let python_plan = prepare_python(&python_build, Path::new(&args[3]), &control)?;
    let mut inputs = BTreeMap::new();
    for path in &args[4..] {
        let path = PathBuf::from(path);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("invalid wheel name")?
            .to_owned();
        if inputs.insert(name, path).is_some() {
            return Err("duplicate wheel".into());
        }
    }
    let sdk_plan = prepare_locked(&sdk, &inputs, &control)?;
    let home = PathBuf::from(&args[2]);
    directory(&home)?;
    let staging = home.join("python-staging");
    directory(&staging)?;
    python_plan.write_into(&staging, &control)?;
    let python_root = home.join("python");
    fs::rename(&staging, &python_root)?;
    let bundle = verify_python_tree(&python_build, &python_root, &control)?;
    let probe = home.join("probe");
    directory(&probe)?;
    let observed = probe_interpreter_cancellable(bundle.executable(), &probe, Arc::clone(&cancel))?;
    if observed.facts().version != python_build.build().python_version
        || observed.facts().platform != python_build.build().platform
        || observed.sha256() != python_build.build().executable_sha256
    {
        return Err("interpreter report mismatch".into());
    }
    sdk.check_python_version(observed.facts().version)?;
    let packages = home.join("site-packages");
    directory(&packages)?;
    let work = home.join("work");
    directory(&work)?;
    sdk_plan.write_into(&packages, &control)?;
    let selection = RuntimeSelection {
        verified_python: None,
        python_bundle: Some(guard_context_assistance::PrivatePythonSelection {
            root: bundle.root().into(),
            binding: python_build.build().binding()?,
        }),
        python: bundle.executable().into(),
        site_packages: packages,
        work_dir: work,
    };
    let approval = inspect_release_bundle(&selection, &sdk)?;
    let status = VerifiedRuntime::verify_release_candidate_with_features(
        selection.clone(),
        &approval,
        &sdk,
        &home,
        &[
            Feature::Graph,
            Feature::Sharing,
            Feature::Persistence,
            Feature::ExecutionContext,
        ],
        // Closing the SDK revokes its session signal permanently. The outer
        // preparer still needs to verify its files after that close.
        Arc::new(AtomicBool::new(false)),
    )?;
    if status.active {
        return Err("qualification runtime did not close".into());
    }
    verify_python_tree(&python_build, &python_root, &control)?;
    let receipt = json!({"schema":"guard-cigar-private-python-qualification.v1","scope":"local-macos-arm64-source-build",
        "interpreter_build":python_build.build(),"interpreter":observed.facts(),"python_sha256":observed.sha256(),
        "python_tree":bundle.tree_sha256(),"python_files":bundle.files(),"python_bytes":bundle.bytes(),
        "sdk_build":sdk.build().identity,"sdk_tree":sdk_plan.tree_sha256(),"selection":selection,"approval":approval,"status":status,
        "elapsed_ms":started.elapsed().as_millis(),"relocated_before_probe":true,"tree_unchanged_after_sdk":true,
        "registered":false,"selected":false,"enabled":false,"qualification_promoted":false});
    let bytes = serde_json::to_vec_pretty(&receipt)?;
    let path = home.join("qualification.json");
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!(
        "{}",
        json!({"receipt":path,"interpreter":observed.facts(),"python_tree":bundle.tree_sha256(),
        "status":status,"elapsed_ms":started.elapsed().as_millis(),"registered":false,"qualification_promoted":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Private CIGAR interpreter qualification failed: {error}");
        std::process::exit(1);
    }
}
