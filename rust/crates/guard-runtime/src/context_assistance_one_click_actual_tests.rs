//! Real network proof of the one-click path on whatever computer runs it:
//! private Python setup, SDK install and a verified start, all from the
//! bundled catalog and the public download hosts. Nothing is enabled.
use super::*;
use python_store::SetupInterpreterRequest;
use std::time::{Duration, Instant};

fn finish(jobs: &Jobs, home: &Path, id: &str) -> Value {
    let started = Instant::now();
    let mut phase = Value::Null;
    loop {
        match jobs.get(home, id) {
            Ok(view) if view["worker_live"] == false => return view,
            Ok(view) if view["phase"] != phase => {
                phase = view["phase"].clone();
                eprintln!("{id} {phase} at {} ms", started.elapsed().as_millis());
            }
            Ok(_) => {}
            Err(code) if code == error("install_metadata_changed") => {}
            Err(code) => panic!("{code}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(600),
            "{id} timed out"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "Explicit network proof: downloads the bundled catalog's Python and CIGAR wheels for this host"]
fn actual_one_click_setup_installs_and_starts_on_this_host() {
    let fixture = Fixture::new();
    let platform = preparation::setup_platform().expect("host platform listed in the catalog");
    let catalog = TrustedCatalog::bundled().unwrap();
    let jobs = Jobs::default();
    let started = Instant::now();
    let setup = SetupInterpreterRequest {
        job_id: "one-click-python".into(),
        build_id: catalog
            .document()
            .interpreters
            .iter()
            .find(|build| build.platform == platform)
            .expect("Python build for this host")
            .build_id
            .clone(),
    };
    jobs.setup_interpreter(&fixture.home, setup.clone())
        .unwrap();
    let python = finish(&jobs, &fixture.home, &setup.job_id);
    assert_eq!(python["phase"], "ready", "{python}");
    let python_ms = started.elapsed().as_millis();
    let install = InstallRequest {
        job_id: "one-click-sdk".into(),
        build_id: catalog.document().builds[0].identity.build_id.clone(),
        interpreter_id: python["interpreter_id"].as_str().unwrap().into(),
    };
    jobs.install(&fixture.home, install.clone()).unwrap();
    let installed = finish(&jobs, &fixture.home, &install.job_id);
    assert_eq!(installed["phase"], "ready", "{installed}");
    let runtime_id = installed["runtime_id"].as_str().unwrap();
    validate_selection(&fixture.home, runtime_id).unwrap();
    let config = guard_context_assistance::ContextAssistanceConfig {
        runtime_id: runtime_id.into(),
        ..Default::default()
    };
    let mut runtime = load(&fixture.home, runtime_id)
        .unwrap()
        .start_cancellable(&fixture.home, &config, Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert!(runtime.status().compile_verified);
    runtime.close();
    let settings = crate::guard_config_load::context_assistance_config(&fixture.home).unwrap();
    assert!(!settings.requested.enabled);
    println!(
        "CIGAR_ONE_CLICK_PROOF {}",
        json!({"platform":platform,"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
        "python_ready_ms":python_ms,"total_ms":started.elapsed().as_millis(),
        "runtime_id":runtime_id,"compile_verified":true,"enabled":false})
    );
}
