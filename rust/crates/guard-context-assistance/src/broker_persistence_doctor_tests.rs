use super::*;
use crate::{BundleApproval, EvidenceCache, RuntimeSelection};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn runtime() -> VerifiedRuntime {
    let selection: RuntimeSelection = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit candidate selection"),
        )
        .unwrap(),
    )
    .unwrap();
    let approval: BundleApproval = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit candidate approval"),
        )
        .unwrap(),
    )
    .unwrap();
    VerifiedRuntime::start(selection, &approval).unwrap()
}

#[test]
#[ignore = "requires the explicitly approved final CPython 3.14 and actual CIGAR 0.14.1 worker"]
fn actual_persistence_doctor_is_private_bounded_independent_and_resets_failed_qualification() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let home = Fixture(std::env::temp_dir().canonicalize().unwrap().join(format!(
        "guard-storage-doctor-{}-{}",
        std::process::id(),
        now.as_nanos()
    )));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&home.0)
        .unwrap();
    let cache = EvidenceCache::open(&home.0).unwrap();
    let mut runtime = runtime();
    let mut config = ContextAssistanceConfig {
        runtime_id: "candidate".into(),
        ..Default::default()
    };
    assert!(matches!(
        runtime.verify_persistence_compile(&home.0.join("not-inspected"), &config),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(!home.0.join("not-inspected").exists());
    assert!(!runtime.status().persistence_compile_verified);
    for n in 0..8 {
        let key = EvidenceCache::key(
            &format!("app{n}"),
            &home.0,
            &runtime.status().worker_fingerprint,
        )
        .unwrap();
        drop(
            cache
                .open_slot(&key, 24, now.as_millis().try_into().unwrap())
                .unwrap(),
        );
    }
    let before = cache.summary().unwrap();
    assert_eq!(before.slots, 8);
    config.storage.mode = StorageMode::Sqlite;
    runtime
        .verify_persistence_compile(&home.0, &config)
        .unwrap();
    assert!(runtime.status().persistence_compile_verified);
    assert!(
        !runtime.status().shared_compile_verified,
        "private qualification must not enable or require sharing"
    );
    assert!(
        !config.enabled,
        "explicit off-state checking must not change opt-in"
    );
    assert_eq!(
        cache.summary().unwrap(),
        before,
        "a full and locked user cache cannot be consumed or cleared by the doctor"
    );
    let scratch = EvidenceCache::qualification(&home.0).unwrap();
    assert_eq!(scratch.summary().unwrap().slots, 0);
    assert!(matches!(
        runtime.verify_persistence_compile(&home.0, &config),
        Err(RuntimeError::Busy)
    ));
    assert!(
        !runtime.status().persistence_compile_verified,
        "a failed recheck revokes the older qualification"
    );
    drop(scratch);
    config.features.agent_context = true;
    config.features.shared_agents = true;
    runtime.verify_shared_compile(&config).unwrap();
    assert!(runtime.status().shared_compile_verified);
    assert!(
        !runtime.status().persistence_compile_verified,
        "memory sharing qualification cannot imply durability qualification"
    );
    assert_eq!(cache.summary().unwrap(), before);
    runtime.close();
    println!("GUARD_CIGAR_PERSISTENCE_DOCTOR_VERIFICATION actual_sqlite=true fresh_epoch=true fresh_catalog_and_client=true old_handle_refused=true user_cache_untouched=true scratch_removed=true independent_flags=true failed_check_revokes=true");
}
