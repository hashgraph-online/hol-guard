//! Test-only explicit root enrollment for the same exact final0.14.1 bytes.
//! These synthetic keys and qualification receipts are never shipped as roots.
use super::*;
use crate::policy_store::context_assistance_registry::catalog::{self, Authority, PublicKey};
use ring::signature::{Ed25519KeyPair, KeyPair};
pub(super) fn install(store: &crate::policy_store::PolicySnapshotStore, home: &Path) -> String {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[117; 32]).unwrap();
    catalog::configure(
        home,
        Authority {
            schema: "guard-cigar-catalog-authority.v1".into(),
            keys: vec![PublicKey {
                key_id: "native-engine-upgrade-test-only".into(),
                public_key_hex: hex::encode(pair.public_key().as_ref()),
                not_before: 1,
                not_after: u64::MAX,
                revoked: false,
            }],
        },
    )
    .unwrap();
    let mut document = guard_cigar_release::TrustedCatalog::bundled()
        .unwrap()
        .document()
        .clone();
    document.revision += 1;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    document.issued_at = now - 1;
    document.expires_at = now + 7200;
    let platform = &mut document.builds[0].platforms[0];
    platform.qualification = guard_cigar_release::Qualification::GuardQualified;
    platform.qualification_receipt_sha256 = Some("d".repeat(64));
    platform.features = vec![
        guard_cigar_release::Feature::Graph,
        guard_cigar_release::Feature::Sharing,
        guard_cigar_release::Feature::Persistence,
    ];
    let payload = serde_json::to_string(&document).unwrap();
    let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
    message.extend_from_slice(payload.as_bytes());
    let raw=serde_json::to_string(&json!({"schema":"guard-cigar-signed-catalog.v1","key_id":"native-engine-upgrade-test-only","payload":payload,"signature_hex":hex::encode(pair.sign(&message).as_ref())})).unwrap();
    let imported = versions(
        store,
        home,
        json!({"action":"import_catalog","signed_catalog":raw}),
    );
    assert_eq!(imported["source"], "cached");
    assert_eq!(imported["activation_granted"], false);
    raw
}

pub(super) fn reverify(store: &crate::policy_store::PolicySnapshotStore, f: &UpgradeFixture) {
    use crate::policy_store::context_assistance_registry as registry;
    let input: Value = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_NOTE_TRANSFER_TEST_INPUT").unwrap()).unwrap(),
    )
    .unwrap();
    let build = registry::catalog::fresh(&f.home)
        .unwrap()
        .catalog
        .document()
        .builds[0]
        .identity
        .build_id
        .clone();
    let run = |operation: Value| -> Value {
        let request = json!({"schema":"guard-cigar-install-operator.v1","guard_home":f.home,"operator_approved":true,"operation":operation});
        let response: Value = serde_json::from_slice(
            &registry::run_operator_command(request.to_string().as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(response["ok"], true, "{response}");
        response["data"].clone()
    };
    run(
        json!({"action":"import_wheels","build_id":build,"platform":"darwin-arm64","files":input["wheels"]}),
    );
    let registered = run(json!({"action":"register_interpreter","python":input["target_python"]}));
    let service = store.context_assistance();
    let actor = old_actor(service);
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let job = versions(
        store,
        &f.home,
        json!({"action":"install","job_id":"catalog-reverify","build_id":build,"interpreter_id":registered["interpreter"]["interpreter_id"]}),
    );
    assert_eq!(job["operation"], "verify", "{job}");
    let started = Instant::now();
    loop {
        let job = versions(
            store,
            &f.home,
            json!({"action":"job","job_id":"catalog-reverify"}),
        );
        assert!(
            !["failed", "cancelled", "recovery_required"]
                .iter()
                .any(|p| job["phase"] == *p),
            "{job}"
        );
        assert!(Arc::ptr_eq(&actor, &old_actor(service)));
        assert!(actor.is_active());
        assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
        if job["phase"] == "ready" && job["worker_live"] == false {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(125), "{job}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The transport payload/pause are test-only; trust, worker ownership,
/// publication and job polling are the normal native implementation.
pub(super) fn refresh(
    store: &crate::policy_store::PolicySnapshotStore,
    f: &UpgradeFixture,
    raw: &str,
    scope: &str,
    snapshot: &str,
) {
    catalog::feed::configure(
        &f.home,
        catalog::feed::Feed {
            schema: "guard-cigar-catalog-feed.v1".into(),
            url: Some("https://catalog.example.com/cigar.json".into()),
        },
    )
    .unwrap();
    let service = store.context_assistance();
    let actor = old_actor(service);
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let generation = service.status().unwrap()["generation"].clone();
    let (entered, seen) = std::sync::mpsc::sync_channel(1);
    let (proceed, pending) = std::sync::mpsc::sync_channel(1);
    service
        .refresh_test_catalog(
            &f.home,
            "catalog-feed-check",
            raw.as_bytes().to_vec(),
            crate::policy_store::context_assistance_registry::InstallPause {
                entered,
                proceed: pending,
            },
        )
        .unwrap();
    seen.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        versions(
            store,
            &f.home,
            json!({"action":"job","job_id":"catalog-feed-check"})
        )["phase"],
        "acquiring"
    );
    workspace(
        service,
        f,
        store,
        json!({"action":"explain","scope_id":scope,"snapshot_id":snapshot}),
    );
    assert!(Arc::ptr_eq(&actor, &old_actor(service)));
    assert!(actor.is_active());
    assert_eq!(service.status().unwrap()["generation"], generation);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    proceed.send(()).unwrap();
    let started = Instant::now();
    loop {
        let job = versions(
            store,
            &f.home,
            json!({"action":"job","job_id":"catalog-feed-check"}),
        );
        assert!(
            !["failed", "cancelled", "recovery_required"]
                .iter()
                .any(|p| job["phase"] == *p),
            "{job}"
        );
        if job["phase"] == "ready" && job["worker_live"] == false {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(10), "{job}");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(Arc::ptr_eq(&actor, &old_actor(service)));
    assert_eq!(service.status().unwrap()["generation"], generation);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
}
