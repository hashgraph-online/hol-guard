//! Test-only enrollment and native exact-wheel publication, never production
//! qualification or a substitute for the unavailable original b47380 bytes.
use super::*;
use crate::policy_store::context_assistance_registry as registry;

impl Fixture {
    pub fn enroll_source(&self, runtime: &VerifiedRuntime) -> registry::Installation {
        let request = json!({"schema":"guard-cigar-enroll-local.v1","guard_home":self.home,
            "runtime_id":self.source.runtime_id,"local_candidate_approved":true,
            "source_revision":"10dd521dec8224d0957365a90111158e43c9d87f",
            "selection":runtime.installation_selection(),"approval":runtime.bundle_approval()});
        let response: Value = serde_json::from_slice(
            &registry::run_enroll_command(request.to_string().as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(response["ok"], true, "{response}");
        registry::load(&self.home, &self.source.runtime_id).unwrap()
    }
    pub fn installed_target(
        &self,
    ) -> (
        registry::Installation,
        VerifiedRuntime,
        EvidenceUpgradeProducer,
    ) {
        let _owner = registry::switching::Owner::acquire(&self.home).unwrap();
        let release = release();
        let python = PathBuf::from(self.input["target_python"].as_str().unwrap());
        let python_hash = guard_secure_fs::read_stable(&python, 128 * 1024 * 1024, true)
            .unwrap()
            .sha256;
        let slot = guard_cigar_install::slot_id(&release, &python_hash).unwrap();
        let bundles = self.home.join("context-assistance/bundles");
        let bundle = bundles.join(&slot);
        let packages = bundle.join("site-packages");
        let work_root = self.home.join("context-assistance/work");
        let work = work_root.join(&slot);
        for path in [&bundles, &bundle, &packages, &work_root, &work] {
            crate::resident_state::ensure_private_directory_under(path, &self.home, true).unwrap();
        }
        let control = guard_cigar_install::PreparationControl::new(
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            std::time::Duration::from_secs(120),
        )
        .unwrap();
        let wheels: BTreeMap<String, PathBuf> =
            serde_json::from_value(self.input["wheels"].clone()).unwrap();
        let plan = guard_cigar_install::prepare_locked(&release, &wheels, &control).unwrap();
        plan.write_into(&packages, &control).unwrap();
        let selection = RuntimeSelection {
            python,
            site_packages: packages,
            work_dir: work,
            python_bundle: None,
            verified_python: None,
        };
        let approval =
            guard_context_assistance::inspect_release_bundle(&selection, &release).unwrap();
        let mut runtime = VerifiedRuntime::start_release_cancellable(
            selection,
            &approval,
            &release,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();
        runtime.verify_shared_compile(&self.target).unwrap();
        if self.target.storage.mode == guard_context_assistance::StorageMode::Sqlite {
            runtime
                .verify_persistence_compile(&self.home, &self.target)
                .unwrap();
        }
        let record = registry::publish_verified(
            &self.home,
            &self.target.runtime_id,
            &slot,
            &release,
            &mut runtime,
        )
        .unwrap();
        let producer = EvidenceUpgradeProducer::new(&release, runtime.bundle_approval()).unwrap();
        (record, runtime, producer)
    }
}
