//! Explicit final artifact fixture. Enrollment here does not stand in for b47380.
use super::*;
use guard_cigar_release::{CatalogTrust, Feature, Qualification, TrustedCatalog, TrustedKey};
use guard_context_assistance::{EvidenceUpgradeProducer, RuntimeSelection};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(crate) struct Fixture {
    _home_owner: tempfile::TempDir,
    _workspace_owner: tempfile::TempDir,
    pub home: PathBuf,
    pub workspace: PathBuf,
    input: Value,
    pub source: ContextAssistanceConfig,
    pub target: ContextAssistanceConfig,
}
pub(super) const SOURCE_TEXT: &str =
    "Release evidence for this project requires a documented inspection.\n";
impl Fixture {
    pub fn new() -> Self {
        let input = std::env::var_os("GUARD_CIGAR_NOTE_TRANSFER_TEST_INPUT")
            .expect("explicit task-private exact artifact input");
        let input = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
        let home_owner = tempfile::tempdir().unwrap();
        let home = home_owner.path().canonicalize().unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let workspace_owner = tempfile::tempdir().unwrap();
        let workspace = workspace_owner.path().canonicalize().unwrap();
        std::fs::write(workspace.join("README.md"), SOURCE_TEXT).unwrap();
        let mut source = ContextAssistanceConfig {
            enabled: true,
            runtime_id: "engine-source".into(),
            ..Default::default()
        };
        source.storage.mode = guard_context_assistance::StorageMode::Sqlite;
        source.storage.retention_hours = 1;
        source.features.agent_context = true;
        source.features.shared_agents = true;
        source.sources.workspace_documents = true;
        source.sources.source_set_id = "explicit-fixture-sources".into();
        source.sources.sanitized_receipt_facts = false;
        let mut target = source.clone();
        target.runtime_id = "engine-target".into();
        Self {
            _home_owner: home_owner,
            _workspace_owner: workspace_owner,
            home,
            workspace,
            input,
            source,
            target,
        }
    }
    pub fn write_settings(&self, config: &ContextAssistanceConfig) {
        let text = toml::to_string(&BTreeMap::from([("context_assistance", config)])).unwrap();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(self.home.join("config.toml")).unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }
    pub fn start(&self, target: bool) -> (VerifiedRuntime, EvidenceUpgradeProducer) {
        let mut selection: RuntimeSelection = serde_json::from_slice(
            &std::fs::read(self.input["current_selection"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        selection.python = PathBuf::from(
            self.input[if target { "target_python" } else { "python" }]
                .as_str()
                .unwrap(),
        );
        selection.python_bundle = None;
        selection.verified_python = None;
        selection.work_dir = self
            .home
            .join(if target { "target-work" } else { "source-work" });
        private(&selection.work_dir);
        let release = release();
        let mut runtime = if target {
            let approval =
                guard_context_assistance::inspect_release_bundle(&selection, &release).unwrap();
            VerifiedRuntime::start_release_cancellable(
                selection,
                &approval,
                &release,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .unwrap()
        } else {
            let approval =
                guard_context_assistance::inspect_bundle(&selection, "darwin-arm64").unwrap();
            VerifiedRuntime::start(selection, &approval).unwrap()
        };
        let config = if target { &self.target } else { &self.source };
        runtime.verify_shared_compile(config).unwrap();
        let doctor = self.home.join(if target {
            "target-doctor"
        } else {
            "source-doctor"
        });
        private(&doctor);
        if config.storage.mode == guard_context_assistance::StorageMode::Sqlite {
            runtime.verify_persistence_compile(&doctor, config).unwrap();
        }
        let producer = if target {
            EvidenceUpgradeProducer::new(&release, runtime.bundle_approval()).unwrap()
        } else {
            EvidenceUpgradeProducer::from_enrolled_runtime(&runtime).unwrap()
        };
        (runtime, producer)
    }
}
#[path = "context_assistance_upgrade_install_fixture.rs"]
mod installation;

fn private(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn release() -> guard_cigar_release::ResolvedRelease {
    let mut document = TrustedCatalog::bundled().unwrap().document().clone();
    let platform = &mut document.builds[0].platforms[0];
    platform.qualification = Qualification::GuardQualified;
    platform.qualification_receipt_sha256 = Some("d".repeat(64));
    platform.features = vec![Feature::Graph, Feature::Sharing, Feature::Persistence];
    let pair = Ed25519KeyPair::from_seed_unchecked(&[117; 32]).unwrap();
    let key = TrustedKey {
        key_id: "native-engine-upgrade-test-only".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        not_before: 1,
        not_after: u64::MAX,
        revoked: false,
    };
    let payload = serde_json::to_string(&document).unwrap();
    let mut signed = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
    signed.extend_from_slice(payload.as_bytes());
    let envelope = serde_json::to_vec(
        &json!({"schema":"guard-cigar-signed-catalog.v1","key_id":key.key_id,
        "payload":payload,"signature_hex":hex::encode(pair.sign(&signed).as_ref())}),
    )
    .unwrap();
    TrustedCatalog::verify(
        &envelope,
        &CatalogTrust {
            keys: &[key],
            checkpoint: None,
            now: document.issued_at,
        },
    )
    .unwrap()
    .for_activation(
        &document.builds[0].identity.build_id,
        "darwin-arm64",
        false,
        &[Feature::Graph, Feature::Sharing, Feature::Persistence],
    )
    .unwrap()
}
pub(crate) fn ask(
    engine: &mut Engine,
    runtime: &mut VerifiedRuntime,
    value: Value,
) -> Result<Value, RuntimeError> {
    engine
        .execute(runtime, serde_json::from_value(value).unwrap())
        .map(|v| v["result"].clone())
}
pub(crate) fn admit(
    engine: &mut Engine,
    runtime: &mut VerifiedRuntime,
    id: &str,
    key: &str,
    text: &str,
) -> Result<(), RuntimeError> {
    let proposal = {
        let scope = engine.scopes.get_mut(id).ok_or(RuntimeError::ScopeDenied)?;
        scope.graph.create_view(
            runtime,
            "app",
            allowed(&scope.sources, &scope.policy),
            &scope.revision,
            true,
        )?;
        let required = scope
            .sources
            .values()
            .flat_map(|s| s.documents.iter().map(|d| d.id.clone()))
            .collect();
        let context = scope
            .graph
            .compile(runtime, "app", "release evidence", required, None)?;
        scope.graph.propose(
            runtime,
            &context,
            "native-engine-upgrade-fixture",
            key,
            text,
        )?["proposal_id"]
            .as_str()
            .ok_or(RuntimeError::TransportFailed)?
            .to_owned()
    };
    ask(
        engine,
        runtime,
        json!({"action":"admit_proposal","scope_id":id,"proposal_id":proposal}),
    )?;
    Ok(())
}

// Legacy storage keys do not imply an enrolled-candidate SDK. A catalog
// runtime with fresh legacy-layout data still needs its exact measured build.
fn measured_producer(
    engine: &Engine,
    runtime: &VerifiedRuntime,
) -> Result<EvidenceUpgradeProducer, RuntimeError> {
    if let Some(producer) = &engine.producer {
        return Ok(producer.clone());
    }
    if runtime.status().release.is_none() {
        return EvidenceUpgradeProducer::from_enrolled_runtime(runtime);
    }
    let installation =
        crate::policy_store::context_assistance_registry::load(&engine.home, &engine.runtime_id)
            .map_err(|_| RuntimeError::ApprovalMismatch)?;
    installation
        .measured_selection(
            &engine.home,
            runtime,
            engine.upgrade_selection_data(&engine.home)?,
        )
        .map(|(_, producer)| producer)
        .map_err(|_| RuntimeError::ApprovalMismatch)
}

pub(crate) fn memory_summary(
    engine: &Engine,
    runtime: &mut VerifiedRuntime,
    id: &str,
) -> Result<Value, RuntimeError> {
    let producer = measured_producer(engine, runtime)?;
    let scope = engine.scopes.get(id).ok_or(RuntimeError::ScopeDenied)?;
    let namespace = EvidenceScope::new(&scope.app, scope.root.path())?;
    producer.revalidate_runtime(runtime)?;
    if let Some(mut empty) = scope.graph.empty_memory_note_summary(runtime)? {
        empty["scope_sha256"] = json!(namespace.namespace_sha256());
        empty["source_producer"] = producer.describe();
        return Ok(empty);
    }
    let notes = scope
        .graph
        .upgrade_memory_notes(runtime, &namespace, &producer)?
        .ok_or(RuntimeError::ScopeDenied)?;
    let mut summary = notes.describe();
    summary["documents_sha256"] = json!(notes.documents_sha256()?);
    Ok(summary)
}

pub(crate) fn reviewed_summary(
    engine: &Engine,
    runtime: &mut VerifiedRuntime,
    id: &str,
) -> Result<Value, RuntimeError> {
    if engine.storage_mode == guard_context_assistance::StorageMode::Memory {
        return memory_summary(engine, runtime, id);
    }
    let producer = measured_producer(engine, runtime)?;
    let scope = engine.scopes.get(id).ok_or(RuntimeError::ScopeDenied)?;
    let namespace = EvidenceScope::new(&scope.app, scope.root.path())?;
    let notes = scope
        .graph
        .upgrade_notes(runtime, &namespace, &producer, now_ms())?
        .ok_or(RuntimeError::ScopeDenied)?;
    let mut summary = notes.describe();
    summary["documents_sha256"] = json!(notes.documents_sha256()?);
    Ok(summary)
}
