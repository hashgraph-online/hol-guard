use super::*;

struct NoScoring;
impl TrustScoringApi for NoScoring {
    fn resolve_skill_security_context(&self, _: &Path, _: &ScanOptions) -> SkillSecurityContext {
        SkillSecurityContext::default()
    }
    fn build_plugin_domain(&self, _: &Path) -> Option<TrustDomainScore> {
        None
    }
    fn build_skill_domain(&self, _: &Path, _: &SkillSecurityContext) -> Option<TrustDomainScore> {
        None
    }
    fn build_mcp_domain(&self, _: &Path) -> Option<TrustDomainScore> {
        None
    }
    fn build_mcp_surface_domain(
        &self,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Option<TrustDomainScore> {
        None
    }
    fn build_instruction_domain(&self, _: &Path, _: &str, _: &str) -> Option<TrustDomainScore> {
        None
    }
}
struct Evidence;
impl GuardEvidenceHashApi for Evidence {
    fn guard_evidence_hash(&self, payload: &Map<String, Value>) -> String {
        serde_json::to_string(payload).unwrap()
    }
}
struct Boundary;
impl TrustMetadataBoundaryApi for Boundary {
    fn separate_untrusted_adapter_trust_metadata(
        &self,
        metadata: Map<String, Value>,
    ) -> Map<String, Value> {
        metadata
    }
}
fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn scanner_config_path_uses_private_inventory_key() {
    let run = object(
        json!({"metadata":{"_configPath":"actual/config.json","configPath":"wrong/config.json"}}),
    );
    assert_eq!(
        _cisco_run_config_path(&run),
        Some(PathBuf::from("actual/config.json"))
    );
    assert_eq!(
        _cisco_run_config_path(&object(
            json!({"metadata":{"configPath":"wrong/config.json"}})
        )),
        None
    );
}

#[test]
fn scanner_target_path_preserves_python_fallback_and_missing_semantics() {
    for absent in [
        Value::Null,
        json!(""),
        json!(" "),
        json!("missing"),
        json!(7),
    ] {
        let run = object(
            json!({"metadata":{"_targetPath":absent,"target":"fallback"},"target_path":"wrong"}),
        );
        assert_eq!(
            _cisco_run_target_path(&run),
            Some(PathBuf::from("fallback"))
        );
    }
    let run = object(json!({"metadata":{"_targetPath":"actual","target":"fallback"}}));
    assert_eq!(_cisco_run_target_path(&run), Some(PathBuf::from("actual")));
    for metadata in [
        json!({}),
        json!({"target":"missing"}),
        json!({"targetPath":"wrong"}),
    ] {
        assert_eq!(
            _cisco_run_target_path(&object(json!({"metadata":metadata,"target_path":"wrong"}))),
            None
        );
    }
}

#[test]
fn cisco_mcp_inventory_retains_trust_layer_and_local_security() {
    let config = std::env::current_exe().unwrap();
    let artifact = object(
        json!({"artifact_type":"mcp_server","config_path":config.to_string_lossy(),"name":"server"}),
    );
    let run = object(
        json!({"source":"cisco-mcp-scanner","status":"enabled","findings":[],"metadata":{"_configPath":config.to_string_lossy(),"_targetPath":config.parent().unwrap().to_string_lossy()}}),
    );
    let deps = TrustDeps {
        scoring: &NoScoring,
        evidence_hash: &Evidence,
        boundary: &Boundary,
    };
    let metadata = apply_local_trust_metadata(
        &artifact,
        &deps,
        "2026-10-03T12:00:00Z",
        "mcp_server",
        Map::new(),
        None,
        &[run],
    );
    let layers = metadata
        .get("trustLayers")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(layers.len(), 1);
    assert_eq!(
        metadata["localSecurity"]["provider"],
        json!("cisco-mcp-scanner")
    );
    assert_eq!(metadata["localSecurity"]["entityType"], json!("mcp_server"));
}
