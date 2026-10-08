//! Port of `_apply_package_protect_projection` (local_supply_chain.py:1914)
//! and `_package_protect_denied_after_final_boundary` (:1992).
//!
//! `_apply_package_protect_projection` projects one authority/evaluation pair
//! into every user and audit surface: `request`, `targets`, `verdict`,
//! `receipt`, `matched_advisories`, `supply_chain_evaluation`, and `executed`.
//! It returns the receipt/receipt-policy-metadata/verdict-action/risk-signals
//! projection the caller persists.
//!
//! `_package_protect_denied_after_final_boundary` is the mixed
//! side-effecting variant: it runs the same projection with
//! `blocking=True, executed=False`, then persists the receipt, stamps the
//! action envelope, records an `install_time_<action>` event, and returns the
//! mutated payload with the package-execution exit code derived from
//! `evaluation.policy_action`.
//!
//! PARITY NOTES / divergent-duplicate flags (reported, NOT unified):
//!   * `local_supply_chain.rs::apply_package_protect_projection` (:7440) is a
//!     private divergent copy of this function. It differs materially: it
//!     builds `payload["command"]` (argv/redacted/tokens) instead of the
//!     Python `payload["request"]["command"]`/`redacted_command`/`install_kind`
//!     `/executor`/`package_manager`/`harness` shape, omits `payload
//!     ["supply_chain_evaluation"]` and `payload["matched_advisories"]`, and
//!     returns a 5-field struct including `blocking`/`executed` rather than
//!     the Python `_PackageProtectProjection` 4-tuple. It uses the divergent
//!     private `package_protect_verdict_context` at :7308 (a different
//!     package_approval::package_protect_verdict_context) and the divergent
//!     `_install_time_event_payload`/`protect_target_payload` copies. Left
//!     untouched per scope; parent integrates.
//!   * `install_time_event::install_time_event_payload` is the canonical port
//!     of `_install_time_event_payload`; the divergent copy lives in
//!     local_supply_chain.rs (:7544).

use serde_json::{json, Map, Value};

use crate::effect_decision::GuardAction;
use crate::local_supply_chain::{PackageRequestEvaluation, SupplyChainStore};
use crate::package_approval::{package_protect_verdict_context, PackageProtectAuthority};
use crate::package_intent_common::PackageIntentTarget;

/// `runtime/package_protect_projection.py:14` — `"guard-cli"`. Distinct from
/// the divergent `local_supply_chain::LOCAL_SUPPLY_CHAIN_HARNESS`
/// (`"local-supply-chain"`).
const GUARD_CLI_HARNESS: &str = "guard-cli";

/// `option_json` — `Some(s)` → `Value::String`, `None` → `Value::Null`
/// (private in `local_supply_chain.rs`; reimplemented to keep this module
/// self-contained per the subagent integration contract).
fn option_json(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// `_apply_package_protect_projection` (:1914)
// ---------------------------------------------------------------------------

/// `_protect_target_payload` (runtime/package_protect_projection.py:91).
/// Public per-target payload. `raw_spec`/`artifact_id`/`artifact_name` fall
/// back to the sanitized `raw_spec` when `package_name` is absent.
fn protect_target_payload(target: &PackageIntentTarget, harness: &str) -> Value {
    let public_target = target.to_dict();
    let raw_spec = public_target
        .get("raw_spec")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let source_url = public_target.get("source_url").cloned();
    let pkg_name = target.package_name.as_deref().filter(|s| !s.is_empty());
    let artifact_id = format!("{}:{}", target.ecosystem, pkg_name.unwrap_or(&raw_spec));
    let artifact_name = pkg_name
        .map(str::to_owned)
        .unwrap_or_else(|| raw_spec.clone());
    json!({
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_type": "package_request",
        "ecosystem": target.ecosystem,
        "package_name": target.package_name,
        "package_url": Value::Null,
        "raw_spec": raw_spec,
        "version": target.requested_specifier,
        "source_url": source_url,
        "harness": harness,
    })
}

/// `shlex.split` (posix, comments off) over the subset reachable from
/// `intent.redacted_command`: whitespace split, single/double quotes,
/// backslash escapes. `#` is a word char (Python default `comments=False`).
/// Unterminated quote → `Err` (ValueError); callers treat as empty argv.
fn shlex_split(input: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    let end = chars.len();
    while index < end {
        while index < end && chars[index].is_whitespace() {
            index += 1;
        }
        if index >= end {
            break;
        }
        let mut token = String::new();
        while index < end && !chars[index].is_whitespace() {
            let c = chars[index];
            match c {
                '\'' => {
                    index += 1;
                    let mut closed = false;
                    while index < end {
                        if chars[index] == '\'' {
                            index += 1;
                            closed = true;
                            break;
                        }
                        token.push(chars[index]);
                        index += 1;
                    }
                    if !closed {
                        return Err("No closing quotation".to_owned());
                    }
                }
                '"' => {
                    index += 1;
                    let mut closed = false;
                    while index < end {
                        if chars[index] == '"' {
                            index += 1;
                            closed = true;
                            break;
                        }
                        if chars[index] == '\\'
                            && index + 1 < end
                            && matches!(chars[index + 1], '"' | '\\' | '$' | '`')
                        {
                            index += 1;
                            token.push(chars[index]);
                            index += 1;
                            continue;
                        }
                        token.push(chars[index]);
                        index += 1;
                    }
                    if !closed {
                        return Err("No closing quotation".to_owned());
                    }
                }
                '\\' => {
                    index += 1;
                    if index < end {
                        token.push(chars[index]);
                        index += 1;
                    }
                }
                _ => {
                    token.push(c);
                    index += 1;
                }
            }
        }
        tokens.push(token);
    }
    Ok(tokens)
}

/// `_package_execution_exit_code` (local_supply_chain.py:4504).
/// `is_execution_permitted` (runtime/package_execution_policy.py:8) permits
/// exactly the strings `"allow"` and `"warn"`; all other values fail closed.
fn package_execution_exit_code(policy_action: &Value) -> i64 {
    if matches!(policy_action.as_str(), Some("allow") | Some("warn")) {
        0
    } else {
        2
    }
}

/// `_PackageProtectProjection` (runtime/package_protect_projection.py:33).
/// `receipt` mirrors `GuardReceipt.to_dict()`; `receipt_id`/`timestamp` are
/// generated per call (uuid4/now) and are therefore not deterministic.
#[derive(Debug, Clone)]
pub struct PackageProtectProjection {
    pub receipt: Value,
    /// `receipt_policy_metadata` mirrors the Python
    /// `dict[str, object]` surface and is stored as a `Value::Object`.
    pub receipt_policy_metadata: Value,
    pub verdict_action: GuardAction,
    pub risk_signals: Vec<String>,
}

/// `_apply_package_protect_projection` (local_supply_chain.py:1914).
/// Projects one authority/evaluation pair into `payload` and returns the
/// persisted projection tuple.
#[allow(clippy::too_many_arguments)]
pub fn apply_package_protect_projection(
    payload: &mut Map<String, Value>,
    authority: &PackageProtectAuthority<'_>,
    evaluation: &PackageRequestEvaluation,
    command: &[String],
    blocking: bool,
    executed: bool,
    execution_policy_action: Option<GuardAction>,
) -> PackageProtectProjection {
    let intent = authority.intent;
    let context = package_protect_verdict_context(authority, evaluation, execution_policy_action);

    // `payload["request"]` — identity + resolved targets + context evidence.
    let mut request = Map::new();
    request.insert(
        "command".to_owned(),
        json!(shlex_split(&intent.redacted_command).unwrap_or_default()),
    );
    request.insert(
        "redacted_command".to_owned(),
        json!(intent.redacted_command),
    );
    request.insert("install_kind".to_owned(), json!(intent.intent_kind));
    request.insert(
        "executor".to_owned(),
        json!(command
            .first()
            .map(String::as_str)
            .unwrap_or(GUARD_CLI_HARNESS)),
    );
    request.insert("package_manager".to_owned(), json!(intent.package_manager));
    request.insert("harness".to_owned(), json!(authority.invoking_harness));
    request.insert("targets".to_owned(), json!(context.public_targets));
    request.insert("manifest_paths".to_owned(), json!(intent.manifest_paths));
    request.insert("lockfile_paths".to_owned(), json!(intent.lockfile_paths));
    request.insert(
        "package_execution_context".to_owned(),
        authority.execution_context.to_evidence(),
    );
    payload.insert("request".to_owned(), Value::Object(request));

    // `payload["targets"]` — one public payload per target.
    payload.insert(
        "targets".to_owned(),
        Value::Array(
            intent
                .targets
                .iter()
                .map(|t| protect_target_payload(t, authority.invoking_harness))
                .collect(),
        ),
    );

    // `payload["verdict"]`.
    let mut verdict = Map::new();
    verdict.insert("action".to_owned(), json!(context.verdict_action.as_str()));
    verdict.insert("reason".to_owned(), json!(context.verdict_reason));
    verdict.insert("risk_signals".to_owned(), json!(context.risk_signals));
    verdict.insert(
        "matched_advisories".to_owned(),
        json!(context.matched_advisories),
    );
    verdict.insert("blocking".to_owned(), json!(blocking));
    if context.observe_projected {
        verdict.insert("observe_mode".to_owned(), json!(true));
        verdict.insert(
            "observed_policy_action".to_owned(),
            json!(context.observed_policy_action.as_str()),
        );
    }
    payload.insert("verdict".to_owned(), Value::Object(verdict));

    // `payload["receipt"]` — receipt dict + action_envelope_json.
    let mut receipt_val = context.receipt.clone();
    if let Value::Object(ref mut m) = receipt_val {
        m.insert(
            "action_envelope_json".to_owned(),
            context.receipt_policy_metadata.clone(),
        );
    }
    payload.insert("receipt".to_owned(), receipt_val);

    payload.insert(
        "matched_advisories".to_owned(),
        json!(context.matched_advisories),
    );
    // `evaluation.to_dict()` → the wrapped evaluation `Value` verbatim.
    payload.insert(
        "supply_chain_evaluation".to_owned(),
        evaluation.value.clone(),
    );
    payload.insert("executed".to_owned(), json!(executed));

    PackageProtectProjection {
        receipt: context.receipt,
        receipt_policy_metadata: context.receipt_policy_metadata,
        verdict_action: context.verdict_action,
        risk_signals: context.risk_signals,
    }
}

/// `_install_time_event_payload` (local_supply_chain.py:1972).
/// Composes `{artifact_id, artifact_name, executor, harness, install_kind,
/// action, risk_signals}` against the borrowed authority. `executor` is
/// `str(command[0])` when `command` is non-empty else `"guard-cli"`.
fn install_time_event_payload(
    authority: &PackageProtectAuthority<'_>,
    command: &[String],
    action: GuardAction,
    risk_signals: &[String],
) -> Value {
    json!({
        "artifact_id": authority.artifact.artifact_id,
        "artifact_name": authority.artifact.name,
        "executor": command.first().map(String::as_str).unwrap_or(GUARD_CLI_HARNESS),
        "harness": authority.invoking_harness,
        "install_kind": authority.intent.intent_kind,
        "action": action.as_str(),
        "risk_signals": risk_signals,
    })
}

// ---------------------------------------------------------------------------
// `_package_protect_denied_after_final_boundary` (:1992)
// ---------------------------------------------------------------------------

/// `_package_protect_denied_after_final_boundary` (local_supply_chain.py:1992).
/// Runs the projection with `blocking=True, executed=False`, persists the
/// receipt + action envelope + `install_time_<action>` event, and returns the
/// mutated payload together with the package-execution exit code.
pub fn package_protect_denied_after_final_boundary(
    payload: &mut Map<String, Value>,
    authority: &PackageProtectAuthority<'_>,
    evaluation: &PackageRequestEvaluation,
    command: &[String],
    store: &dyn SupplyChainStore,
    now: &str,
) -> (Map<String, Value>, i64) {
    let projection = apply_package_protect_projection(
        payload, authority, evaluation, command, true, false, None,
    );
    store.add_receipt(&projection.receipt);
    store.set_receipt_action_envelope(
        projection
            .receipt
            .get("receipt_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        &projection.receipt_policy_metadata,
    );
    store.add_event(
        &format!("install_time_{}", projection.verdict_action.as_str()),
        &install_time_event_payload(
            authority,
            command,
            projection.verdict_action,
            &projection.risk_signals,
        ),
        now,
    );
    let exit_code = package_execution_exit_code(&option_json(evaluation.policy_action()));
    (payload.clone(), exit_code)
}

// ---------------------------------------------------------------------------
// Tests — Python oracle parity (fixtures generated via `concat!` blocks).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use crate::local_supply_chain::PackageRequestEvaluation;
    use crate::package_execution_context::{
        PackageExecutionContext, PackageExecutionContextComponent,
    };
    use crate::package_intent_common::{GuardArtifact, PackageIntent, PackageIntentTarget};

    fn ctx() -> PackageExecutionContext {
        PackageExecutionContext {
            digest: "d".repeat(64),
            portable: false,
            components: vec![PackageExecutionContextComponent {
                name: "workspace".to_string(),
                digest: "a".repeat(64),
            }],
            non_portable_reason: Some("no git remote".to_string()),
        }
    }

    fn artifact() -> GuardArtifact {
        GuardArtifact {
            artifact_id: "art-1".to_string(),
            name: "cli-artifact".to_string(),
            harness: "guard-cli".to_string(),
            artifact_type: "package-request".to_string(),
            source_scope: "workspace".to_string(),
            config_path: "/tmp/proj/.holguard".to_string(),
            command: None,
            args: vec![],
            url: None,
            transport: None,
            publisher: None,
            metadata: json!({}),
            runtime_private_metadata: json!({}),
        }
    }

    fn intent() -> PackageIntent {
        PackageIntent {
            package_manager: "npm".to_string(),
            intent_kind: "install",
            command_tokens: vec!["npm".into(), "install".into(), "lodash".into()],
            redacted_command: "npm install lodash".into(),
            targets: vec![PackageIntentTarget {
                ecosystem: "npm".into(),
                package_name: Some("lodash".into()),
                raw_spec: "lodash@4.17.21".into(),
                requested_specifier: Some("^4.0.0".into()),
                ..Default::default()
            }],
            manifest_paths: vec!["package.json".into()],
            lockfile_paths: vec!["package-lock.json".into()],
            flags: vec![],
            notes: vec![],
            local_executions: vec![],
            execution_context_hashes: vec![],
            execution_context_cwds: vec![],
            execution_context_reason_codes: vec![],
        }
    }

    fn authority<'a>(
        intent: &'a PackageIntent,
        artifact: &'a GuardArtifact,
        ctx: &'a PackageExecutionContext,
        observe_mode: bool,
    ) -> PackageProtectAuthority<'a> {
        PackageProtectAuthority {
            intent,
            artifact,
            execution_context: ctx,
            artifact_hash: "h",
            additional_policy_context: None,
            observe_mode,
            invoking_harness: "guard-cli",
        }
    }

    fn evaluation() -> PackageRequestEvaluation {
        PackageRequestEvaluation::new(json!({
            "policy_action": "require-reapproval",
            "user_copy": {"summary": "Needs reapproval.", "harness_message": "HM."},
            "matched_rule_id": "rule-7",
            "policy_version": "2026.09",
            "bundle_version": "bundle-1",
            "reasons": [{"signal": "sig-1"}, {"signal": "sig-2"}],
            "packages": [{"matched_advisories": [{"id": "ADV-1"}]}],
        }))
    }

    #[test]
    fn projection_request_block_matches_oracle() {
        let intent = intent();
        let artifact = artifact();
        let cx = ctx();
        let evaln = evaluation();
        let auth = authority(&intent, &artifact, &cx, false);
        let mut payload = Map::new();
        apply_package_protect_projection(
            &mut payload,
            &auth,
            &evaln,
            &["npm".into(), "install".into(), "lodash".into()],
            true,
            false,
            None,
        );
        let request = &payload["request"];
        assert_eq!(
            request["command"],
            json!(["npm", "install", "lodash"]),
            "request.command = shlex.split(redacted_command)"
        );
        assert_eq!(request["redacted_command"], json!("npm install lodash"));
        assert_eq!(request["install_kind"], json!("install"));
        assert_eq!(request["executor"], json!("npm"));
        assert_eq!(request["package_manager"], json!("npm"));
        assert_eq!(request["harness"], json!("guard-cli"));
        assert_eq!(request["manifest_paths"], json!(["package.json"]));
        assert_eq!(request["lockfile_paths"], json!(["package-lock.json"]));
        assert_eq!(request["package_execution_context"], cx.to_evidence(),);
        // public target hash parity (oracle: adaac414...)
        let target0 = &request["targets"][0];
        assert_eq!(
            target0["raw_spec_hash"],
            json!("adaac4144887ebc2c1b682380ff385210f681fc58b4bc1ef3986148cf8dcd28a")
        );
    }

    #[test]
    fn projection_targets_block_matches_oracle() {
        let intent = intent();
        let artifact = artifact();
        let cx = ctx();
        let evaln = evaluation();
        let auth = authority(&intent, &artifact, &cx, false);
        let mut payload = Map::new();
        apply_package_protect_projection(
            &mut payload,
            &auth,
            &evaln,
            &["npm".into(), "install".into(), "lodash".into()],
            true,
            false,
            None,
        );
        assert_eq!(
            payload["targets"],
            json!([{
                "artifact_id": "npm:lodash",
                "artifact_name": "lodash",
                "artifact_type": "package_request",
                "ecosystem": "npm",
                "package_name": "lodash",
                "package_url": null,
                "raw_spec": "lodash@4.17.21",
                "version": "^4.0.0",
                "source_url": null,
                "harness": "guard-cli",
            }])
        );
    }

    #[test]
    fn projection_verdict_and_executed_flags() {
        let intent = intent();
        let artifact = artifact();
        let cx = ctx();
        let evaln = evaluation();
        let auth = authority(&intent, &artifact, &cx, false);
        let mut payload = Map::new();
        apply_package_protect_projection(
            &mut payload,
            &auth,
            &evaln,
            &["npm".into()],
            true,
            false,
            None,
        );
        let verdict = &payload["verdict"];
        assert_eq!(verdict["action"], json!("require-reapproval"));
        assert_eq!(verdict["reason"], json!("Needs reapproval."));
        assert_eq!(verdict["blocking"], json!(true));
        assert!(verdict.get("observe_mode").is_none());
        assert_eq!(payload["executed"], json!(false));
        assert_eq!(payload["supply_chain_evaluation"], evaln.value.clone());
        assert_eq!(payload["matched_advisories"], json!([]));
    }

    #[test]
    fn projection_observe_mode_injects_override_keys() {
        let intent = intent();
        let artifact = artifact();
        let cx = ctx();
        let evaln = evaluation();
        // observe_mode=true + execution override differing from observed policy
        let auth = authority(&intent, &artifact, &cx, true);
        let mut payload = Map::new();
        let proj = apply_package_protect_projection(
            &mut payload,
            &auth,
            &evaln,
            &["npm".into()],
            false,
            true,
            Some(GuardAction::Allow),
        );
        let verdict = &payload["verdict"];
        assert_eq!(verdict["action"], json!("allow"));
        assert_eq!(verdict["observe_mode"], json!(true));
        assert_eq!(
            verdict["observed_policy_action"],
            json!("require-reapproval")
        );
        assert_eq!(proj.verdict_action, GuardAction::Allow);
        assert_eq!(payload["executed"], json!(true));
    }

    #[test]
    fn projection_empty_command_executor_falls_back_to_guard_cli() {
        let intent = intent();
        let artifact = artifact();
        let cx = ctx();
        let evaln = evaluation();
        let auth = authority(&intent, &artifact, &cx, false);
        let mut payload = Map::new();
        apply_package_protect_projection(&mut payload, &auth, &evaln, &[], true, false, None);
        assert_eq!(payload["request"]["executor"], json!("guard-cli"));
    }

    // A thread-safe recording store to observe the denied-path mutations.
    #[derive(Default)]
    struct RecordingStore {
        home: PathBuf,
        receipts: Mutex<Vec<Value>>,
        envelopes: Mutex<Vec<(String, Value)>>,
        events: Mutex<Vec<(String, Value, String)>>,
    }

    impl SupplyChainStore for RecordingStore {
        fn guard_home(&self) -> &std::path::Path {
            &self.home
        }
        fn get_cloud_sync_profile(&self) -> Option<Value> {
            None
        }
        fn get_cloud_workspace_id(&self) -> Option<String> {
            None
        }
        fn get_cached_supply_chain_bundle(&self, _w: &str) -> Option<Value> {
            None
        }
        fn get_sync_payload(&self, _k: &str) -> Option<Value> {
            None
        }
        fn set_sync_payload(&self, _k: &str, _p: &Value) {}
        fn list_cached_advisories(&self) -> Vec<Value> {
            vec![]
        }
        fn list_managed_installs(&self) -> Vec<Value> {
            vec![]
        }
        fn record_latest_guard_connect_sync_result(
            &self,
            _s: &str,
            _m: &str,
            _n: &str,
            _r: Option<&str>,
        ) {
        }
        fn get_approval_request(&self, _id: &str) -> Option<Value> {
            None
        }
        fn resolve_policy_decision_lookup(
            &self,
            _h: &str,
            _a: &str,
            _ah: Option<&str>,
            _w: &str,
            _p: Option<&str>,
            _n: &str,
            _c: bool,
        ) -> crate::local_supply_chain::PolicyDecisionLookup {
            Default::default()
        }
        fn approval_reuse_diagnostic(
            &self,
            _h: &str,
            _a: &str,
            _ah: &str,
            _w: &str,
            _p: Option<&str>,
            _n: &str,
        ) -> (Option<String>, Option<String>) {
            (None, None)
        }
        fn approval_reuse_claim_disposition(&self, _d: &Value) -> Option<String> {
            None
        }
        fn claim_approval_reuse_decision(&self, _d: &Value, _n: &str) -> bool {
            false
        }
        fn claim_local_once_approval(&self, _id: &str, _c: &str, _d: &Value) -> bool {
            false
        }
        fn add_receipt(&self, receipt: &Value) {
            self.receipts.lock().unwrap().push(receipt.clone());
        }
        fn set_receipt_action_envelope(&self, receipt_id: &str, metadata: &Value) {
            self.envelopes
                .lock()
                .unwrap()
                .push((receipt_id.to_string(), metadata.clone()));
        }
        fn add_event(&self, kind: &str, payload: &Value, now: &str) {
            self.events
                .lock()
                .unwrap()
                .push((kind.to_string(), payload.clone(), now.to_string()));
        }
    }

    #[test]
    fn denied_mutates_payload_persists_receipt_and_event() {
        let intent = intent();
        let artifact = artifact();
        let cx = ctx();
        let evaln = evaluation();
        let auth = authority(&intent, &artifact, &cx, false);
        let store = RecordingStore::default();
        let mut payload = Map::new();
        let (returned, exit_code) = package_protect_denied_after_final_boundary(
            &mut payload,
            &auth,
            &evaln,
            &["npm".into(), "install".into(), "lodash".into()],
            &store,
            "2026-10-03T00:00:00Z",
        );
        // policy_action "require-reapproval" is not allow/warn → exit 2
        assert_eq!(exit_code, 2);
        // returned payload mirrors mutated map
        assert_eq!(returned["verdict"]["blocking"], json!(true));
        assert_eq!(returned["executed"], json!(false));
        assert_eq!(payload["verdict"]["action"], json!("require-reapproval"));
        // one receipt persisted
        let receipts = store.receipts.lock().unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0]["receipt_id"]
            .as_str()
            .unwrap()
            .starts_with("guard-receipt-"));
        // envelope stamped under the same receipt_id
        let envelopes = store.envelopes.lock().unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].0, receipts[0]["receipt_id"].as_str().unwrap());
        assert_eq!(envelopes[0].1["policy_action"], json!("require-reapproval"));
        // event kind + payload
        let events = store.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "install_time_require-reapproval");
        assert_eq!(events[0].1["artifact_id"], json!("art-1"));
        assert_eq!(events[0].1["executor"], json!("npm"));
        assert_eq!(events[0].1["harness"], json!("guard-cli"));
        assert_eq!(events[0].1["action"], json!("require-reapproval"));
        assert_eq!(events[0].2, "2026-10-03T00:00:00Z");
    }

    #[test]
    fn denied_exit_code_is_zero_for_allow_or_warn() {
        let intent = intent();
        let artifact = artifact();
        let cx = ctx();
        let mut eval_allow = evaluation();
        eval_allow.value["policy_action"] = json!("allow");
        let auth = authority(&intent, &artifact, &cx, false);
        let store = RecordingStore::default();
        let mut payload = Map::new();
        let (_, code) = package_protect_denied_after_final_boundary(
            &mut payload,
            &auth,
            &eval_allow,
            &["npm".into()],
            &store,
            "n",
        );
        assert_eq!(code, 0, "allow → exit 0");

        let mut eval_warn = evaluation();
        eval_warn.value["policy_action"] = json!("warn");
        let mut payload2 = Map::new();
        let (_, code2) = package_protect_denied_after_final_boundary(
            &mut payload2,
            &auth,
            &eval_warn,
            &["npm".into()],
            &store,
            "n",
        );
        assert_eq!(code2, 0, "warn → exit 0");
    }

    #[test]
    fn denied_exit_code_is_two_for_unknown_or_missing_action() {
        let intent = intent();
        let artifact = artifact();
        let cx = ctx();
        let mut eval_missing = evaluation();
        eval_missing
            .value
            .as_object_mut()
            .unwrap()
            .remove("policy_action");
        let auth = authority(&intent, &artifact, &cx, false);
        let store = RecordingStore::default();
        let mut payload = Map::new();
        let (_, code) = package_protect_denied_after_final_boundary(
            &mut payload,
            &auth,
            &eval_missing,
            &["npm".into()],
            &store,
            "n",
        );
        assert_eq!(code, 2, "missing policy_action fails closed → 2");

        let mut eval_block = evaluation();
        eval_block.value["policy_action"] = json!("monitor");
        let mut p2 = Map::new();
        let (_, c2) = package_protect_denied_after_final_boundary(
            &mut p2,
            &auth,
            &eval_block,
            &["npm".into()],
            &store,
            "n",
        );
        assert_eq!(c2, 2, "monitor (telemetry) fails closed → 2");
    }
    #[test]
    fn projection_quoted_shlex_and_raw_spec_fallback_match_oracle() {
        // Oracle (Python): shlex.split("pip install 'req uests'") ==
        //   ["pip","install","req uests"]; package_name=None →
        //   artifact_id "pypi:requests>=2", artifact_name "requests>=2".
        let mut pypi_intent = intent();
        pypi_intent.package_manager = "pip".to_string();
        pypi_intent.redacted_command = "pip install 'req uests'".into();
        pypi_intent.targets = vec![PackageIntentTarget {
            ecosystem: "pypi".into(),
            package_name: None,
            raw_spec: "requests>=2".into(),
            requested_specifier: Some(">=2".into()),
            ..Default::default()
        }];
        let artifact = artifact();
        let cx = ctx();
        let evaln = evaluation();
        let auth = authority(&pypi_intent, &artifact, &cx, false);
        let mut payload = Map::new();
        apply_package_protect_projection(
            &mut payload,
            &auth,
            &evaln,
            &[], // empty command → executor falls back to "guard-cli"
            true,
            false,
            None,
        );
        assert_eq!(
            payload["request"]["command"],
            json!(["pip", "install", "req uests"])
        );
        assert_eq!(payload["request"]["executor"], json!("guard-cli"));
        let tgt = &payload["targets"][0];
        assert_eq!(tgt["artifact_id"], json!("pypi:requests>=2"));
        assert_eq!(tgt["artifact_name"], json!("requests>=2"));
        assert_eq!(tgt["package_name"], Value::Null);
        assert_eq!(tgt["version"], json!(">=2"));
        assert_eq!(tgt["package_url"], Value::Null);
    }

    #[test]
    fn shlex_split_matches_python_posix_semantics() {
        // unterminated quote → error → empty argv (ValueError → [])
        assert!(shlex_split("'unterminated").is_err());
        assert_eq!(shlex_split(r"a\ b").unwrap(), vec!["a b"]);
        assert_eq!(shlex_split("a  b").unwrap(), vec!["a", "b"]);
        assert_eq!(shlex_split("").unwrap(), Vec::<String>::new());
        // '#' is a word char (Python default comments=False)
        assert_eq!(shlex_split("a#b c").unwrap(), vec!["a#b", "c"]);
    }
}
