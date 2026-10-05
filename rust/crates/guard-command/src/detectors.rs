//! Rust port of `runtime/detectors.py` — runtime detector registry
//! primitives for Guard actions.
//!
//! Port notes (matching crate conventions in `data_flow_rules.rs` /
//! `local_supply_chain.rs`):
//!   - `RiskSignalV2` / `RiskSignalCategory` / label helpers come from
//!     `guard_contracts::signal_contract`.
//!   - `GuardActionEnvelope` -> `DetectorActionView` seam (borrowed fields).
//!   - `GuardConfig` -> `config: Option<&Map<String, Value>>` on
//!     `DetectorContext`; only `runtime_detector_timeout_ms` is read by the
//!     Cisco seam detectors, via `runtime_detector_timeout_ms()`.
//!   - `PromptRequest` -> `PromptRequestView` (borrowed record produced by
//!     the `PromptInjectionApi` seam).
//!   - `PersistenceMatch` -> `PersistenceMatchView`.
//!   - `DecodeResult` -> `DecodeResultView` / `DecodeLayerView`.
//!   - `SecretPathMatch` -> `crate::shell_secret_read_support::SecretPathMatch`
//!     (already ported); `classify_secret_path` is reused directly.
//!   - Unported dependencies surface as traits (`*Api`), injected on the
//!     detector structs (mirroring `local_supply_chain.rs` / `RiskDetectApi`).
//!   - Cisco preflight detectors come from `cisco_preflight.py` (another
//!     module); they are injected as `Box<dyn GuardDetector>` instances
//!     through `CiscoPreflightApi`.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;
use serde_json::{Map, Value};

use guard_contracts::{
    confidence_label_from_score, severity_label_from_score, RiskConfidenceLabel,
    RiskRedactionLevel, RiskSeverityLabel, RiskSignalCategory, RiskSignalV2,
};

use crate::data_flow_rules::detect_data_flow_exfiltration;
use crate::data_flow_rules::GuardActionEnvelopeView;
use crate::false_positive_rules::{
    classify_docs_example_source, classify_health_endpoint_fetch, classify_package_metadata_access,
    classify_read_only_http_fetch, classify_source_search_command, classify_version_file_access,
};
use crate::shell_secret_read_support::classify_secret_path;
use crate::shell_secret_read_support::SecretPathMatch;

// ---------------------------------------------------------------------------
// Module constants (:40-54).
// ---------------------------------------------------------------------------

/// `DETECTOR_CATEGORY_TAGS` (:40-52).
pub const DETECTOR_CATEGORY_TAGS: &[RiskSignalCategory] = &[
    RiskSignalCategory::Secret,
    RiskSignalCategory::Network,
    RiskSignalCategory::Prompt,
    RiskSignalCategory::Mcp,
    RiskSignalCategory::Skill,
    RiskSignalCategory::SupplyChain,
    RiskSignalCategory::Encoded,
    RiskSignalCategory::Persistence,
    RiskSignalCategory::Bypass,
    RiskSignalCategory::FalsePositive,
    RiskSignalCategory::Filesystem,
    RiskSignalCategory::Execution,
];

/// `DetectorRunStatus` (:53) — Literal["ok","disabled","filtered","timeout","error"].
pub type DetectorRunStatus = &'static str;
pub const STATUS_OK: DetectorRunStatus = "ok";
pub const STATUS_DISABLED: DetectorRunStatus = "disabled";
pub const STATUS_FILTERED: DetectorRunStatus = "filtered";
pub const STATUS_TIMEOUT: DetectorRunStatus = "timeout";
pub const STATUS_ERROR: DetectorRunStatus = "error";

/// `_SLOW_DETECTOR_THRESHOLD_MS` (:54).
pub const SLOW_DETECTOR_THRESHOLD_MS: i64 = 100;

/// `_SENSITIVE_DECODE_CONTEXT_PATTERN` (:56-63). Python's regex uses
/// lookarounds `(?!…)`/`(?<!…)` which the `regex` crate does not support;
/// the same boundary guards are enforced manually in
/// `has_sensitive_decode_context` via `alnum_boundary_ok`.
static SENSITIVE_DECODE_CONTEXT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\.env(?:\.[A-Za-z0-9_-]+)?|\.npmrc|id_(?:rsa|ed25519|ecdsa|dsa)|api[_-]?key|private[_-]?key|\.pem|\.key|aws[_-](?:access[_-]?key|secret[_-]?access[_-]?key|session[_-]?token|credentials?)|(?:credentials?|secrets?|tokens?|passwords?)",
    )
    .expect("SENSITIVE_DECODE_CONTEXT_PATTERN")
});

/// Return whether the byte at `index` (if any) is `[A-Za-z0-9_-]` — used to
/// enforce the negative lookarounds on the sensitive-context pattern.
fn sensitive_context_boundary_ok(
    text: &str,
    start: usize,
    end: usize,
    forbid_underscore_dash: bool,
    also_allow_pub_suffix: bool,
) -> bool {
    // `(?<![A-Za-z0-9])` — char immediately before `start` must not be
    // alphanumeric. Only relevant for the credential/secret/token/password
    // alternation and checked by the caller.
    let _ = start;
    let bytes = text.as_bytes();
    if end < bytes.len() {
        let next = bytes[end] as char;
        let is_forbidden = if forbid_underscore_dash {
            next.is_ascii_alphanumeric() || next == '_' || next == '-'
        } else {
            next.is_ascii_alphanumeric()
        };
        if is_forbidden && !also_allow_pub_suffix {
            return false;
        }
        // `.pub\b` alternative for `id_*`: if the next bytes are `.pub`
        // followed by a word boundary, the lookahead accepts it.
        if also_allow_pub_suffix && next == '.' {
            if text[end..].starts_with(".pub") {
                let after = end + 4;
                if after >= bytes.len()
                    || !(bytes[after] as char).is_ascii_alphanumeric()
                        && (bytes[after] as char) != '_'
                {
                    return true;
                }
            }
            return false;
        }
        if is_forbidden {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Seam views (:66-116 and collaborator types).
// ---------------------------------------------------------------------------

/// `GuardActionEnvelope` — borrowed view of the fields read by detectors.
#[derive(Debug, Clone, Copy)]
pub struct DetectorActionView<'a> {
    pub action_type: &'a str,
    pub command: Option<&'a str>,
    pub prompt_text: Option<&'a str>,
    pub prompt_excerpt: Option<&'a str>,
    pub mcp_tool: Option<&'a str>,
    pub target_paths: &'a [String],
}

impl<'a> DetectorActionView<'a> {
    /// Bridge to the narrower `GuardActionEnvelopeView` used by
    /// `data_flow_rules`.
    fn as_envelope_view(&self) -> GuardActionEnvelopeView<'a> {
        GuardActionEnvelopeView {
            action_type: self.action_type,
            command: self.command,
        }
    }
}

/// `DetectorContext` (:66-74) — context shared with runtime detectors.
///
/// `config` is a `Map<String, Value>` mirror of `GuardConfig` (unported);
/// `prior_decisions`, `threat_intel`, and `redaction_settings` are `Mapping`
/// mirrors. `workspace`/`approved_scan_roots` stay `Path`-typed.
#[derive(Debug, Clone)]
pub struct DetectorContext<'a> {
    /// `GuardConfig` mirror — `runtime_detector_timeout_ms` etc. read via
    /// `Map` key access (the Python dataclass attributes are flat).
    pub config: &'a Map<String, Value>,
    pub workspace: Option<&'a Path>,
    pub prior_decisions: &'a Map<String, Value>,
    pub threat_intel: &'a Map<String, Value>,
    pub redaction_settings: &'a Map<String, Value>,
    pub approved_scan_roots: &'a [PathBuf],
}

impl DetectorContext<'_> {
    /// `getattr(config, "runtime_detector_timeout_ms", 5000)` —
    /// Cisco seam reads this on the config object.
    pub fn runtime_detector_timeout_ms(&self, default_ms: i64) -> i64 {
        self.config
            .get("runtime_detector_timeout_ms")
            .and_then(Value::as_i64)
            .unwrap_or(default_ms)
    }
}

/// `PromptRequest` — borrowed view of the prompt-injection request record.
#[derive(Debug, Clone, Copy)]
pub struct PromptRequestView<'a> {
    pub request_id: &'a str,
    pub request_class: &'a str,
    pub summary: &'a str,
    pub matched_text: &'a str,
    pub severity: i64,
    pub confidence: f64,
    /// `RemediationAction.detail` values (already filtered to `Some`).
    pub remediation_details: &'a [String],
}

/// `PersistenceMatch` — borrowed view of a persistence mechanism match.
#[derive(Debug, Clone, Copy)]
pub struct PersistenceMatchView<'a> {
    pub mechanism: &'a str,
    pub plain_reason: &'a str,
    pub false_positive_hint: &'a str,
}

/// `DecodedLayer.encoding` view for `DecodeResult.layers`.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLayerView<'a> {
    pub encoding: &'a str,
}

/// `DecodeResult` — borrowed view of a `decode_layers` result.
#[derive(Debug, Clone)]
pub struct DecodeResultView<'a> {
    pub layers: Vec<DecodeLayerView<'a>>,
    pub final_text: &'a str,
    pub eval_signals: Vec<String>,
    pub exec_signals: Vec<String>,
    pub marshal_signals: Vec<String>,
}

// ---------------------------------------------------------------------------
// Unported-dependency seams (traits, injected; crate convention).
// ---------------------------------------------------------------------------

/// `.runtime.safe_decode` seam (:35 import).
pub trait SafeDecodeApi {
    /// `SAFE_DECODE_DETECTOR_VERSION` module constant.
    fn safe_decode_detector_version(&self) -> &str;
    /// `decode_layers(content)` (:108).
    fn decode_layers<'a>(&self, content: &'a str) -> DecodeResultView<'a>;
}

/// `.runtime.prompt_injection` seam (:33 import).
pub trait PromptInjectionApi {
    /// `detect_prompt_injection_requests(text)` -> sequence of
    /// `PromptRequest` records.
    fn detect_prompt_injection_requests<'a>(&self, text: &'a str) -> Vec<PromptRequestView<'a>>;
}

/// `.runtime.skill_protection` seam (:34 import).
pub trait SkillProtectionApi {
    /// `has_skill_structure(text)` -> bool.
    fn has_skill_structure(&self, text: &str) -> bool;
    /// `detect_skill_content_risk(text)` -> `RiskSignalV2` sequence.
    fn detect_skill_content_risk(&self, text: &str) -> Vec<RiskSignalV2>;
}

/// `.runtime.supply_chain` seam (:36 import).
pub trait SupplyChainRiskApi {
    /// `detect_supply_chain_risk(content)` -> `RiskSignalV2` sequence.
    fn detect_supply_chain_risk(&self, content: &str) -> Vec<RiskSignalV2>;
}

/// `.runtime.persistence_rules` seam (:32 import).
pub trait PersistenceRulesApi {
    /// `detect_persistence_mechanisms(command)` -> `PersistenceMatch`
    /// sequence.
    fn detect_persistence_mechanisms<'a>(&self, command: &'a str) -> Vec<PersistenceMatchView<'a>>;
}

/// `.runtime.cisco_preflight` seam (:14 import) — produces the two
/// scanner-backed `GuardDetector` instances registered first in
/// `register_default_detectors`.
pub trait CiscoPreflightApi {
    fn cisco_mcp_preflight_detector(&self) -> Box<dyn GuardDetector>;
    fn cisco_skill_preflight_detector(&self) -> Box<dyn GuardDetector>;
}

// ---------------------------------------------------------------------------
// GuardDetector trait (:76-90) — `GuardDetector` Protocol.
// ---------------------------------------------------------------------------

/// `GuardDetector` Protocol — detector interface for runtime Guard actions.
pub trait GuardDetector {
    /// `detector_id` attribute.
    fn detector_id(&self) -> &str;
    /// `categories` property.
    fn categories(&self) -> &'static [RiskSignalCategory];
    /// `detect(action, context)` -> typed risk signals.
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2>;
}

// ---------------------------------------------------------------------------
// DetectorTelemetry (:93-110) / DetectorRunResult (:112-122).
// ---------------------------------------------------------------------------

/// `DetectorTelemetry` (:93-110) — debug-safe detector execution telemetry.
#[derive(Debug, Clone)]
pub struct DetectorTelemetry {
    pub detector_id: String,
    pub categories: Vec<RiskSignalCategory>,
    pub status: DetectorRunStatus,
    pub elapsed_ms: i64,
    pub error_type: Option<String>,
}

impl DetectorTelemetry {
    /// `to_dict` (:104-110).
    pub fn to_dict(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert(
            "detector_id".to_string(),
            Value::from(self.detector_id.as_str()),
        );
        out.insert(
            "categories".to_string(),
            Value::Array(
                self.categories
                    .iter()
                    .map(|c| Value::from(c.as_str()))
                    .collect(),
            ),
        );
        out.insert("status".to_string(), Value::from(self.status));
        out.insert("elapsed_ms".to_string(), Value::from(self.elapsed_ms));
        match &self.error_type {
            Some(e) => {
                out.insert("error_type".to_string(), Value::from(e.as_str()));
            }
            None => {
                out.insert("error_type".to_string(), Value::Null);
            }
        }
        out
    }
}

/// `DetectorRunResult` (:112-122) — signals and telemetry from a registry run.
#[derive(Debug, Clone)]
pub struct DetectorRunResult {
    pub signals: Vec<RiskSignalV2>,
    pub telemetry: Vec<DetectorTelemetry>,
}

impl DetectorRunResult {
    /// `slow_detectors(threshold_ms=SLOW_DETECTOR_THRESHOLD_MS)` (:120-122).
    pub fn slow_detectors(&self, threshold_ms: Option<i64>) -> Vec<&DetectorTelemetry> {
        let threshold = threshold_ms.unwrap_or(SLOW_DETECTOR_THRESHOLD_MS);
        self.telemetry
            .iter()
            .filter(|t| t.elapsed_ms >= threshold)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// DetectorRegistry (:124-171).
// ---------------------------------------------------------------------------

/// `DetectorRegistry` — runs detectors in deterministic order with failure
/// isolation. `clock` is an injected monotonic-time source returning
/// `Instant` (the Python default is `time.monotonic`).
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn GuardDetector>>,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl DetectorRegistry {
    /// `__init__` (:128-136) — sorts by `detector_id` ascending.
    pub fn new(
        detectors: Vec<Box<dyn GuardDetector>>,
        clock: Option<Box<dyn Fn() -> Instant + Send + Sync>>,
    ) -> Self {
        let mut detectors = detectors;
        detectors.sort_by(|a, b| a.detector_id().cmp(b.detector_id()));
        DetectorRegistry {
            detectors,
            clock: clock.unwrap_or_else(|| Box::new(Instant::now)),
        }
    }

    /// `run` (:138-171). `timeout_ms` defaults to 50; `disabled_detector_ids`
    /// and `enabled_categories` gate which detectors run.
    pub fn run(
        &self,
        action: &DetectorActionView<'_>,
        context: &DetectorContext<'_>,
        timeout_ms: i64,
        disabled_detector_ids: &[&str],
        enabled_categories: Option<&[RiskSignalCategory]>,
    ) -> DetectorRunResult {
        let disabled: std::collections::HashSet<&str> =
            disabled_detector_ids.iter().copied().collect();
        let category_filter: Option<std::collections::HashSet<RiskSignalCategory>> =
            enabled_categories.map(|c| c.iter().copied().collect());
        let mut signals: Vec<RiskSignalV2> = Vec::new();
        let mut telemetry: Vec<DetectorTelemetry> = Vec::new();
        for detector in &self.detectors {
            if disabled.contains(detector.detector_id()) {
                telemetry.push(telemetry_entry(detector.as_ref(), STATUS_DISABLED, 0, None));
                continue;
            }
            if let Some(filter) = &category_filter {
                let intersects = detector.categories().iter().any(|c| filter.contains(c));
                if !intersects {
                    telemetry.push(telemetry_entry(detector.as_ref(), STATUS_FILTERED, 0, None));
                    continue;
                }
            }
            let started_at = (self.clock)();
            // Detectors return `Vec`; a panicking detector is caught via
            // `catch_unwind` so one failure cannot abort the run (mirrors the
            // Python `except Exception` isolation).
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                detector.detect(action, context)
            }));
            let finished_at = (self.clock)();
            let elapsed = elapsed_ms(started_at, finished_at);
            match outcome {
                Ok(detector_signals) => {
                    signals.extend(filter_signals(&detector_signals, category_filter.as_ref()));
                    if elapsed > timeout_ms {
                        telemetry.push(telemetry_entry(
                            detector.as_ref(),
                            STATUS_TIMEOUT,
                            elapsed,
                            None,
                        ));
                        continue;
                    }
                    telemetry.push(telemetry_entry(detector.as_ref(), STATUS_OK, elapsed, None));
                }
                Err(_panic) => {
                    // `type(error).__name__` — panic payloads do not carry a
                    // class name; record a stable marker.
                    telemetry.push(telemetry_entry(
                        detector.as_ref(),
                        STATUS_ERROR,
                        elapsed,
                        Some("Panic".to_string()),
                    ));
                    continue;
                }
            }
        }
        DetectorRunResult { signals, telemetry }
    }
}

// ---------------------------------------------------------------------------
// Detector implementations.
// ---------------------------------------------------------------------------

/// `SecretPathDetector` (:174-183).
pub struct SecretPathDetector;

impl GuardDetector for SecretPathDetector {
    fn detector_id(&self) -> &str {
        "secret.path"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[RiskSignalCategory::Secret]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        if action.action_type != "file_read" {
            return Vec::new();
        }
        let matches = secret_path_matches(action.target_paths, context.workspace);
        matches
            .iter()
            .enumerate()
            .map(|(index, m)| secret_path_signal(m, index))
            .collect()
    }
}

/// `DataFlowExfiltrationDetector` (:185-189).
pub struct DataFlowExfiltrationDetector;

impl GuardDetector for DataFlowExfiltrationDetector {
    fn detector_id(&self) -> &str {
        "data_flow.exfiltration"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[RiskSignalCategory::Secret, RiskSignalCategory::Network]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        detect_data_flow_exfiltration(&action.as_envelope_view(), context.workspace)
    }
}

/// `PromptInjectionDetector` (:191-198) — wraps the injected
/// `PromptInjectionApi`.
pub struct PromptInjectionDetector<A: PromptInjectionApi> {
    pub api: A,
}

impl<A: PromptInjectionApi> GuardDetector for PromptInjectionDetector<A> {
    fn detector_id(&self) -> &str {
        "prompt.injection"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[
            RiskSignalCategory::Prompt,
            RiskSignalCategory::Secret,
            RiskSignalCategory::Network,
            RiskSignalCategory::Bypass,
            RiskSignalCategory::Filesystem,
            RiskSignalCategory::Execution,
        ]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        if action.action_type != "prompt" || action.prompt_excerpt.is_none() {
            return Vec::new();
        }
        let requests = self
            .api
            .detect_prompt_injection_requests(action.prompt_excerpt.unwrap());
        requests.iter().map(|r| prompt_request_signal(r)).collect()
    }
}

/// `SkillRiskDetector` (:200-219) — wraps the injected `SkillProtectionApi`.
pub struct SkillRiskDetector<A: SkillProtectionApi> {
    pub api: A,
}

impl<A: SkillProtectionApi> GuardDetector for SkillRiskDetector<A> {
    fn detector_id(&self) -> &str {
        "skill.content"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[
            RiskSignalCategory::Skill,
            RiskSignalCategory::Secret,
            RiskSignalCategory::Network,
            RiskSignalCategory::Execution,
            RiskSignalCategory::Persistence,
            RiskSignalCategory::Bypass,
            RiskSignalCategory::Encoded,
        ]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        if action.action_type != "prompt" || action.prompt_text.is_none() {
            return Vec::new();
        }
        let text = action.prompt_text.unwrap();
        if !self.api.has_skill_structure(text) {
            return Vec::new();
        }
        self.api.detect_skill_content_risk(text)
    }
}

/// `SupplyChainDetector` (:221-236) — wraps the injected
/// `SupplyChainRiskApi`.
pub struct SupplyChainDetector<A: SupplyChainRiskApi> {
    pub api: A,
}

impl<A: SupplyChainRiskApi> GuardDetector for SupplyChainDetector<A> {
    fn detector_id(&self) -> &str {
        "supply-chain.content"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[
            RiskSignalCategory::SupplyChain,
            RiskSignalCategory::Persistence,
            RiskSignalCategory::Secret,
            RiskSignalCategory::Execution,
            RiskSignalCategory::Network,
        ]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        let mut signals: Vec<RiskSignalV2> = Vec::new();
        // `filter(None, (action.prompt_text, action.command))` — skip None
        // and empty strings.
        for content in [action.prompt_text, action.command]
            .iter()
            .copied()
            .flatten()
            .filter(|s| !s.is_empty())
        {
            signals.extend(self.api.detect_supply_chain_risk(content));
        }
        signals
    }
}

/// `SafeDecodeDetector` (:238-261) — wraps the injected `SafeDecodeApi`.
pub struct SafeDecodeDetector<A: SafeDecodeApi> {
    pub api: A,
}

impl<A: SafeDecodeApi> GuardDetector for SafeDecodeDetector<A> {
    fn detector_id(&self) -> &str {
        "safe-decode.content"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[
            RiskSignalCategory::Encoded,
            RiskSignalCategory::Execution,
            RiskSignalCategory::Network,
            RiskSignalCategory::Secret,
        ]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        // `value for value in (prompt_text, command) if value` — truthy
        // non-empty strings only.
        let candidates: Vec<&str> = [action.prompt_text, action.command]
            .iter()
            .copied()
            .flatten()
            .filter(|s| !s.is_empty())
            .collect();
        for content in candidates {
            let result = self.api.decode_layers(content);
            let signals = safe_decode_signals(
                &result,
                self.detector_id(),
                content,
                self.api.safe_decode_detector_version(),
            );
            if !signals.is_empty() {
                return signals;
            }
        }
        Vec::new()
    }
}

/// `FalsePositiveSuppressorDetector` (:365-509).
pub struct FalsePositiveSuppressorDetector;

impl GuardDetector for FalsePositiveSuppressorDetector {
    fn detector_id(&self) -> &str {
        "false_positive.suppressor"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[RiskSignalCategory::FalsePositive]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        let mut signals: Vec<RiskSignalV2> = Vec::new();
        if action.action_type == "shell_command" && action.command.is_some() {
            let command = action.command.unwrap();
            let classification = classify_source_search_command(command);
            if classification.is_source_search {
                signals.push(RiskSignalV2 {
                    signal_id: format!(
                        "fp:source-search:{}",
                        classification.tool.as_deref().unwrap_or("")
                    ),
                    category: RiskSignalCategory::FalsePositive,
                    severity: RiskSeverityLabel::Info,
                    confidence: RiskConfidenceLabel::Strong,
                    detector: self.detector_id().to_string(),
                    title: "Read-only code or filesystem search".to_string(),
                    plain_reason: format!(
                        "This command uses '{}' to search code or the filesystem and does not access secret files or pipe output to the network.",
                        classification.tool.as_deref().unwrap_or("")
                    ),
                    technical_detail: classification.reason.map(|r| r.to_string()),
                    evidence_ref: Some("command".to_string()),
                    redaction_level: RiskRedactionLevel::None,
                    false_positive_hint: None,
                    advisory_id: None,
                });
            }
            if classify_health_endpoint_fetch(command) {
                signals.push(RiskSignalV2 {
                    signal_id: "fp:health-endpoint-fetch".to_string(),
                    category: RiskSignalCategory::FalsePositive,
                    severity: RiskSeverityLabel::Info,
                    confidence: RiskConfidenceLabel::Strong,
                    detector: self.detector_id().to_string(),
                    title: "Localhost health or readiness check".to_string(),
                    plain_reason: "This command fetches a localhost health or readiness endpoint, which is a normal development pattern.".to_string(),
                    technical_detail: Some("matched localhost health endpoint pattern".to_string()),
                    evidence_ref: Some("command".to_string()),
                    redaction_level: RiskRedactionLevel::None,
                    false_positive_hint: None,
                    advisory_id: None,
                });
            }
            if let Some(tool) = classify_read_only_http_fetch(command) {
                signals.push(RiskSignalV2 {
                    signal_id: format!("fp:read-only-http-fetch:{tool}"),
                    category: RiskSignalCategory::FalsePositive,
                    severity: RiskSeverityLabel::Info,
                    confidence: RiskConfidenceLabel::Strong,
                    detector: self.detector_id().to_string(),
                    title: "Read-only HTTP page probe".to_string(),
                    plain_reason: "This command fetches a page and inspects the response locally without uploading data or reading secret files.".to_string(),
                    technical_detail: Some("matched read-only HTTP fetch pattern".to_string()),
                    evidence_ref: Some("command".to_string()),
                    redaction_level: RiskRedactionLevel::None,
                    false_positive_hint: None,
                    advisory_id: None,
                });
            }
        }
        if action.action_type == "file_read" && !action.target_paths.is_empty() {
            if classify_version_file_access(action.target_paths) {
                signals.push(RiskSignalV2 {
                    signal_id: "fp:version-file-access".to_string(),
                    category: RiskSignalCategory::FalsePositive,
                    severity: RiskSeverityLabel::Info,
                    confidence: RiskConfidenceLabel::Strong,
                    detector: self.detector_id().to_string(),
                    title: "Version pin file access".to_string(),
                    plain_reason: "Reading a version pin file (.nvmrc, .python-version, etc.) is a normal toolchain operation with no sensitive data.".to_string(),
                    technical_detail: Some("matched version pin file pattern".to_string()),
                    evidence_ref: Some("target_paths".to_string()),
                    redaction_level: RiskRedactionLevel::None,
                    false_positive_hint: None,
                    advisory_id: None,
                });
            }
            if classify_package_metadata_access(action.target_paths) {
                signals.push(RiskSignalV2 {
                    signal_id: "fp:package-metadata-access".to_string(),
                    category: RiskSignalCategory::FalsePositive,
                    severity: RiskSeverityLabel::Info,
                    confidence: RiskConfidenceLabel::Strong,
                    detector: self.detector_id().to_string(),
                    title: "Package manifest or lock file access".to_string(),
                    plain_reason: "Reading package.json, requirements.txt, or similar manifests is a normal dependency management operation.".to_string(),
                    technical_detail: Some("matched package metadata file pattern".to_string()),
                    evidence_ref: Some("target_paths".to_string()),
                    redaction_level: RiskRedactionLevel::None,
                    false_positive_hint: None,
                    advisory_id: None,
                });
            }
            for path in action.target_paths {
                if classify_docs_example_source(path) {
                    signals.push(RiskSignalV2 {
                        signal_id: format!(
                            "fp:docs-example-source:{}",
                            truncate_chars(path, 40)
                        ),
                        category: RiskSignalCategory::FalsePositive,
                        severity: RiskSeverityLabel::Info,
                        confidence: RiskConfidenceLabel::Strong,
                        detector: self.detector_id().to_string(),
                        title: "Access to docs or example file".to_string(),
                        plain_reason: "The file path points to documentation, examples, or fixture data, which rarely contains real credentials or sensitive content.".to_string(),
                        technical_detail: Some(format!(
                            "matched docs/example path: {path}"
                        )),
                        evidence_ref: Some("target_paths".to_string()),
                        redaction_level: RiskRedactionLevel::None,
                        false_positive_hint: None,
                        advisory_id: None,
                    });
                    break;
                }
            }
        }
        signals
    }
}

/// `PersistenceDetector` (:512-540) — wraps the injected
/// `PersistenceRulesApi`.
pub struct PersistenceDetector<A: PersistenceRulesApi> {
    pub api: A,
}

impl<A: PersistenceRulesApi> GuardDetector for PersistenceDetector<A> {
    fn detector_id(&self) -> &str {
        "persistence.mechanism"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[RiskSignalCategory::Persistence]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        if action.action_type != "shell_command" || action.command.is_none() {
            return Vec::new();
        }
        let matches = self
            .api
            .detect_persistence_mechanisms(action.command.unwrap());
        matches
            .iter()
            .map(|m| RiskSignalV2 {
                signal_id: format!("persistence:{}", m.mechanism),
                category: RiskSignalCategory::Persistence,
                severity: RiskSeverityLabel::High,
                confidence: RiskConfidenceLabel::Likely,
                detector: self.detector_id().to_string(),
                title: format!("Persistence via {}", m.mechanism.replace('_', " ")),
                plain_reason: m.plain_reason.to_string(),
                technical_detail: Some(format!("mechanism: {}", m.mechanism)),
                evidence_ref: Some("command".to_string()),
                redaction_level: RiskRedactionLevel::Summary,
                false_positive_hint: Some(m.false_positive_hint.to_string()),
                advisory_id: None,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// GuardBypassDetector (:542-636) — patterns + struct.
// ---------------------------------------------------------------------------

/// `GuardBypassDetector._UNINSTALL_PATTERN` (:549-558).
static GUARD_UNINSTALL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s;&|])(?:pip(?:3)?\s+uninstall\s+(?:-y\s+)?(?:holguard|hol[_-]guard|codex[_-]plugin[_-]scanner)\b|brew\s+(?:uninstall|remove)\s+hol[_-]guard\b|npm\s+(?:uninstall|remove)\s+(?:-g\s+)?hol[_-]guard\b|apt(?:-get)?\s+(?:remove|purge)\s+hol[_-]guard\b)",
    )
    .expect("GUARD_UNINSTALL_PATTERN")
});

/// `GuardBypassDetector._CONFIG_DESTROY_PATTERN` (:560-565). Python's
/// `(?<![a-zA-Z0-9_])`/`(?![a-zA-Z0-9_])` lookarounds on `guard.db` /
/// `guard.lock` are ASCII word-boundary checks; `\b` in the `regex` crate
/// is equivalent because the Python lookahead restricts the neighbour to
/// exactly `[a-zA-Z0-9_]` (an ASCII word char).
static GUARD_CONFIG_DESTROY_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s;&|])(?:rm|rmdir)\b[^\r\n;&|]{0,100}(?:~?/?\.hol[_-]guard|guard[_-]home|\bguard\.(?:db|lock)\b)",
    )
    .expect("GUARD_CONFIG_DESTROY_PATTERN")
});

/// `GuardBypassDetector._DAEMON_KILL_PATTERN` (:567-573). The `pkill` arm's
/// `(?<![a-zA-Z0-9_])`/`(?![a-zA-Z0-9_])` on `hol_guard` -> `\b` (same
/// ASCII word-char class).
static GUARD_DAEMON_KILL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s;&|])(?:kill\b[^\r\n;&|]{0,80}hol[_-]guard|pkill\b[^\r\n;&|]{0,40}\bhol[_-]guard\b|launchctl\s+(?:unload|disable)\b[^\r\n;&|]{0,80}(?:hol[_-]guard|com\.hol\.guard))",
    )
    .expect("GUARD_DAEMON_KILL_PATTERN")
});

/// `GuardBypassDetector` (:542-636).
pub struct GuardBypassDetector;

impl GuardDetector for GuardBypassDetector {
    fn detector_id(&self) -> &str {
        "bypass.shell"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[RiskSignalCategory::Bypass]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        if !(action.action_type == "shell_command" || action.action_type == "prompt")
            || action.command.is_none()
        {
            return Vec::new();
        }
        let command = action.command.unwrap();
        let mut signals: Vec<RiskSignalV2> = Vec::new();
        if GUARD_UNINSTALL_PATTERN.is_match(command) {
            signals.push(RiskSignalV2 {
                signal_id: "bypass:guard-uninstall".to_string(),
                category: RiskSignalCategory::Bypass,
                severity: RiskSeverityLabel::Critical,
                confidence: RiskConfidenceLabel::Strong,
                detector: self.detector_id().to_string(),
                title: "Command uninstalls HOL Guard".to_string(),
                plain_reason:
                    "This command removes HOL Guard, which would disable all AI harness protection."
                        .to_string(),
                technical_detail: Some("matched guard uninstall pattern".to_string()),
                evidence_ref: Some("command".to_string()),
                redaction_level: RiskRedactionLevel::Summary,
                false_positive_hint: Some(
                    "Allow only if you intentionally want to remove Guard from this machine."
                        .to_string(),
                ),
                advisory_id: None,
            });
        }
        if GUARD_CONFIG_DESTROY_PATTERN.is_match(command) {
            signals.push(RiskSignalV2 {
                signal_id: "bypass:guard-config-destroy".to_string(),
                category: RiskSignalCategory::Bypass,
                severity: RiskSeverityLabel::Critical,
                confidence: RiskConfidenceLabel::Strong,
                detector: self.detector_id().to_string(),
                title: "Command destroys Guard configuration or data".to_string(),
                plain_reason: "This command deletes HOL Guard configuration or state files, which would reset all protection settings and history.".to_string(),
                technical_detail: Some(
                    "matched guard config/data deletion pattern".to_string()
                ),
                evidence_ref: Some("command".to_string()),
                redaction_level: RiskRedactionLevel::Summary,
                false_positive_hint: Some(
                    "Allow only if you intend to fully reset Guard and are aware of data loss."
                        .to_string(),
                ),
                advisory_id: None,
            });
        }
        if GUARD_DAEMON_KILL_PATTERN.is_match(command) {
            signals.push(RiskSignalV2 {
                signal_id: "bypass:guard-daemon-kill".to_string(),
                category: RiskSignalCategory::Bypass,
                severity: RiskSeverityLabel::High,
                confidence: RiskConfidenceLabel::Strong,
                detector: self.detector_id().to_string(),
                title: "Command kills or disables Guard daemon".to_string(),
                plain_reason: "This command stops the Guard background daemon, leaving future AI actions unmonitored.".to_string(),
                technical_detail: Some("matched guard daemon kill/disable pattern".to_string()),
                evidence_ref: Some("command".to_string()),
                redaction_level: RiskRedactionLevel::Summary,
                false_positive_hint: Some(
                    "Allow only if you intentionally need to pause Guard for maintenance."
                        .to_string(),
                ),
                advisory_id: None,
            });
        }
        signals
    }
}

// ---------------------------------------------------------------------------
// MCP detectors (:638-739).
// ---------------------------------------------------------------------------

/// `_MCP_RISKY_TOOL_PATTERN` (:638-643).
static MCP_RISKY_TOOL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:exec(?:ute)?|run|shell|spawn|eval|invoke|dispatch|launch)|(?:write|send|upload|post|exfil|steal|dump|leak).*(?:cred|secret|token|key|password)|(?:arbitrary|remote|unsafe|untruste[d])",
    )
    .expect("MCP_RISKY_TOOL_PATTERN")
});

/// `McpToolSchemaRiskDetector` (:645-686).
pub struct McpToolSchemaRiskDetector;

impl GuardDetector for McpToolSchemaRiskDetector {
    fn detector_id(&self) -> &str {
        "mcp.schema-risk"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[RiskSignalCategory::Mcp]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        if action.action_type != "mcp_tool" || action.mcp_tool.is_none() {
            return Vec::new();
        }
        let tool_name = action.mcp_tool.unwrap();
        if !MCP_RISKY_TOOL_PATTERN.is_match(tool_name) {
            return Vec::new();
        }
        vec![RiskSignalV2 {
            signal_id: format!(
                "mcp:schema-risk:{}",
                truncate_chars(tool_name, 40)
            ),
            category: RiskSignalCategory::Mcp,
            severity: RiskSeverityLabel::High,
            confidence: RiskConfidenceLabel::Likely,
            detector: self.detector_id().to_string(),
            title: "MCP tool name suggests dangerous capability".to_string(),
            plain_reason: format!(
                "The MCP tool '{tool_name}' has a name that suggests it can execute code, run shell commands, or exfiltrate credentials. Review the tool's actual implementation before approving."
            ),
            technical_detail: Some(format!(
                "tool name matched risky-capability pattern: {}",
                py_repr_str(tool_name)
            )),
            evidence_ref: Some("mcp_tool".to_string()),
            redaction_level: RiskRedactionLevel::Summary,
            false_positive_hint: Some(
                "Allow if this tool is from a trusted server and its implementation is audited and does not perform unauthorized actions.".to_string(),
            ),
            advisory_id: None,
        }]
    }
}

/// `_MCP_INJECTION_PATTERNS` (:688-697). The `https?://(?!localhost|127.0.0.1)`
/// lookahead on pattern index 3 is enforced manually in
/// `mcp_injection_match`.
static MCP_INJECTION_PATTERNS: [LazyLock<Regex>; 5] = [
    LazyLock::new(|| {
        Regex::new(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instruction")
            .expect("mcp_injection[0]")
    }),
    LazyLock::new(|| {
        Regex::new(r"(?i)you\s+(?:are\s+now|have\s+no\s+restriction|must\s+obey)")
            .expect("mcp_injection[1]")
    }),
    LazyLock::new(|| {
        Regex::new(
            r"(?i)(?:disregard|forget|override)\s+(?:your\s+)?(?:instruction|system\s+prompt|training)",
        )
        .expect("mcp_injection[2]")
    }),
    LazyLock::new(|| {
        Regex::new(r"(?i)(?:send|post|upload|exfil(?:trate)?)\s+.*\bto\s+https?://")
            .expect("mcp_injection[3]")
    }),
    LazyLock::new(|| {
        Regex::new(
            r"(?i)when\s+you\s+(?:read|access|open|process)\s+.{0,60}(?:also|then|and)\s+(?:send|post|upload)",
        )
        .expect("mcp_injection[4]")
    }),
];

/// Pattern index 3 carries `(?!localhost|127.0.0.1)` after `https?://`;
/// enforce it by rejecting matches whose URL host begins with those literals.
fn mcp_injection_match(pattern_index: usize, text: &str) -> Option<regex::Match<'_>> {
    let pattern = &MCP_INJECTION_PATTERNS[pattern_index];
    let m = pattern.find(text)?;
    if pattern_index == 3 {
        // The lookahead follows the `://` scheme separator; locate the
        // host portion at the end of the match (the regex is greedy but the
        // lookahead is evaluated at the position right after `https?://`).
        // Re-check by scanning for `https?://localhost` / `://127.0.0.1` —
        // if the only match is a localhost URL the lookahead rejects it and
        // Python `search` would try the next candidate position; mirror by
        // walking successive `find` offsets.
        let mut offset = 0;
        while let Some(candidate) = pattern.find_at(text, offset) {
            let span = candidate.as_str();
            // Find the `://` inside the matched span, then the host.
            if let Some(scheme_end) = span.find("://") {
                let host_start = scheme_end + 3;
                let host = &span[host_start..];
                if !(host.starts_with("localhost") || host.starts_with("127.0.0.1")) {
                    return Some(candidate);
                }
            } else {
                return Some(candidate);
            }
            offset = candidate.end();
        }
        return None;
    }
    Some(m)
}

/// `McpDescriptionDeceptionDetector` (:699-739).
pub struct McpDescriptionDeceptionDetector;

impl GuardDetector for McpDescriptionDeceptionDetector {
    fn detector_id(&self) -> &str {
        "mcp.description-deception"
    }
    fn categories(&self) -> &'static [RiskSignalCategory] {
        &[RiskSignalCategory::Prompt]
    }
    fn detect(
        &self,
        action: &DetectorActionView<'_>,
        _context: &DetectorContext<'_>,
    ) -> Vec<RiskSignalV2> {
        if !(action.action_type == "mcp_tool" || action.action_type == "mcp_tool_call")
            || action.prompt_excerpt.is_none()
        {
            return Vec::new();
        }
        let excerpt = action.prompt_excerpt.unwrap();
        let mut signals: Vec<RiskSignalV2> = Vec::new();
        for i in 0..MCP_INJECTION_PATTERNS.len() {
            if let Some(m) = mcp_injection_match(i, excerpt) {
                signals.push(RiskSignalV2 {
                    signal_id: format!("mcp:desc-deception:p{i}"),
                    category: RiskSignalCategory::Prompt,
                    severity: RiskSeverityLabel::Critical,
                    confidence: RiskConfidenceLabel::Strong,
                    detector: self.detector_id().to_string(),
                    title:
                        "MCP description contains prompt injection or jailbreak attempt"
                            .to_string(),
                    plain_reason:
                        "The tool description or prompt contains language designed to override your AI assistant's instructions or cause it to exfiltrate data. This is a common technique used by malicious MCP servers."
                            .to_string(),
                    technical_detail: Some(format!(
                        "matched deception pattern {}: {}",
                        i,
                        py_repr_str(truncate_chars(m.as_str(), 60).as_str())
                    )),
                    evidence_ref: Some("prompt_excerpt".to_string()),
                    redaction_level: RiskRedactionLevel::Summary,
                    false_positive_hint: Some(
                        "Allow only if you authored this tool description yourself and verified it does not cause unintended behavior."
                            .to_string(),
                    ),
                    advisory_id: None,
                });
                break;
            }
        }
        signals
    }
}

// ---------------------------------------------------------------------------
// register_default_detectors (:742-770).
// ---------------------------------------------------------------------------

/// `register_default_detectors` — the default ordered detector list.
///
/// Cisco scanner detectors (from `cisco_preflight.py`, injected via
/// `CiscoPreflightApi`) run first; `FalsePositiveSuppressorDetector` runs
/// early to annotate benign patterns before risk detectors evaluate the
/// same action.
#[allow(clippy::too_many_arguments)]
pub fn register_default_detectors<PI, SK, SC, SD, PE>(
    cisco: &dyn CiscoPreflightApi,
    prompt_injection: PI,
    skill_protection: SK,
    supply_chain: SC,
    safe_decode: SD,
    persistence: PE,
) -> Vec<Box<dyn GuardDetector>>
where
    PI: PromptInjectionApi + 'static,
    SK: SkillProtectionApi + 'static,
    SC: SupplyChainRiskApi + 'static,
    SD: SafeDecodeApi + 'static,
    PE: PersistenceRulesApi + 'static,
{
    vec![
        cisco.cisco_mcp_preflight_detector(),
        cisco.cisco_skill_preflight_detector(),
        Box::new(FalsePositiveSuppressorDetector),
        Box::new(DataFlowExfiltrationDetector),
        Box::new(GuardBypassDetector),
        Box::new(McpDescriptionDeceptionDetector),
        Box::new(McpToolSchemaRiskDetector),
        Box::new(PersistenceDetector { api: persistence }),
        Box::new(PromptInjectionDetector {
            api: prompt_injection,
        }),
        Box::new(SafeDecodeDetector { api: safe_decode }),
        Box::new(SecretPathDetector),
        Box::new(SkillRiskDetector {
            api: skill_protection,
        }),
        Box::new(SupplyChainDetector { api: supply_chain }),
    ]
}

// ---------------------------------------------------------------------------
// Free helper functions (:267-882).
// ---------------------------------------------------------------------------

/// `_safe_decode_signals` (:267-349).
pub fn safe_decode_signals(
    result: &DecodeResultView<'_>,
    detector_id: &str,
    source_text: &str,
    detector_version: &str,
) -> Vec<RiskSignalV2> {
    if result.layers.is_empty() {
        return Vec::new();
    }
    let mut signals: Vec<RiskSignalV2> = Vec::new();
    if !result.eval_signals.is_empty()
        || !result.exec_signals.is_empty()
        || !result.marshal_signals.is_empty()
    {
        let mut detail_parts: Vec<String> = Vec::new();
        if let Some(first) = result.eval_signals.first() {
            detail_parts.push(format!("eval(): {}", py_repr_str(first)));
        }
        if let Some(first) = result.exec_signals.first() {
            detail_parts.push(format!("exec(): {}", py_repr_str(first)));
        }
        if let Some(first) = result.marshal_signals.first() {
            detail_parts.push(format!("marshal.loads(): {}", py_repr_str(first)));
        }
        let layer_names: Vec<&str> = result.layers.iter().map(|l| l.encoding).collect();
        signals.push(RiskSignalV2 {
            signal_id: "encoded.code-execution".to_string(),
            category: RiskSignalCategory::Execution,
            severity: severity_label_from_score(8.0),
            confidence: confidence_label_from_score(0.80),
            detector: detector_id.to_string(),
            title: "Encoded code-execution payload detected".to_string(),
            plain_reason: format!(
                "Decoded {} encoding layer(s) and found code-execution signals: {}",
                result.layers.len(),
                detail_parts[..detail_parts.len().min(2)].join("; ")
            ),
            technical_detail: Some(format!(
                "Detector: {}; Layers: {:?}; eval={} exec={} marshal={}",
                detector_version,
                layer_names,
                result.eval_signals.len(),
                result.exec_signals.len(),
                result.marshal_signals.len()
            )),
            evidence_ref: None,
            redaction_level: RiskRedactionLevel::Summary,
            false_positive_hint: Some(
                "Some build tools legitimately encode setup scripts.".to_string(),
            ),
            advisory_id: None,
        });
    } else {
        // `elif result.layers` is guaranteed by the early return above.
        if looks_like_opaque_decoded_payload(result.final_text) {
            if has_sensitive_decode_context(source_text) {
                signals.push(RiskSignalV2 {
                    signal_id: "encoded.opaque-sensitive".to_string(),
                    category: RiskSignalCategory::Encoded,
                    severity: severity_label_from_score(6.0),
                    confidence: confidence_label_from_score(0.70),
                    detector: detector_id.to_string(),
                    title: "Opaque encoded payload near sensitive context".to_string(),
                    plain_reason: "Guard decoded an opaque or encrypted-looking payload in a command that also references local secret material.".to_string(),
                    technical_detail: Some(format!(
                        "Detector: {}; Layers: {:?}",
                        detector_version,
                        result
                            .layers
                            .iter()
                            .map(|l| l.encoding)
                            .collect::<Vec<_>>()
                    )),
                    evidence_ref: None,
                    redaction_level: RiskRedactionLevel::Summary,
                    false_positive_hint: Some(
                        "Encrypted test fixtures are usually safe when no secret file or token is in scope.".to_string(),
                    ),
                    advisory_id: None,
                });
            }
            return signals;
        }
        signals.push(RiskSignalV2 {
            signal_id: "encoded.obfuscated-content".to_string(),
            category: RiskSignalCategory::Execution,
            severity: severity_label_from_score(5.0),
            confidence: confidence_label_from_score(0.60),
            detector: detector_id.to_string(),
            title: "Multi-layer encoded content detected".to_string(),
            plain_reason: format!(
                "Content decoded through {} encoding layer(s) ({}). Obfuscated content may conceal malicious instructions.",
                result.layers.len(),
                result
                    .layers
                    .iter()
                    .map(|l| l.encoding)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            technical_detail: Some(format!("Detector: {detector_version}")),
            evidence_ref: None,
            redaction_level: RiskRedactionLevel::Summary,
            false_positive_hint: Some(
                "Encoded documentation or binary assets are common false positives.".to_string(),
            ),
            advisory_id: None,
        });
    }
    signals
}

/// `_looks_like_opaque_decoded_payload` (:350-359).
pub fn looks_like_opaque_decoded_payload(text: &str) -> bool {
    if text.len() < 32 {
        return false;
    }
    let replacement_count = text.matches('\u{fffd}').count() as f64;
    let replacement_ratio = replacement_count / (text.len().max(1) as f64);
    if replacement_ratio >= 0.10 {
        return true;
    }
    let printable_count = text
        .chars()
        .filter(|c| python_isprintable(*c) || c.is_whitespace())
        .count();
    (printable_count as f64) / (text.len().max(1) as f64) < 0.75
}

/// `_has_sensitive_decode_context` (:360-362). The Python pattern uses
/// lookarounds; the `regex` crate equivalent matches the core token and the
/// boundary guards are enforced by `sensitive_context_hit`.
pub fn has_sensitive_decode_context(text: &str) -> bool {
    for m in SENSITIVE_DECODE_CONTEXT_PATTERN.find_iter(text) {
        if sensitive_context_hit(text, m.start(), m.end()) {
            return true;
        }
    }
    false
}

/// Apply the Python lookarounds for each alternative of
/// `_SENSITIVE_DECODE_CONTEXT_PATTERN` to a candidate match span.
fn sensitive_context_hit(text: &str, start: usize, end: usize) -> bool {
    let token = text[start..end].to_lowercase();
    let bytes = text.as_bytes();
    // `(?<![A-Za-z0-9])` on the `credentials?|secrets?|tokens?|passwords?`
    // arm.
    let is_unanchored_word = matches!(
        token.as_str(),
        "credential"
            | "credentials"
            | "secret"
            | "secrets"
            | "token"
            | "tokens"
            | "password"
            | "passwords"
    );
    if is_unanchored_word && start > 0 {
        let prev = bytes[start - 1] as char;
        if prev.is_ascii_alphanumeric() {
            return false;
        }
    }
    // Forward lookahead varies by alternative:
    //   - `.env*` / `.npmrc` / `.pem` / `.key` -> `(?![A-Za-z0-9_-])`
    //   - `id_*` -> `(?![A-Za-z0-9]|\.pub\b)` (`.pub` suffix allowed)
    //   - `api_key` / `private_key` / `aws_*` / word-arm -> `(?![A-Za-z0-9])`
    if token.starts_with("id_") {
        return sensitive_context_boundary_ok(text, start, end, false, true);
    }
    let forbid_dash_underscore =
        token.starts_with(".env") || token == ".npmrc" || token == ".pem" || token == ".key";
    sensitive_context_boundary_ok(text, start, end, forbid_dash_underscore, false)
}

/// `_prompt_request_signal` (:771-788).
pub fn prompt_request_signal(request: &PromptRequestView<'_>) -> RiskSignalV2 {
    let category = prompt_request_category(request);
    RiskSignalV2 {
        signal_id: format!(
            "prompt-injection:{}:{}",
            request.request_class,
            truncate_chars(request.request_id, 16)
        ),
        category,
        severity: severity_label(request.severity),
        confidence: confidence_label(request.confidence),
        detector: "prompt.injection".to_string(),
        title: prompt_request_title(request.request_class),
        plain_reason: request.summary.to_string(),
        technical_detail: Some(format!(
            "matched prompt request class: {}",
            request.request_class
        )),
        evidence_ref: Some("prompt_excerpt".to_string()),
        redaction_level: RiskRedactionLevel::Summary,
        false_positive_hint: prompt_request_false_positive_hint(request),
        advisory_id: None,
    }
}

/// `_prompt_request_category` (:789-799).
pub fn prompt_request_category(request: &PromptRequestView<'_>) -> RiskSignalCategory {
    match request.request_class {
        "secret_read" => RiskSignalCategory::Secret,
        "exfil_intent" => RiskSignalCategory::Network,
        "destructive_intent" => RiskSignalCategory::Filesystem,
        "subprocess_intent" => RiskSignalCategory::Execution,
        "guard_bypass_intent" => RiskSignalCategory::Bypass,
        _ => RiskSignalCategory::Prompt,
    }
}

/// `_severity_label` (:800-803).
pub fn severity_label(score: i64) -> RiskSeverityLabel {
    severity_label_from_score(score as f64)
}

/// `_confidence_label` (:804-807).
pub fn confidence_label(score: f64) -> RiskConfidenceLabel {
    confidence_label_from_score(score)
}

/// `_prompt_request_title` (:808-818).
pub fn prompt_request_title(request_class: &str) -> String {
    match request_class {
        "secret_read" => "Prompt requests local secret access".to_string(),
        "exfil_intent" => "Prompt requests data exfiltration".to_string(),
        "destructive_intent" => "Prompt requests destructive action".to_string(),
        "subprocess_intent" => "Prompt requests subprocess execution".to_string(),
        "guard_bypass_intent" => "Prompt requests Guard bypass".to_string(),
        "prompt_injection_intent" => "Prompt includes injection intent".to_string(),
        _ => "Prompt request needs review".to_string(),
    }
}

/// `_prompt_request_false_positive_hint` (:819-825).
///
/// The Python iterates `request.remediation` and returns the first
/// non-blank `remediation.detail`; `remediation_details` is already the
/// `Option<detail>`-filtered list from `PromptRequestView`.
pub fn prompt_request_false_positive_hint(request: &PromptRequestView<'_>) -> Option<String> {
    request
        .remediation_details
        .iter()
        .find(|d| !d.trim().is_empty())
        .cloned()
}

/// `_secret_path_signal` (:826-842).
pub(crate) fn secret_path_signal(match_: &SecretPathMatch, index: usize) -> RiskSignalV2 {
    RiskSignalV2 {
        signal_id: format!("secret:path:{}:{}", slug(&match_.family), index),
        category: RiskSignalCategory::Secret,
        severity: RiskSeverityLabel::High,
        confidence: RiskConfidenceLabel::Strong,
        detector: "secret.path".to_string(),
        title: format!("Direct access to {}", match_.family),
        plain_reason: format!("Requested direct access to {}.", match_.family),
        technical_detail: Some(format!("matched secret path family: {}", match_.family)),
        evidence_ref: Some("target_paths".to_string()),
        redaction_level: RiskRedactionLevel::Summary,
        false_positive_hint: Some(
            "Allow only if this tool needs the exact local secret file for the current task."
                .to_string(),
        ),
        advisory_id: None,
    }
}

/// `_secret_path_matches` (:843-851).
pub(crate) fn secret_path_matches(
    paths: &[String],
    workspace: Option<&Path>,
) -> Vec<SecretPathMatch> {
    let mut matches: Vec<SecretPathMatch> = Vec::new();
    for path in paths {
        if let Some(m) = classify_secret_path(path, workspace, None) {
            matches.push(m);
        }
    }
    matches
}

/// `_elapsed_ms` (:852-855) — `max(0, round((finished - started) * 1000))`.
pub fn elapsed_ms(started_at: Instant, finished_at: Instant) -> i64 {
    let delta = finished_at.saturating_duration_since(started_at);
    (delta.as_secs_f64() * 1000.0).round().max(0.0) as i64
}

/// `_filter_signals` (:856-864).
pub fn filter_signals(
    signals: &[RiskSignalV2],
    category_filter: Option<&std::collections::HashSet<RiskSignalCategory>>,
) -> Vec<RiskSignalV2> {
    match category_filter {
        None => signals.to_vec(),
        Some(filter) => signals
            .iter()
            .filter(|s| filter.contains(&s.category))
            .cloned()
            .collect(),
    }
}

/// `_slug` (:865-868).
pub fn slug(value: &str) -> String {
    value
        .to_lowercase()
        .replace(['.', '/'], " ")
        .split_whitespace()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// `_telemetry` (:869-882).
fn telemetry_entry(
    detector: &dyn GuardDetector,
    status: DetectorRunStatus,
    elapsed_ms: i64,
    error_type: Option<String>,
) -> DetectorTelemetry {
    DetectorTelemetry {
        detector_id: detector.detector_id().to_string(),
        categories: detector.categories().to_vec(),
        status,
        elapsed_ms,
        error_type,
    }
}

// ---------------------------------------------------------------------------
// Python-compatible helpers (not in the source file; supporting shims).
// ---------------------------------------------------------------------------

/// `text[:n]` — Python char-based prefix truncation (the Python source uses
/// `[:40]` / `[:16]` / `[:60]` on `str`, which slices code points).
fn truncate_chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// Python `repr(str)` — single-quoted with backslash escapes, matching
/// `!r`/`repr()` in `technical_detail` strings.
fn py_repr_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

/// Python `str.isprintable()` — not in a "Other" (C*) or "Separator"
/// category except ASCII space. Approximated conservatively: ASCII
/// printable + common letters/digits/punctuation; control, format,
/// surrogate, private-use, and unassigned code points are non-printable.
/// The crate's `command_option_unicode` tables only cover alnum/whitespace,
/// so this uses `char` properties as the closest available proxy: a char is
/// printable iff it is not a control char and not in a separator/format
/// range. This is a heuristic — kept local to avoid widening the shared
/// unicode tables.
fn python_isprintable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() {
        return false;
    }
    // Zs (space separators other than ASCII space), Zl, Zp are non-printable.
    // Cf (format) chars are non-printable. Rust's `char::is_whitespace`
    // covers Zs/Zl/Zp; treat remaining whitespace as non-printable unless
    // it's the ASCII space already handled.
    if c.is_whitespace() {
        return false;
    }
    // Cf format characters: common invisible format controls.
    if matches!(c,
        '\u{00ad}' | '\u{0600}'..='\u{0605}' | '\u{061c}' | '\u{06dd}' | '\u{070f}'
        | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}' | '\u{feff}'
        | '\u{fff9}'..='\u{fffb}'
    ) {
        return false;
    }
    // Surrogates and noncharacters.
    if ('\u{fdd0}'..='\u{fdef}').contains(&c) || (u32::from(c) & 0xfffe) == 0xfffe {
        return false;
    }
    // Private use.
    if ('\u{e000}'..='\u{f8ff}').contains(&c)
        || ('\u{f0000}'..='\u{ffffd}').contains(&c)
        || ('\u{100000}'..='\u{10fffd}').contains(&c)
    {
        return false;
    }
    true
}
