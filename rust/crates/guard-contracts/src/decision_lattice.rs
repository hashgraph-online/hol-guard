//! Canonical Guard action lattice + signal composition rules.
//!
//! Port of `action_lattice.py` and `runtime/composition_rules.py`:
//!   * `GuardAction` — the six-value canonical action lattice with severity
//!     ranks 0..=5 (allow < warn < review < require-reapproval <
//!     sandbox-required < block).
//!   * `normalize_guard_action*` — conservative normalization: known action
//!     passes through, `"ask"` aliases to `"review"`, anything else falls back
//!     to `unknown_action` (default `"review"`, callers may use `"block"`)
//!     while retaining `guard_action_unknown` diagnostics.
//!   * `guard_action_severity` / `most_restrictive_guard_action` — total-order
//!     composition over normalized actions.
//!   * `is_action_bearing_key` — camelCase/separator tokenization so
//!     `finalAction` and `observed_policy_action` are recognized while
//!     `redaction` is not.
//!   * `compose_action_from_signals` — false-positive/risk calibration:
//!     upgrades on likely+ bypass / high+critical persistence / likely+
//!     critical signals; downgrades `block`->`review` or `review`->`warn` on
//!     strong false-positive evidence with only low-severity, non-protected
//!     risk; never lowers an explicit require-reapproval/sandbox-required.
//!
//! Byte-parity: severity ranks, alias, reason strings, and the upgrade /
//! downgrade decision branches match the Python source line-for-line.

use serde_json::Value;

use crate::signal_contract::{
    RiskConfidenceLabel, RiskSeverityLabel, RiskSignalCategory, RiskSignalV2,
};

// ---------------------------------------------------------------------------
// GuardAction lattice
// ---------------------------------------------------------------------------

pub const UNKNOWN_GUARD_ACTION_REASON: &str = "guard_action_unknown";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GuardAction {
    Allow,
    Warn,
    Review,
    RequireReapproval,
    SandboxRequired,
    Block,
}

impl GuardAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Review => "review",
            Self::RequireReapproval => "require-reapproval",
            Self::SandboxRequired => "sandbox-required",
            Self::Block => "block",
        }
    }

    /// Canonical severity rank (matches `GUARD_ACTION_SEVERITY`, contiguous).
    pub const fn severity(self) -> i32 {
        match self {
            Self::Allow => 0,
            Self::Warn => 1,
            Self::Review => 2,
            Self::RequireReapproval => 3,
            Self::SandboxRequired => 4,
            Self::Block => 5,
        }
    }

    /// The canonical lattice order (severity rank ascending).
    pub const LATTICE: [GuardAction; 6] = [
        GuardAction::Allow,
        GuardAction::Warn,
        GuardAction::Review,
        GuardAction::RequireReapproval,
        GuardAction::SandboxRequired,
        GuardAction::Block,
    ];

    /// `is_guard_action` — exact canonical-name membership (no alias).
    pub fn from_canonical(s: &str) -> Option<Self> {
        Some(match s {
            "allow" => Self::Allow,
            "warn" => Self::Warn,
            "review" => Self::Review,
            "require-reapproval" => Self::RequireReapproval,
            "sandbox-required" => Self::SandboxRequired,
            "block" => Self::Block,
            _ => return None,
        })
    }
}

pub const DEFAULT_UNKNOWN_GUARD_ACTION: GuardAction = GuardAction::Review;

/// `is_guard_action` — is this value covered by the canonical lattice?
pub fn is_guard_action(value: &Value) -> bool {
    matches!(value, Value::String(s) if GuardAction::from_canonical(s).is_some())
}

/// Normalized action plus stable, non-coercive diagnostics.
#[derive(Debug, Clone)]
pub struct GuardActionNormalization {
    pub action: GuardAction,
    /// `None` when the input was recognized; `guard_action_unknown` otherwise.
    pub reason_code: Option<&'static str>,
    /// The original string when the input was a string (else `None`).
    pub original_action: Option<String>,
    /// Python `type(value).__name__` analogue for diagnostics.
    pub original_type: &'static str,
}

impl GuardActionNormalization {
    /// `.recognized` — `reason_code is None`.
    pub const fn recognized(&self) -> bool {
        self.reason_code.is_none()
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(_) => "float", // python int/float both classify as numeric
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `normalize_guard_action_result` — normalize an untyped value, keeping
/// non-coercive diagnostics. `ask` aliases to `review`; unknown -> fallback.
pub fn normalize_guard_action_result(
    value: &Value,
    unknown_action: GuardAction,
) -> GuardActionNormalization {
    if let Value::String(s) = value {
        if let Some(action) = GuardAction::from_canonical(s) {
            return GuardActionNormalization {
                action,
                reason_code: None,
                original_action: Some(s.clone()),
                original_type: "str",
            };
        }
        if s == "ask" {
            // LEGACY_GUARD_ACTION_ALIASES = {"ask": "review"}
            return GuardActionNormalization {
                action: GuardAction::Review,
                reason_code: None,
                original_action: Some(s.clone()),
                original_type: "str",
            };
        }
    }
    GuardActionNormalization {
        action: unknown_action,
        reason_code: Some(UNKNOWN_GUARD_ACTION_REASON),
        original_action: value.as_str().map(str::to_string),
        original_type: json_type_name(value),
    }
}

/// `normalize_guard_action` — conservative fallback for untyped inputs.
pub fn normalize_guard_action(value: &Value, unknown_action: GuardAction) -> GuardAction {
    normalize_guard_action_result(value, unknown_action).action
}

/// `guard_action_severity` — canonical rank; unknown inputs get fallback rank.
pub fn guard_action_severity(value: &Value, unknown_action: GuardAction) -> i32 {
    normalize_guard_action(value, unknown_action).severity()
}

/// `most_restrictive_guard_action` — total-order composition; the highest
/// severity rank wins. With no candidates, the normalized `None` (=> fallback)
/// is returned.
pub fn most_restrictive_guard_action(
    actions: &[Value],
    unknown_action: GuardAction,
) -> GuardAction {
    if actions.is_empty() {
        return normalize_guard_action(&Value::Null, unknown_action);
    }
    let normalized: Vec<GuardAction> = actions
        .iter()
        .map(|a| normalize_guard_action(a, unknown_action))
        .collect();
    let mut winner = normalized[0];
    for &cand in &normalized[1..] {
        if cand.severity() > winner.severity() {
            winner = cand;
        }
    }
    winner
}

/// Convenience: compose already-typed actions (used by composition rules).
pub fn most_restrictive_of(a: GuardAction, b: GuardAction) -> GuardAction {
    if b.severity() > a.severity() {
        b
    } else {
        a
    }
}

// ---------------------------------------------------------------------------
// is_action_bearing_key
// ---------------------------------------------------------------------------

/// `_SEMANTIC_ACTION_FIELD_ALIASES` — compact (separators+case stripped) names.
const SEMANTIC_ACTION_FIELD_ALIASES: [&str; 1] = ["preexecutionresult"];

/// `is_action_bearing_key` — true when a field name can carry an alternate
/// action authority. CamelCase/separator-delimited names are tokenized so
/// `finalAction` and `observed_policy_action` are recognized while `redaction`
/// is not mistaken for the standalone `action` token.
pub fn is_action_bearing_key(key: &str) -> bool {
    // re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key): insert space at camel bump.
    let mut separated = String::with_capacity(key.len() + 8);
    let bytes = key.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            let prev = bytes[i - 1];
            let lower_or_digit = prev.is_ascii_lowercase() || prev.is_ascii_digit();
            if lower_or_digit && b.is_ascii_uppercase() {
                separated.push(' ');
            }
        }
        separated.push(b as char);
    }
    // tokens = [t for t in re.sub(r"[^A-Za-z0-9]+"," ",separated).lower().split() if t]
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in separated.chars() {
        if c.is_ascii_alphanumeric() {
            cur.push(c.to_ascii_lowercase());
        } else if !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    let compact: String = tokens.concat();
    SEMANTIC_ACTION_FIELD_ALIASES.contains(&compact.as_str())
        || tokens.iter().any(|t| t == "action" || t == "actions")
}

// ---------------------------------------------------------------------------
// compose_action_from_signals
// ---------------------------------------------------------------------------

/// `_DOWNGRADE_BLOCK_CATEGORIES` — risk categories that veto a downgrade.
fn is_downgrade_block_category(c: RiskSignalCategory) -> bool {
    matches!(
        c,
        RiskSignalCategory::Bypass | RiskSignalCategory::Persistence
    )
}

/// `_DOWNGRADE_PROTECTED_SEVERITIES` — retained for parity; not used by the
/// current branch structure but kept so the constants table is complete.
fn _is_protected_severity(s: RiskSeverityLabel) -> bool {
    matches!(s, RiskSeverityLabel::Critical | RiskSeverityLabel::High)
}

/// `_FP_DOWNGRADE_MAX_SEVERITY` — risk severities compatible with a downgrade.
fn is_fp_downgrade_max_severity(s: RiskSeverityLabel) -> bool {
    matches!(s, RiskSeverityLabel::Info | RiskSeverityLabel::Low)
}

/// `SEVERITY_RANK` — rank used to pick the top risk signal for the reason.
fn severity_rank(s: RiskSeverityLabel) -> i32 {
    match s {
        RiskSeverityLabel::Info => 0,
        RiskSeverityLabel::Low => 1,
        RiskSeverityLabel::Medium => 2,
        RiskSeverityLabel::High => 3,
        RiskSeverityLabel::Critical => 4,
    }
}

/// `CompositionResult` — final calibrated action + explanation + flags.
#[derive(Debug, Clone)]
pub struct CompositionResult {
    pub action: GuardAction,
    pub reason: String,
    pub downgraded: bool,
    pub upgraded: bool,
    pub normalization_reason_code: Option<&'static str>,
    pub original_action: Option<String>,
}

/// `compose_action_from_signals` — apply false-positive / risk calibration to
/// the base policy action. Mirrors the Python branch structure exactly:
/// upgrades first (bypass / persistence / critical), then the downgrade gate
/// (only when no upgrade fired AND the base action was recognized), then the
/// reason ladder.
pub fn compose_action_from_signals(
    signals: &[RiskSignalV2],
    base_action: &Value,
) -> CompositionResult {
    // Python: normalize_guard_action_result(base_action, unknown_action="block")
    let base_norm = normalize_guard_action_result(base_action, GuardAction::Block);
    let normalized_base = base_norm.action;
    let risk: Vec<&RiskSignalV2> = signals
        .iter()
        .filter(|s| s.category != RiskSignalCategory::FalsePositive)
        .collect();
    let fp: Vec<&RiskSignalV2> = signals
        .iter()
        .filter(|s| s.category == RiskSignalCategory::FalsePositive)
        .collect();

    if signals.is_empty() {
        return CompositionResult {
            action: normalized_base,
            reason: "no detector signals; base policy action applies".into(),
            downgraded: false,
            upgraded: false,
            normalization_reason_code: base_norm.reason_code,
            original_action: base_norm.original_action,
        };
    }

    let mut current = normalized_base;
    let mut upgrade_reason: Option<String> = None;
    let mut downgrade_reason: Option<String> = None;

    for signal in &risk {
        if signal.category == RiskSignalCategory::Bypass
            && matches!(
                signal.confidence,
                RiskConfidenceLabel::Likely | RiskConfidenceLabel::Strong
            )
        {
            let upgraded = most_restrictive_of(current, GuardAction::Block);
            if upgraded.severity() > current.severity() {
                upgrade_reason = Some(format!("bypass signal '{}' forces block", signal.detector));
                current = upgraded;
            }
        }
        if signal.category == RiskSignalCategory::Persistence
            && matches!(
                signal.severity,
                RiskSeverityLabel::High | RiskSeverityLabel::Critical
            )
        {
            let upgraded = most_restrictive_of(current, GuardAction::Review);
            if upgraded.severity() > current.severity() {
                if upgrade_reason.is_none() {
                    upgrade_reason = Some(format!(
                        "persistence signal '{}' requires review",
                        signal.detector
                    ));
                }
                current = upgraded;
            }
        }
        if signal.severity == RiskSeverityLabel::Critical
            && matches!(
                signal.confidence,
                RiskConfidenceLabel::Likely | RiskConfidenceLabel::Strong
            )
        {
            let upgraded = most_restrictive_of(current, GuardAction::Block);
            if upgraded.severity() > current.severity() {
                if upgrade_reason.is_none() {
                    upgrade_reason = Some(format!(
                        "critical signal '{}' forces block",
                        signal.detector
                    ));
                }
                current = upgraded;
            }
        }
    }

    let mut final_action = current;

    if !fp.is_empty() && upgrade_reason.is_none() && base_norm.recognized() {
        let all_fp_strong = fp
            .iter()
            .all(|s| s.confidence == RiskConfidenceLabel::Strong);
        let only_low_risk = risk
            .iter()
            .all(|s| is_fp_downgrade_max_severity(s.severity));
        let no_protected_cats = !risk.iter().any(|s| is_downgrade_block_category(s.category));

        if all_fp_strong
            && only_low_risk
            && no_protected_cats
            && normalized_base == GuardAction::Block
        {
            final_action = GuardAction::Review;
            downgrade_reason = Some(
                "strong false-positive signals with only low-severity risk; downgraded block \u{2192} review"
                    .into(),
            );
        } else if all_fp_strong
            && only_low_risk
            && no_protected_cats
            && normalized_base == GuardAction::Review
        {
            let review_noise_fp_present = fp.iter().any(|s| {
                s.signal_id.starts_with("fp:source-search:")
                    || s.signal_id.starts_with("fp:read-only-http-fetch:")
            });
            if review_noise_fp_present && risk.is_empty() {
                final_action = GuardAction::Warn;
                downgrade_reason = Some(
                    "strong read-only false-positive with no risk signals; downgraded review \u{2192} warn"
                        .into(),
                );
            }
        }
    }

    if let Some(reason) = upgrade_reason {
        return CompositionResult {
            action: final_action,
            reason,
            downgraded: false,
            upgraded: final_action.severity() > normalized_base.severity(),
            normalization_reason_code: base_norm.reason_code,
            original_action: base_norm.original_action,
        };
    }

    if let Some(reason) = downgrade_reason {
        return CompositionResult {
            action: final_action,
            reason,
            downgraded: true,
            upgraded: false,
            normalization_reason_code: base_norm.reason_code,
            original_action: base_norm.original_action,
        };
    }

    if !risk.is_empty() {
        let top = risk
            .iter()
            .max_by_key(|s| severity_rank(s.severity))
            .copied()
            .unwrap();
        return CompositionResult {
            action: final_action,
            reason: format!(
                "risk signal '{}' ({}/{}); base action applies",
                top.detector,
                top.severity.as_str(),
                top.confidence.as_str()
            ),
            downgraded: false,
            upgraded: false,
            normalization_reason_code: base_norm.reason_code,
            original_action: base_norm.original_action,
        };
    }

    CompositionResult {
        action: final_action,
        reason: "advisory false-positive signals only; base action applies".into(),
        downgraded: false,
        upgraded: false,
        normalization_reason_code: base_norm.reason_code,
        original_action: base_norm.original_action,
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn risk_signal(
        cat: RiskSignalCategory,
        sev: RiskSeverityLabel,
        conf: RiskConfidenceLabel,
        det: &str,
        id: &str,
    ) -> RiskSignalV2 {
        RiskSignalV2 {
            signal_id: id.into(),
            category: cat,
            severity: sev,
            confidence: conf,
            detector: det.into(),
            title: "t".into(),
            plain_reason: "r".into(),
            technical_detail: None,
            evidence_ref: None,
            redaction_level: crate::signal_contract::RiskRedactionLevel::Summary,
            false_positive_hint: None,
            advisory_id: None,
        }
    }

    #[test]
    fn lattice_severity_contiguous_and_ordered() {
        for (i, a) in GuardAction::LATTICE.iter().enumerate() {
            assert_eq!(a.severity(), i as i32);
        }
        assert_eq!(GuardAction::Allow.severity(), 0);
        assert_eq!(GuardAction::Block.severity(), 5);
    }

    #[test]
    fn normalize_recognizes_alias_and_falls_back() {
        // known
        let n = normalize_guard_action_result(&json!("warn"), GuardAction::Review);
        assert_eq!(n.action, GuardAction::Warn);
        assert!(n.recognized());
        assert_eq!(n.original_action.as_deref(), Some("warn"));
        // alias ask -> review
        let a = normalize_guard_action_result(&json!("ask"), GuardAction::Review);
        assert_eq!(a.action, GuardAction::Review);
        assert!(a.recognized());
        // unknown string -> fallback + reason
        let u = normalize_guard_action_result(&json!("bogus"), GuardAction::Block);
        assert_eq!(u.action, GuardAction::Block);
        assert_eq!(u.reason_code, Some("guard_action_unknown"));
        assert_eq!(u.original_action.as_deref(), Some("bogus"));
        // non-string -> fallback, original_action None
        let x = normalize_guard_action_result(&json!(5), GuardAction::Review);
        assert_eq!(x.action, GuardAction::Review);
        assert_eq!(x.reason_code, Some("guard_action_unknown"));
        assert_eq!(x.original_action, None);
        assert_eq!(x.original_type, "float");
    }

    #[test]
    fn most_restrictive_picks_highest() {
        let winner = most_restrictive_guard_action(
            &[json!("allow"), json!("review"), json!("warn")],
            GuardAction::Block,
        );
        assert_eq!(winner, GuardAction::Review);
        // empty -> normalized None -> fallback
        assert_eq!(
            most_restrictive_guard_action(&[], GuardAction::Block),
            GuardAction::Block
        );
        // unknown input normalized to fallback participates
        let w =
            most_restrictive_guard_action(&[json!("allow"), json!("bogus")], GuardAction::Review);
        assert_eq!(w, GuardAction::Review);
    }

    #[test]
    fn is_action_bearing_key_tokenizes() {
        assert!(is_action_bearing_key("finalAction"));
        assert!(is_action_bearing_key("observed_policy_action"));
        assert!(is_action_bearing_key("action"));
        assert!(is_action_bearing_key("policyAction")); // camel bump -> "policy action"
        assert!(is_action_bearing_key("preExecutionResult")); // semantic alias
        assert!(is_action_bearing_key("action_envelope_json"));
        assert!(!is_action_bearing_key("redaction")); // "redaction" -> no standalone token
        assert!(!is_action_bearing_key("reaction")); // contains 'action' but not token
        assert!(!is_action_bearing_key("user_title"));
        assert!(is_action_bearing_key("transActionName")); // tokens: trans action name -> has "action"
    }

    #[test]
    fn compose_no_signals_uses_base() {
        let r = compose_action_from_signals(&[], &json!("review"));
        assert_eq!(r.action, GuardAction::Review);
        assert_eq!(r.reason, "no detector signals; base policy action applies");
    }

    #[test]
    fn compose_bypass_upgrades_to_block() {
        let sigs = vec![risk_signal(
            RiskSignalCategory::Bypass,
            RiskSeverityLabel::Low,
            RiskConfidenceLabel::Likely,
            "det-bypass",
            "sig-bypass",
        )];
        let r = compose_action_from_signals(&sigs, &json!("allow"));
        assert_eq!(r.action, GuardAction::Block);
        assert!(r.upgraded);
        assert_eq!(r.reason, "bypass signal 'det-bypass' forces block");
    }

    #[test]
    fn compose_critical_likely_upgrades_to_block() {
        let sigs = vec![risk_signal(
            RiskSignalCategory::Secret,
            RiskSeverityLabel::Critical,
            RiskConfidenceLabel::Strong,
            "det-crit",
            "sig-crit",
        )];
        let r = compose_action_from_signals(&sigs, &json!("warn"));
        assert_eq!(r.action, GuardAction::Block);
        assert!(r.upgraded);
        assert_eq!(r.reason, "critical signal 'det-crit' forces block");
    }

    #[test]
    fn compose_persistence_high_upgrades_to_review() {
        let sigs = vec![risk_signal(
            RiskSignalCategory::Persistence,
            RiskSeverityLabel::High,
            RiskConfidenceLabel::Weak,
            "det-pers",
            "sig-pers",
        )];
        let r = compose_action_from_signals(&sigs, &json!("allow"));
        assert_eq!(r.action, GuardAction::Review);
        assert!(r.upgraded);
        assert_eq!(r.reason, "persistence signal 'det-pers' requires review");
    }

    #[test]
    fn compose_strong_fp_low_risk_downgrades_block_to_review() {
        let sigs = vec![
            risk_signal(
                RiskSignalCategory::FalsePositive,
                RiskSeverityLabel::Info,
                RiskConfidenceLabel::Strong,
                "det-fp",
                "fp:source-search:x",
            ),
            risk_signal(
                RiskSignalCategory::Filesystem,
                RiskSeverityLabel::Low,
                RiskConfidenceLabel::Likely,
                "det-fs",
                "sig-fs",
            ),
        ];
        let r = compose_action_from_signals(&sigs, &json!("block"));
        assert_eq!(r.action, GuardAction::Review);
        assert!(r.downgraded);
        assert_eq!(r.reason, "strong false-positive signals with only low-severity risk; downgraded block \u{2192} review");
    }

    #[test]
    fn compose_strong_readonly_fp_no_risk_downgrades_review_to_warn() {
        let sigs = vec![risk_signal(
            RiskSignalCategory::FalsePositive,
            RiskSeverityLabel::Info,
            RiskConfidenceLabel::Strong,
            "det-fp",
            "fp:read-only-http-fetch:x",
        )];
        let r = compose_action_from_signals(&sigs, &json!("review"));
        assert_eq!(r.action, GuardAction::Warn);
        assert!(r.downgraded);
        assert_eq!(
            r.reason,
            "strong read-only false-positive with no risk signals; downgraded review \u{2192} warn"
        );
    }

    #[test]
    fn compose_does_not_downgrade_when_bypass_present() {
        // bypass category is a protected category -> no downgrade even w/ strong fp + low sev
        let sigs = vec![
            risk_signal(
                RiskSignalCategory::FalsePositive,
                RiskSeverityLabel::Info,
                RiskConfidenceLabel::Strong,
                "det-fp",
                "fp:x",
            ),
            risk_signal(
                RiskSignalCategory::Bypass,
                RiskSeverityLabel::Low,
                RiskConfidenceLabel::Weak,
                "det-b",
                "sig-b",
            ),
        ];
        // bypass weak confidence does NOT upgrade (needs likely+)
        let r = compose_action_from_signals(&sigs, &json!("block"));
        assert_eq!(r.action, GuardAction::Block); // no upgrade, no downgrade (protected cat)
        assert!(!r.upgraded && !r.downgraded);
    }

    #[test]
    fn compose_never_downgrades_unrecognized_base() {
        // base unrecognized -> fallback to "block" but recognized=false -> no downgrade
        let sigs = vec![risk_signal(
            RiskSignalCategory::FalsePositive,
            RiskSeverityLabel::Info,
            RiskConfidenceLabel::Strong,
            "det-fp",
            "fp:x",
        )];
        let r = compose_action_from_signals(&sigs, &json!("bogus"));
        assert_eq!(r.action, GuardAction::Block); // fallback block
        assert_eq!(r.normalization_reason_code, Some("guard_action_unknown"));
        assert!(!r.downgraded); // recognized gate blocks downgrade
        assert_eq!(
            r.reason,
            "advisory false-positive signals only; base action applies"
        );
    }

    #[test]
    fn compose_plain_risk_reports_top_signal_reason() {
        let sigs = vec![
            risk_signal(
                RiskSignalCategory::Network,
                RiskSeverityLabel::Medium,
                RiskConfidenceLabel::Likely,
                "det-net",
                "sig-net",
            ),
            risk_signal(
                RiskSignalCategory::Filesystem,
                RiskSeverityLabel::High,
                RiskConfidenceLabel::Weak,
                "det-fs",
                "sig-fs",
            ),
        ];
        let r = compose_action_from_signals(&sigs, &json!("warn"));
        assert_eq!(r.action, GuardAction::Warn);
        // top = highest severity (high/fs) -> reason names it
        assert_eq!(
            r.reason,
            "risk signal 'det-fs' (high/weak); base action applies"
        );
        assert!(!r.upgraded && !r.downgraded);
    }
}
