//! Plans the Cisco preflight: which containment verdicts the action already
//! earned and which scans the caller may run, in the order they must run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use guard_command::local_supply_chain::stable_digest_hex_len;
use guard_contracts::{
    CiscoPlanQueryV1, CiscoStepV1, GuardRiskSignalV3, RiskConfidenceLabel, RiskRedactionLevel,
    RiskSeverityLabel, RiskSignalCategory, RiskSignalSource, ScannerStatusLabel,
};

use crate::cisco_containment::{self as contain, ApprovedRoot, Contain, Validated};

const OUTSIDE: &str = "outside_approved_workspace";

pub(crate) fn containment_signal(kind: &str, error: &Contain) -> GuardRiskSignalV3 {
    let material = format!("{kind}|{}|{}", error.reason, error.label);
    let suffix = stable_digest_hex_len(material.as_bytes(), Some(12));
    GuardRiskSignalV3 {
        signal_id: format!("cisco-preflight:{OUTSIDE}:{suffix}"),
        source: RiskSignalSource::RuntimeDetector,
        source_version: "1".to_owned(),
        category: RiskSignalCategory::Filesystem,
        severity: RiskSeverityLabel::High,
        confidence: RiskConfidenceLabel::Strong,
        title: "Cisco preflight target is outside the approved workspace".to_owned(),
        plain_language_summary: "Guard did not run the Cisco scanner because the target or derived scan root could not be proven to remain inside the selected workspace or another explicitly approved folder.".to_owned(),
        technical_detail: Some(format!("{OUTSIDE}: {}", error.reason)),
        evidence_ref: Some(format!("approved-root:{}", error.label)),
        scanner_name: Some("Cisco preflight containment".to_owned()),
        scanner_status: ScannerStatusLabel::Failed,
        scanner_rule_id: Some(OUTSIDE.to_owned()),
        redaction_level: RiskRedactionLevel::Redacted,
        source_path: None,
        source_line: None,
        data_source: None,
        data_sink: None,
        recommended_action: Some("Move the target into the selected workspace or explicitly approve its containing folder, then retry.".to_owned()),
    }
}

#[derive(Default)]
struct Plan {
    steps: Vec<CiscoStepV1>,
    signals: Vec<GuardRiskSignalV3>,
    skill_roots: BTreeSet<PathBuf>,
    mcp_roots: BTreeSet<PathBuf>,
}

impl Plan {
    fn contained(&mut self, kind: &str, error: &Contain) {
        let signal = containment_signal(kind, error);
        if !self.signals.contains(&signal) {
            self.signals.push(signal.clone());
            self.steps.push(CiscoStepV1::Signal {
                signal: signal.to_value(),
            });
        }
    }

    fn scan(&mut self, validated: &Validated) {
        let roots = if validated.kind == "skill" {
            &mut self.skill_roots
        } else {
            &mut self.mcp_roots
        };
        if roots.insert(validated.scan_root.clone()) {
            self.steps.push(CiscoStepV1::Scan {
                kind: validated.kind.to_owned(),
                scan_root: validated.scan_root.to_string_lossy().into_owned(),
                status: None,
                findings: Vec::new(),
            });
        }
    }
}

fn checked(validated: Result<Validated, Contain>) -> Result<Validated, Contain> {
    let validated = validated?;
    contain::revalidate(&validated)?;
    Ok(validated)
}

pub(crate) fn plan(query: &CiscoPlanQueryV1) -> Vec<CiscoStepV1> {
    if query.action_type != "file_write" && query.action_type != "config_change" {
        return Vec::new();
    }
    let cwd = Path::new(&query.cwd);
    let home = query.home.as_deref();
    let roots = match contain::approved_roots(
        query.workspace.as_deref(),
        &query.approved_scan_roots,
        cwd,
        home,
    ) {
        Ok(roots) => roots,
        Err(error) => {
            return vec![CiscoStepV1::Signal {
                signal: containment_signal("approved-root", &error).to_value(),
            }];
        }
    };
    let primary: &ApprovedRoot = &roots[0];
    let mut plan = Plan::default();
    let (mut redacted_skill, mut redacted_mcp) = (false, false);
    for target in &query.target_paths {
        let Some(kind) = contain::target_kind(target, &query.sources) else {
            continue;
        };
        if target.starts_with(".../") {
            redacted_skill |= kind == "skill";
            redacted_mcp |= kind == "mcp";
            continue;
        }
        match checked(contain::validated_target(
            target,
            kind,
            &primary.path,
            home,
            &roots,
        )) {
            Ok(validated) => plan.scan(&validated),
            Err(error) => plan.contained(kind, &error),
        }
    }
    for (wanted, kind) in [(redacted_skill, "skill"), (redacted_mcp, "mcp")] {
        if !wanted {
            continue;
        }
        match checked(contain::validated_redacted(kind, primary)) {
            Ok(validated) => plan.scan(&validated),
            Err(error) => plan.contained(kind, &error),
        }
    }
    plan.steps
}
