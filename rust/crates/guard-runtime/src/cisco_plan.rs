//! Plans the Cisco preflight: which containment verdicts the action already
//! earned and which scans the caller may run, in the order they must run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use guard_command::local_supply_chain::stable_digest_hex_len;
use guard_contracts::{
    CiscoPlanQueryV1, CiscoRevalidateQueryV1, CiscoScanBindingV1, CiscoStepV1, GuardRiskSignalV3,
    RiskConfidenceLabel, RiskRedactionLevel, RiskSeverityLabel, RiskSignalCategory,
    RiskSignalSource, ScannerStatusLabel,
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
    contained_action: BTreeSet<&'static str>,
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

    /// An approved root that cannot be proven contains the whole action, so
    /// report it once. Each planned workspace reaches the same unprovable
    /// directory under its own label -- the selected workspace in one plan and
    /// an explicit root in the next -- and that label names the plan that
    /// reached it, not a second containment to report.
    fn contained_action(&mut self, error: &Contain) {
        if self.contained_action.insert(error.reason) {
            self.contained("approved-root", error);
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
                binding: Some(CiscoScanBindingV1 {
                    approved_root: validated.approved_root.path.to_string_lossy().into_owned(),
                    approved_label: validated.approved_root.label.clone(),
                    target: validated
                        .path
                        .as_ref()
                        .map(|path| path.to_string_lossy().into_owned()),
                }),
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

/// Every workspace this action is planned against, in the order the caller
/// proved them.
///
/// A relative target resolves against the shell's working directory, and an
/// action may carry more than one proven directory, so each is planned as the
/// selected workspace in turn and the rest stay approved roots for that plan.
/// Spellings are deduplicated before planning so one directory named twice is
/// planned once. A directory that cannot be read is an approved root for every
/// plan, so it contains all of them, and that containment is reported once
/// rather than once per planned workspace. With no proven shell directory the
/// caller's own workspace is the only one, which may be absent.
fn planned_workspaces(query: &CiscoPlanQueryV1, home: Option<&str>) -> Vec<Option<String>> {
    let mut named: Vec<String> = Vec::new();
    for value in &query.shell_cwds {
        if value.trim().is_empty() {
            continue;
        }
        let expanded = contain::expand(value, home).to_string_lossy().into_owned();
        if !named.contains(&expanded) {
            named.push(expanded);
        }
    }
    if named.is_empty() {
        return vec![query.workspace.clone()];
    }
    named.into_iter().map(Some).collect()
}

/// The roots every plan may reach: the explicitly approved ones the caller
/// named, then each proven shell directory.
fn approved(query: &CiscoPlanQueryV1, home: Option<&str>) -> Vec<String> {
    let mut roots = query.approved_scan_roots.clone();
    for workspace in planned_workspaces(query, home).into_iter().flatten() {
        if !roots.contains(&workspace) {
            roots.push(workspace);
        }
    }
    roots
}

pub(crate) fn plan(query: &CiscoPlanQueryV1) -> Vec<CiscoStepV1> {
    if query.action_type != "file_write" && query.action_type != "config_change" {
        return Vec::new();
    }
    let cwd = Path::new(&query.cwd);
    let home = query.home.as_deref();
    let approved_roots = approved(query, home);
    let mut plan = Plan::default();
    for workspace in planned_workspaces(query, home) {
        plan_one(
            query,
            workspace.as_deref(),
            &approved_roots,
            cwd,
            home,
            &mut plan,
        );
    }
    plan.steps
}

/// Plan the action against one selected workspace, adding to what the
/// workspaces before it already planned.
fn plan_one(
    query: &CiscoPlanQueryV1,
    workspace: Option<&str>,
    approved_roots: &[String],
    cwd: &Path,
    home: Option<&str>,
    plan: &mut Plan,
) {
    let roots = match contain::approved_roots(workspace, approved_roots, cwd, home) {
        Ok(roots) => roots,
        Err(error) => {
            plan.contained_action(&error);
            return;
        }
    };
    let primary: &ApprovedRoot = &roots[0];
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
}

/// Re-proves one planned scan root is still contained, immediately before the
/// caller hands it to the analyzer. A failed proof is the containment signal.
pub(crate) fn revalidated(query: &CiscoRevalidateQueryV1) -> Result<Option<GuardRiskSignalV3>, ()> {
    let kind = match query.kind.as_str() {
        "skill" => "skill",
        "mcp" => "mcp",
        _ => return Err(()),
    };
    let validated = Validated {
        path: query.binding.target.as_ref().map(PathBuf::from),
        scan_root: PathBuf::from(&query.scan_root),
        approved_root: ApprovedRoot {
            path: PathBuf::from(&query.binding.approved_root),
            label: query.binding.approved_label.clone(),
        },
        kind,
    };
    Ok(contain::revalidate(&validated)
        .err()
        .map(|error| containment_signal(kind, &error)))
}
