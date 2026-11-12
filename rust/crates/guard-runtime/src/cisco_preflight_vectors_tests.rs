//! Parity vectors recorded from the retired Python Cisco preflight, replayed
//! against real temporary directory layouts, plus revalidation checks the
//! Python could only exercise by monkeypatching.
// The layout replays build real directory trees and run only on unix, so the
// helpers they share are unused on Windows.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};

use guard_contracts::{
    CiscoEvidenceQueryV1, CiscoFindingV1, CiscoPlanQueryV1, CiscoPolicyQueryV1,
    CiscoRevalidateQueryV1, CiscoStepV1,
};
use serde_json::{json, Value};

use crate::cisco_containment as contain;
use crate::store_vectors_support_tests::gunzip_json;
use crate::{cisco_evidence, cisco_plan};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/cisco_preflight_vectors.json.gz");

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("cisco-vec-{}-{tag}-{index}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");
        Self(std::fs::canonicalize(dir).expect("canonical scratch"))
    }

    fn text(&self, value: &str) -> String {
        value.replace("{root}", &self.0.to_string_lossy())
    }
}

#[cfg(unix)]
fn unlock(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() {
        return;
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    if meta.is_dir() {
        for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
            unlock(&entry.path());
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        #[cfg(unix)]
        unlock(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn build(root: &Scratch, layout: &[Value]) {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let chmod = |path: &Path, mode: u64| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode as u32))
            .expect("chmod");
    };
    for entry in layout {
        let path = root.0.join(entry["path"].as_str().expect("path"));
        match entry["kind"].as_str().expect("kind") {
            "dir" => {
                std::fs::create_dir_all(&path).expect("dir");
                if let Some(mode) = entry["mode"].as_u64() {
                    chmod(&path, mode);
                }
            }
            "file" => {
                std::fs::create_dir_all(path.parent().expect("parent")).expect("parent");
                std::fs::write(&path, "x").expect("file");
                if let Some(mode) = entry["mode"].as_u64() {
                    chmod(&path, mode);
                }
            }
            _ => {
                std::fs::create_dir_all(path.parent().expect("parent")).expect("parent");
                symlink(root.text(entry["target"].as_str().expect("target")), &path).expect("link");
            }
        }
    }
    for entry in layout {
        if let Some(mode) = entry["late_mode"].as_u64() {
            chmod(&root.0.join(entry["path"].as_str().expect("path")), mode);
        }
    }
}

fn findings(kind: &str) -> Vec<CiscoFindingV1> {
    let levels = ["critical", "high", "medium", "low", "info"];
    let mut out: Vec<CiscoFindingV1> = levels
        .iter()
        .enumerate()
        .map(|(i, level)| CiscoFindingV1 {
            rule_id: format!("R-{kind}-{i}"),
            severity: (*level).to_owned(),
            category: format!("{kind}-security"),
            title: format!("Title {i}  with   spaces"),
            description: format!("desc {}", "x".repeat(i)),
            remediation: Some("fix it".to_owned()),
            file_path: Some(format!("demo/{kind}/file{i}.md")),
            line_number: Some(i as i64 + 1),
            source: format!("cisco-{kind}-scanner"),
        })
        .collect();
    out.push(CiscoFindingV1 {
        rule_id: "R-NOLINE".to_owned(),
        severity: "high".to_owned(),
        category: "skill-security".to_owned(),
        title: "no line".to_owned(),
        description: "d".to_owned(),
        remediation: None,
        file_path: Some("a/b.md".to_owned()),
        line_number: None,
        source: "cisco-skill-scanner".to_owned(),
    });
    out.push(CiscoFindingV1 {
        rule_id: "R-NOPATH".to_owned(),
        severity: "medium".to_owned(),
        category: "x".to_owned(),
        title: "np".to_owned(),
        description: "d".to_owned(),
        remediation: Some("r".to_owned()),
        file_path: None,
        line_number: None,
        source: String::new(),
    });
    out
}

fn plan_query(root: &Scratch, query: &Value) -> CiscoPlanQueryV1 {
    let text = |value: &Value| value.as_str().map(|item| root.text(item));
    let list = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .expect("list")
            .iter()
            .filter_map(text)
            .collect()
    };
    CiscoPlanQueryV1 {
        action_type: query["action_type"].as_str().expect("action").to_owned(),
        workspace: text(&query["workspace"]),
        cwd: text(&query["cwd"]).expect("cwd"),
        home: text(&query["home"]),
        approved_scan_roots: list(&query["approved_scan_roots"]),
        shell_cwds: match query.get("shell_cwds") {
            Some(value) => list(value),
            None => Vec::new(),
        },
        target_paths: list(&query["target_paths"]),
        sources: list(&query["sources"]),
    }
}

fn scans_of(steps: &[CiscoStepV1], root: &Scratch) -> Vec<Value> {
    let prefix = root.0.to_string_lossy().into_owned();
    steps
        .iter()
        .filter_map(|step| match step {
            CiscoStepV1::Scan {
                kind, scan_root, ..
            } => Some(json!({"kind": kind, "scan_root": scan_root.replace(&prefix, "{root}")})),
            CiscoStepV1::Signal { .. } => None,
        })
        .collect()
}

#[cfg(unix)]
#[test]
fn layouts_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors["layout_cases"].as_array().expect("cases");
    assert!(cases.len() >= 50);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let root = Scratch::new("layout");
        build(&root, case["layout"].as_array().expect("layout"));
        let steps = cisco_plan::plan(&plan_query(&root, &case["query"]));
        assert_eq!(
            Value::Array(scans_of(&steps, &root)),
            case["expected"]["scans"],
            "{name}: scans"
        );
        let status = case["scan_status"].as_str().expect("status");
        let filled: Vec<CiscoStepV1> = steps
            .into_iter()
            .map(|step| match step {
                CiscoStepV1::Scan {
                    kind,
                    scan_root,
                    binding,
                    ..
                } => CiscoStepV1::Scan {
                    binding,
                    status: Some(status.to_owned()),
                    findings: if status == "enabled" {
                        findings(&kind)
                    } else {
                        Vec::new()
                    },
                    kind,
                    scan_root,
                },
                other => other,
            })
            .collect();
        let actual = cisco_evidence::evidence(&filled).expect("evidence");
        assert_eq!(
            actual["signals"], case["expected"]["signals"],
            "{name}: signals"
        );
    }
}

#[test]
fn evidence_cases_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors["evidence_cases"].as_array().expect("cases");
    assert!(cases.len() >= 10);
    for (index, case) in cases.iter().enumerate() {
        let found: Vec<CiscoFindingV1> =
            serde_json::from_value(case["findings"].clone()).expect("findings");
        let step = CiscoStepV1::Scan {
            kind: case["kind"].as_str().expect("kind").to_owned(),
            scan_root: "/scan".to_owned(),
            binding: None,
            status: case["status"].as_str().map(str::to_owned),
            findings: found,
        };
        let actual = cisco_evidence::evidence(&[step]).expect("evidence");
        assert_eq!(actual["signals"], case["expected"], "evidence case {index}");
    }
}

#[test]
fn policy_cases_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors["policy_cases"].as_array().expect("cases");
    assert!(cases.len() > 2000);
    for case in cases {
        let sources: Vec<String> =
            serde_json::from_value(case["sources"].clone()).expect("sources");
        let configured = serde_json::from_value(case["configured"].clone()).expect("configured");
        let actual = cisco_evidence::compose_policy_action(&sources, &configured).expect("policy");
        assert_eq!(actual["policy_action"], case["expected"], "{case}");
    }
}

#[test]
fn a_missing_configured_action_fails_closed() {
    assert!(cisco_evidence::compose_policy_action(
        &["cisco_skill".to_owned()],
        &std::collections::BTreeMap::new(),
    )
    .is_err());
}

#[test]
fn the_resident_resolves_each_signal_source_from_the_sent_config() {
    let query = CiscoPolicyQueryV1 {
        signal_sources: vec!["cisco_skill".to_owned(), "cisco_mcp".to_owned()],
        guard_config: guard_contracts::RiskActionConfigV1 {
            security_level: "balanced".to_owned(),
            protection_posture: "protected".to_owned(),
            protection_posture_explicit: false,
            risk_actions: [("malicious_skill".to_owned(), "block".to_owned())]
                .into_iter()
                .collect(),
            ..Default::default()
        },
        harness: None,
    };
    let actual = cisco_evidence::policy_action(&query).expect("policy");
    assert_eq!(actual["policy_action"], "block");
}

#[test]
fn a_per_harness_risk_action_overrides_the_global_one() {
    let config = guard_contracts::RiskActionConfigV1 {
        security_level: "balanced".to_owned(),
        protection_posture: "protected".to_owned(),
        protection_posture_explicit: false,
        risk_actions: [("malicious_skill".to_owned(), "warn".to_owned())]
            .into_iter()
            .collect(),
        harness_risk_actions: [(
            "codex".to_owned(),
            [("malicious_skill".to_owned(), "block".to_owned())]
                .into_iter()
                .collect(),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let query = |harness: Option<&str>| CiscoPolicyQueryV1 {
        signal_sources: vec!["cisco_skill".to_owned()],
        guard_config: config.clone(),
        harness: harness.map(str::to_owned),
    };
    assert_eq!(
        cisco_evidence::policy_action(&query(Some("codex"))).expect("policy")["policy_action"],
        "block"
    );
    assert_eq!(
        cisco_evidence::policy_action(&query(None)).expect("policy")["policy_action"],
        "warn"
    );
}

#[test]
fn an_unknown_severity_or_status_is_an_error() {
    let mut bad = findings("skill").remove(0);
    bad.severity = "catastrophic".to_owned();
    let step = |status: &str, finding: CiscoFindingV1| CiscoStepV1::Scan {
        kind: "skill".to_owned(),
        scan_root: "/scan".to_owned(),
        binding: None,
        status: Some(status.to_owned()),
        findings: vec![finding],
    };
    assert!(cisco_evidence::evidence(&[step("enabled", bad)]).is_err());
    assert!(cisco_evidence::evidence(&[step("sleeping", findings("skill").remove(0))]).is_err());
    let _ = CiscoEvidenceQueryV1 { steps: Vec::new() };
}

#[cfg(unix)]
#[test]
fn revalidation_catches_a_target_swapped_after_validation() {
    use std::os::unix::fs::symlink;
    let root = Scratch::new("swap");
    let skill_dir = root.0.join("ws/skills/a");
    std::fs::create_dir_all(&skill_dir).expect("dirs");
    std::fs::write(skill_dir.join("SKILL.md"), "x").expect("skill");
    std::fs::create_dir_all(root.0.join("outside")).expect("outside");
    std::fs::write(root.0.join("outside/SKILL.md"), "y").expect("outside file");
    let roots =
        contain::approved_roots(Some(&root.text("{root}/ws")), &[], &root.0, None).expect("roots");
    let validated =
        contain::validated_target("skills/a/SKILL.md", "skill", &roots[0].path, None, &roots)
            .expect("validated");
    contain::revalidate(&validated).expect("stable layout revalidates");
    std::fs::remove_file(skill_dir.join("SKILL.md")).expect("remove");
    symlink(root.0.join("outside/SKILL.md"), skill_dir.join("SKILL.md")).expect("swap");
    let error = contain::revalidate(&validated).expect_err("swap detected");
    assert_eq!(error.reason, "target_changed");
}

#[cfg(unix)]
#[test]
fn a_planned_scan_is_revalidated_through_its_own_binding() {
    use std::os::unix::fs::symlink;
    let root = Scratch::new("bound");
    let skill_dir = root.0.join("ws/skills/a");
    std::fs::create_dir_all(&skill_dir).expect("dirs");
    std::fs::write(skill_dir.join("SKILL.md"), "x").expect("skill");
    std::fs::create_dir_all(root.0.join("outside")).expect("outside");
    std::fs::write(root.0.join("outside/SKILL.md"), "y").expect("outside file");
    let query = CiscoPlanQueryV1 {
        action_type: "file_write".to_owned(),
        workspace: Some(root.text("{root}/ws")),
        cwd: root.text("{root}/ws"),
        home: None,
        approved_scan_roots: Vec::new(),
        shell_cwds: Vec::new(),
        target_paths: vec!["skills/a/SKILL.md".to_owned()],
        sources: vec!["skill".to_owned()],
    };
    let steps = cisco_plan::plan(&query);
    let Some(CiscoStepV1::Scan {
        kind,
        scan_root,
        binding: Some(binding),
        ..
    }) = steps.into_iter().next()
    else {
        panic!("expected a bound scan step");
    };
    let recheck = CiscoRevalidateQueryV1 {
        kind,
        scan_root,
        binding,
    };
    assert!(cisco_plan::revalidated(&recheck).expect("valid").is_none());
    std::fs::remove_file(skill_dir.join("SKILL.md")).expect("remove");
    symlink(root.0.join("outside/SKILL.md"), skill_dir.join("SKILL.md")).expect("swap");
    assert!(cisco_plan::revalidated(&recheck).expect("valid").is_some());
    let mut unknown = recheck.clone();
    unknown.kind = "other".to_owned();
    assert!(cisco_plan::revalidated(&unknown).is_err());
}

#[cfg(unix)]
#[test]
fn every_proven_shell_directory_is_planned_in_one_exchange() {
    let root = Scratch::new("cwds");
    for workspace in ["w1", "w2"] {
        let skill_dir = root.0.join(workspace).join("skills/a");
        std::fs::create_dir_all(&skill_dir).expect("dirs");
        std::fs::write(skill_dir.join("SKILL.md"), "x").expect("skill");
    }
    let query = CiscoPlanQueryV1 {
        action_type: "file_write".to_owned(),
        workspace: Some(root.text("{root}/w1")),
        cwd: root.text("{root}/w1"),
        home: None,
        approved_scan_roots: Vec::new(),
        shell_cwds: vec![
            root.text("{root}/w1"),
            root.text("{root}/w1"),
            "   ".to_owned(),
            root.text("{root}/w2"),
        ],
        target_paths: vec!["skills/a/SKILL.md".to_owned()],
        sources: vec!["skill".to_owned()],
    };
    let steps = cisco_plan::plan(&query);
    assert_eq!(
        scans_of(&steps, &root),
        vec![
            json!({"kind": "skill", "scan_root": "{root}/w1/skills"}),
            json!({"kind": "skill", "scan_root": "{root}/w2/skills"}),
        ],
        "each distinct proven directory is planned once, in the order proven"
    );
    assert!(
        !steps
            .iter()
            .any(|step| matches!(step, CiscoStepV1::Signal { .. })),
        "two proven directories that both contain the target earn no containment signal"
    );
}

#[cfg(unix)]
#[test]
fn a_proven_shell_directory_that_cannot_be_read_contains_the_whole_action() {
    let root = Scratch::new("cwd-gone");
    let skill_dir = root.0.join("w1/skills/a");
    std::fs::create_dir_all(&skill_dir).expect("dirs");
    std::fs::write(skill_dir.join("SKILL.md"), "x").expect("skill");
    let query = CiscoPlanQueryV1 {
        action_type: "file_write".to_owned(),
        workspace: Some(root.text("{root}/w1")),
        cwd: root.text("{root}/w1"),
        home: None,
        approved_scan_roots: Vec::new(),
        shell_cwds: vec![root.text("{root}/w1"), root.text("{root}/never-created")],
        target_paths: vec!["skills/a/SKILL.md".to_owned()],
        sources: vec!["skill".to_owned()],
    };
    let steps = cisco_plan::plan(&query);
    assert!(
        scans_of(&steps, &root).is_empty(),
        "an unprovable directory is an approved root for every plan, so none of them may scan"
    );
    assert_eq!(
        steps
            .iter()
            .filter(|step| matches!(step, CiscoStepV1::Signal { .. }))
            .count(),
        1,
        "the plans report that containment once, not once per planned workspace"
    );
}
