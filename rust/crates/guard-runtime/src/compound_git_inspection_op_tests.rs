//! Envelope, bounds and fail-closed behavior of the compound Git op.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use guard_contracts::{
    CompoundGitCheckV1, CompoundGitInspectionRequestV1, CompoundGitSegmentV1,
    COMPOUND_GIT_INSPECTION_REQUEST_SCHEMA,
};

use crate::compound_git_facts::GitFacts;
use crate::compound_git_inspection_op::{decide, evaluate_with_facts};
use crate::git_execution_safety_probe::ProbeOutput;

/// Pinned environment facts so shape and path semantics are tested alone.
pub(crate) struct StubFacts {
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) git: Option<PathBuf>,
    pub(crate) routing_clean: bool,
    pub(crate) safe: bool,
    pub(crate) probe: Option<(Option<i32>, Vec<u8>)>,
}

impl Default for StubFacts {
    fn default() -> Self {
        Self {
            env: BTreeMap::new(),
            git: Some(PathBuf::from("/usr/bin/git")),
            routing_clean: true,
            safe: true,
            probe: Some((Some(1), Vec::new())),
        }
    }
}

impl GitFacts for StubFacts {
    fn env(&self, name: &str) -> Option<&str> {
        self.env.get(name).map(String::as_str)
    }
    fn trusted_git(&self, _cwd: &Path) -> Option<PathBuf> {
        self.git.clone()
    }
    fn routing_environment_is_clean(&self) -> bool {
        self.routing_clean
    }
    fn fetch_origin_is_safe(&self, _cwd: &Path, _git: &Path) -> bool {
        self.safe
    }
    fn status_is_safe(&self, _cwd: &Path, _git: &Path) -> bool {
        self.safe
    }
    fn push_origin_is_safe(&self, _cwd: &Path, _git: &Path, _branch: &str) -> bool {
        self.safe
    }
    fn object_query_is_safe(&self, _cwd: &Path, _git: &Path) -> bool {
        self.safe
    }
    fn probe(&self, _git: &Path, _cwd: &Path, _arguments: &[&str]) -> Option<ProbeOutput> {
        self.probe
            .clone()
            .map(|(code, stdout)| ProbeOutput { code, stdout })
    }
}

pub(crate) fn request(check: CompoundGitCheckV1) -> CompoundGitInspectionRequestV1 {
    CompoundGitInspectionRequestV1 {
        schema: COMPOUND_GIT_INSPECTION_REQUEST_SCHEMA.to_owned(),
        request_id: "cgi-1".to_owned(),
        check,
        segments: Vec::new(),
        complete: true,
        command_text: None,
        value: None,
        values: Vec::new(),
        cwd: None,
        home_dir: None,
        repository_path: None,
        pager_key: None,
        git_binary: None,
        home: "/home/user".to_owned(),
        account_home: None,
        groups: Vec::new(),
        environment: BTreeMap::new(),
    }
}

fn temp_dir() -> PathBuf {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("cgi-op-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn git_segment(cwd: &Path, tokens: &[&str]) -> CompoundGitSegmentV1 {
    CompoundGitSegmentV1 {
        tokens: tokens.iter().map(|token| (*token).to_owned()).collect(),
        effective_cwd: Some(cwd.to_string_lossy().into_owned()),
        ..CompoundGitSegmentV1::default()
    }
}

fn envelope(request: &CompoundGitInspectionRequestV1, facts: &StubFacts) -> serde_json::Value {
    serde_json::from_slice(&evaluate_with_facts(request, facts).unwrap()).unwrap()
}

fn with_env(pairs: &[(&str, &str)]) -> StubFacts {
    StubFacts {
        env: pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
        ..StubFacts::default()
    }
}

fn with_probe(probe: Option<(Option<i32>, Vec<u8>)>) -> StubFacts {
    StubFacts {
        probe,
        ..StubFacts::default()
    }
}

#[test]
fn ok_envelope_binds_the_request_and_carries_the_verdict() {
    let cwd = temp_dir();
    let mut req = request(CompoundGitCheckV1::Segment);
    req.segments = vec![git_segment(&cwd, &["git", "status", "--short"])];
    let result = envelope(&req, &StubFacts::default());
    assert_eq!(result["schema"], "guard-compound-git-inspection-result.v1");
    assert_eq!(result["request_id"], "cgi-1");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["allowed"], true);
    assert!(result["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn schema_mismatch_and_missing_fields_are_errors_that_deny() {
    let mut req = request(CompoundGitCheckV1::RepositoryPath);
    req.schema = "other".to_owned();
    let result = envelope(&req, &StubFacts::default());
    assert_eq!(result["status"], "error");
    assert_eq!(
        result["code"],
        "native_compound_git_inspection_schema_mismatch"
    );
    assert_eq!(result["allowed"], false);
    for check in [
        CompoundGitCheckV1::RepositoryPath,
        CompoundGitCheckV1::ObjectExistenceQuery,
        CompoundGitCheckV1::HomeGitCPath,
        CompoundGitCheckV1::LogConfig,
        CompoundGitCheckV1::Segment,
        CompoundGitCheckV1::ShowConfig,
        CompoundGitCheckV1::PushSegment,
    ] {
        let result = envelope(&request(check), &StubFacts::default());
        assert_eq!(result["status"], "error", "{check:?}");
        assert_eq!(result["code"], "native_compound_git_inspection_invalid");
        assert_eq!(result["allowed"], false);
    }
}

#[test]
fn oversized_and_nul_bearing_fields_are_refused() {
    let mut req = request(CompoundGitCheckV1::RepositoryPath);
    req.value = Some("a".repeat(20_000));
    assert_eq!(envelope(&req, &StubFacts::default())["status"], "error");
    let mut req = request(CompoundGitCheckV1::ObjectExistenceQuery);
    req.command_text = Some("git cat-file -e HEAD".to_owned());
    req.cwd = Some("/tmp/a\0b".to_owned());
    assert_eq!(envelope(&req, &StubFacts::default())["status"], "error");
    let mut req = request(CompoundGitCheckV1::Compound);
    req.segments = vec![CompoundGitSegmentV1::default(); 129];
    assert_eq!(envelope(&req, &StubFacts::default())["status"], "error");
    let mut req = request(CompoundGitCheckV1::LogConfig);
    req.cwd = Some("/tmp".to_owned());
    req.git_binary = Some("/usr/bin/git".to_owned());
    req.pager_key = Some("core.sshCommand".to_owned());
    assert_eq!(envelope(&req, &StubFacts::default())["status"], "error");
}

fn pathspec_verdict(values: &[&str]) -> serde_json::Value {
    let mut req = request(CompoundGitCheckV1::CachedDiffPathspecs);
    req.values = values.iter().map(|value| (*value).to_owned()).collect();
    envelope(&req, &StubFacts::default())
}

#[test]
fn cached_diff_pathspecs_are_decided_in_one_request() {
    assert_eq!(
        pathspec_verdict(&["src", "docs/a.md", ":!vendor"])["allowed"],
        true
    );
    assert_eq!(pathspec_verdict(&[":^dist/out"])["allowed"], true);
    // One unsafe pathspec denies the whole list.
    for bad in [
        &["src", "/etc/passwd"][..],
        &["src", ":!/abs"],
        &["src", ":!"],
        &["src", ":!~/x"],
        &["src", ":!:(glob)x"],
        &["src", ":(top)x"],
        &["src", "$HOME"],
        &["src", ".."],
    ] {
        let result = pathspec_verdict(bad);
        assert_eq!(result["status"], "ok", "{bad:?}");
        assert_eq!(result["allowed"], false, "{bad:?}");
    }
    // No pathspecs is not a path scope.
    assert_eq!(pathspec_verdict(&[])["allowed"], false);
    // More than the bounded count is refused outright.
    let many: Vec<String> = (0..17).map(|index| format!("p{index}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let result = pathspec_verdict(&refs);
    assert_eq!(result["status"], "error");
    assert_eq!(result["allowed"], false);
}

#[test]
fn home_git_c_path_returns_the_extracted_value() {
    let mut req = request(CompoundGitCheckV1::HomeGitCPath);
    req.command_text = Some("git -C ~/repo status".to_owned());
    let result = envelope(&req, &StubFacts::default());
    assert_eq!(result["allowed"], true);
    assert_eq!(result["value"], "~/repo");
    req.command_text = Some("git -C ~/../repo status".to_owned());
    let result = envelope(&req, &StubFacts::default());
    assert_eq!(result["allowed"], false);
    assert!(result.get("value").is_none());
}

fn log_config_verdict(facts: &StubFacts) -> bool {
    let mut req = request(CompoundGitCheckV1::LogConfig);
    req.cwd = Some("/tmp".to_owned());
    req.git_binary = Some("/usr/bin/git".to_owned());
    decide(&req, facts).unwrap().allowed
}

#[test]
fn pager_environment_and_config_gate_log_output() {
    assert!(log_config_verdict(&StubFacts::default()));
    assert!(log_config_verdict(&with_env(&[("GIT_PAGER", "cat")])));
    assert!(log_config_verdict(&with_env(&[("GIT_PAGER", "")])));
    assert!(!log_config_verdict(&with_env(&[("GIT_PAGER", "less")])));
    assert!(!log_config_verdict(&with_env(&[("PAGER", "less")])));
    assert!(log_config_verdict(&with_env(&[("PAGER", "cat")])));
    let mut dirty = with_env(&[("GIT_PAGER", "cat")]);
    dirty.routing_clean = false;
    assert!(!log_config_verdict(&dirty));
    assert!(!log_config_verdict(&with_probe(Some((
        Some(0),
        b"less\0".to_vec()
    )))));
    assert!(log_config_verdict(&with_probe(Some((
        Some(0),
        b"cat\0".to_vec()
    )))));
    for failed in [
        Some((Some(0), vec![0xff, 0xfe])),
        Some((Some(2), Vec::new())),
        Some((None, Vec::new())),
        None,
    ] {
        assert!(!log_config_verdict(&with_probe(failed)));
    }
}

#[test]
fn show_config_requires_clean_diff_environment_and_probe() {
    let cwd = temp_dir();
    let mut req = request(CompoundGitCheckV1::ShowConfig);
    req.segments = vec![git_segment(&cwd, &["git", "diff", "--stat"])];
    assert!(decide(&req, &StubFacts::default()).unwrap().allowed);
    assert!(
        !decide(&req, &with_env(&[("GIT_EXTERNAL_DIFF", "tool")]))
            .unwrap()
            .allowed
    );
    assert!(
        decide(&req, &with_env(&[("GIT_EXTERNAL_DIFF", "  ")]))
            .unwrap()
            .allowed
    );
    for probe in [
        Some((Some(0), b"diff.external\0tool".to_vec())),
        Some((Some(1), b"x".to_vec())),
        None,
    ] {
        assert!(!decide(&req, &with_probe(probe)).unwrap().allowed);
    }
    req.segments[0].effective_cwd = None;
    assert!(!decide(&req, &StubFacts::default()).unwrap().allowed);
}

#[test]
fn untrusted_git_or_failed_safety_checks_deny() {
    let cwd = temp_dir();
    let mut req = request(CompoundGitCheckV1::Segment);
    req.segments = vec![git_segment(&cwd, &["git", "fetch", "origin"])];
    assert!(decide(&req, &StubFacts::default()).unwrap().allowed);
    let no_git = StubFacts {
        git: None,
        ..StubFacts::default()
    };
    assert!(!decide(&req, &no_git).unwrap().allowed);
    let unsafe_facts = StubFacts {
        safe: false,
        ..StubFacts::default()
    };
    assert!(!decide(&req, &unsafe_facts).unwrap().allowed);
    req.segments[0].effective_cwd = Some("relative/dir".to_owned());
    assert!(!decide(&req, &StubFacts::default()).unwrap().allowed);
}
