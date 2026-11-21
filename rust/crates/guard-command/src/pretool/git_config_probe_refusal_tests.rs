use super::super::PathContext;
use super::{execution_free, probe_unanswered};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn environment(home: &Path) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec![
            "HOME".to_owned(),
            "PATH".to_owned(),
            "GIT_CONFIG_NOSYSTEM".to_owned(),
        ],
        environment_digest: "0".repeat(64),
        home: Some(home.to_string_lossy().into_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
    }
}

/// A real repository this host's own Git trusts, so a probe against it fails
/// for the reason the test sets up and not for its surroundings.
struct Fixture {
    root: PathBuf,
    declared: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = crate::unique_nanos::unique_nanos();
        let root =
            std::env::temp_dir().join(format!("hg-probe-refusal-{}-{nonce}", std::process::id()));
        let declared = root.join("declared");
        let repo = declared.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let mut init = Command::new("git");
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_NAMESPACE",
        ] {
            init.env_remove(name);
        }
        let init = init
            .arg("init")
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &declared)
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        Self {
            root,
            declared,
            repo,
        }
    }

    fn append_to_configuration(&self, text: &str) {
        let config = self.repo.join(".git").join("config");
        let mut contents = fs::read_to_string(&config).unwrap();
        contents.push_str(text);
        fs::write(&config, contents).unwrap();
    }

    /// Bytes Git writes for the keys the configuration probe asks about.
    fn matching_reply_bytes(&self) -> usize {
        Command::new("git")
            .args([
                "--no-pager",
                "config",
                "--null",
                "--get-regexp",
                "^(core\\.fsmonitor|pretty\\..*)$",
            ])
            .current_dir(&self.repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &self.declared)
            .output()
            .unwrap()
            .stdout
            .len()
    }

    fn configuration_readable(&self) -> bool {
        Command::new("git")
            .args(["--no-pager", "config", "--null", "--get-regexp", "^core\\."])
            .current_dir(&self.repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &self.declared)
            .output()
            .unwrap()
            .status
            .success()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A probe that read the configuration and only then ran out of answers is a
/// refusal, not an unanswered probe.
///
/// `git hash-object` runs the repository's clean filter over the paths it
/// names, so the proof asks `check-attr` which of them the filter claims. An
/// operand this proof will not hand to that query leaves the filter's reach
/// unknown -- but the configuration was read and a filter was found in it, so
/// nothing about this read is an open question. Reporting it as unanswered
/// would let an explicit allow settle a read that starts a configured filter
/// program.
#[test]
fn a_filter_the_proof_could_not_follow_is_not_an_unanswered_probe() {
    let fixture = Fixture::new();
    fixture.append_to_configuration("[filter \"demo\"]\n\tclean = demo-clean\n");
    assert!(
        fixture.configuration_readable(),
        "the configuration must stay readable for this case"
    );
    let declared = fixture.declared.canonicalize().unwrap();
    let repo = fixture.repo.canonicalize().unwrap();
    let context = PathContext {
        home_dir: declared.to_str(),
        cwd: repo.to_str(),
        ..PathContext::default()
    };
    let environment = environment(&declared);
    // Longer than the operand the attribute query accepts, so the query the
    // proof depends on never runs.
    let operand = "a".repeat(5000);
    let arguments = ["hash-object".to_owned(), operand];
    assert_eq!(
        execution_free("git", &arguments, context, None, Some(&environment), false),
        Some(false),
        "a filter the proof could not follow leaves the read refused"
    );
    assert!(
        !probe_unanswered("git", &arguments, context, None, Some(&environment), false),
        "the configuration was read, so this refusal is not an open question"
    );
}

/// A configuration the probe could not read at all is the open question an
/// explicit allow settles.
#[test]
fn an_unreadable_configuration_is_an_unanswered_probe() {
    let fixture = Fixture::new();
    fixture.append_to_configuration("[core\n");
    assert!(
        !fixture.configuration_readable(),
        "the fixture must leave the configuration unreadable"
    );
    let declared = fixture.declared.canonicalize().unwrap();
    let repo = fixture.repo.canonicalize().unwrap();
    let context = PathContext {
        home_dir: declared.to_str(),
        cwd: repo.to_str(),
        ..PathContext::default()
    };
    let environment = environment(&declared);
    let arguments = ["status".to_owned(), "--short".to_owned()];
    assert_eq!(
        execution_free("git", &arguments, context, None, Some(&environment), false),
        Some(false),
        "an unreadable configuration proves nothing"
    );
    assert!(
        probe_unanswered("git", &arguments, context, None, Some(&environment), false),
        "the probe never read the configuration"
    );
}

/// A configuration reply larger than the probe reads is not an open question
/// either.
///
/// Git parses the file without trouble and starts whatever helper it names;
/// the probe simply declines to read a reply that big. Padding is cheap and
/// repository-controlled, so treating the overflow as an unanswered probe
/// would hand anyone who can write `.git/config` a way to put a monitor or a
/// pager beyond an explicit allow's sight.
#[test]
fn a_configuration_reply_over_the_bound_is_not_an_unanswered_probe() {
    let fixture = Fixture::new();
    // One matching value wider than the probe's 64 KiB bound, set beside a
    // helper the probe would otherwise have found.
    fixture.append_to_configuration(&format!(
        "[core]\n\tfsmonitor = demo-monitor\n[pretty]\n\tpad = {}\n",
        "a".repeat(70_000)
    ));
    assert!(
        fixture.configuration_readable(),
        "the configuration must stay readable for this case"
    );
    assert!(
        fixture.matching_reply_bytes() > 65_536,
        "the fixture must push the reply past the probe's bound"
    );
    let declared = fixture.declared.canonicalize().unwrap();
    let repo = fixture.repo.canonicalize().unwrap();
    let context = PathContext {
        home_dir: declared.to_str(),
        cwd: repo.to_str(),
        ..PathContext::default()
    };
    let environment = environment(&declared);
    let arguments = ["status".to_owned(), "--short".to_owned()];
    assert_eq!(
        execution_free("git", &arguments, context, None, Some(&environment), false),
        Some(false),
        "a reply the probe did not read proves nothing"
    );
    assert!(
        !probe_unanswered("git", &arguments, context, None, Some(&environment), false),
        "Git answered, so this refusal is not an open question"
    );
}
