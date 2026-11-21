//! The launch loop of an observation against a real fixture hook: a `sh`
//! script in a temp directory that answers each probe with canned output and
//! a canned stderr, the way a protected package would, or lies.
//!
//! Ported from the false-proof, deadline, containment and legacy-key cases of
//! the Python observer tests, with the same refusal codes.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{
    legacy_args, legacy_call, observation, reason, receipt, seal, stderr_of, OPERATION, RUNTIME,
};
use crate::guard_store_legacy_probe::tests::build_database;
use crate::hook_process_spawn::BoundedHookProcessResult;
use crate::transition_files::publication_observe::intact;
use crate::transition_files::publication_observe_check::OBSERVATION_SCHEMA;
use crate::transition_files::publication_observe_legacy::Legacy;
use crate::transition_files::publication_observe_run::{agreed, launched, Run};
use crate::transition_files::{Budget, Step};

const ALLOW_ID: &str = "transition-hook-00000000000000000000000000000001";
const DENY_ID: &str = "transition-hook-00000000000000000000000000000002";
const DENIED: &str = r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#;
/// Pick the canned answer by the command the probe carries.
const HOOK: &str = r#"input=$(cat)
dir=$1
case "$input" in
  *'"command":"pwd"'*) name=allow ;;
  *) name=deny ;;
esac
[ -f "$dir/before" ] && . "$dir/before"
cat "$dir/$name.err" >&2
cat "$dir/$name.out"
"#;

/// What the fixture hook writes for one probe.
#[derive(Clone)]
struct Answer {
    out: String,
    err: String,
}

fn line(request_id: &str, receipt: &Value) -> String {
    let mut line = observation(receipt);
    line["request_id"] = json!(request_id);
    assert_eq!(line["operation_id"], OPERATION);
    assert_eq!(line["schema"], OBSERVATION_SCHEMA);
    stderr_of(&line)
}

fn honest(request_id: &str, decision: &str) -> Answer {
    let action = if decision == "allow" {
        "allow"
    } else {
        "block"
    };
    Answer {
        out: if decision == "allow" { "{}" } else { DENIED }.to_owned(),
        err: line(request_id, &receipt(request_id, decision, action)),
    }
}

fn runtime() -> String {
    RUNTIME.repeat(64)
}

struct Fixture {
    dir: tempfile::TempDir,
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
}

impl Fixture {
    fn new(allow: &Answer, deny: &Answer) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        fs::write(path.join("hook.sh"), HOOK).unwrap();
        fs::write(path.join("allow.out"), &allow.out).unwrap();
        fs::write(path.join("allow.err"), &allow.err).unwrap();
        fs::write(path.join("deny.out"), &deny.out).unwrap();
        fs::write(path.join("deny.err"), &deny.err).unwrap();
        let argv = [
            "/bin/sh",
            path.join("hook.sh").to_str().unwrap(),
            path.to_str().unwrap(),
        ]
        .map(str::to_owned)
        .to_vec();
        let environment = BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]);
        Self {
            dir,
            argv,
            environment,
        }
    }

    fn honest() -> Self {
        Self::new(&honest(ALLOW_ID, "allow"), &honest(DENY_ID, "deny"))
    }

    /// Run the loop for a package with the probe envelope.
    fn modern(&self, deadline: Duration) -> Step<(Vec<Value>, Vec<String>)> {
        self.run(deadline, None)
    }

    fn run(&self, deadline: Duration, legacy: Option<&Legacy>) -> Step<(Vec<Value>, Vec<String>)> {
        let runtime = runtime();
        let run = Run {
            argv: &self.argv,
            modern: legacy.is_none(),
            cwd: self.dir.path(),
            environment: &self.environment,
            workspace: "/work",
            operation_id: OPERATION,
            runtime: &runtime,
            deadline: Instant::now() + deadline,
            legacy,
        };
        let next = Cell::new(0);
        let ids = [ALLOW_ID, DENY_ID];
        let probed = run.probes(&|| {
            let index = next.get();
            next.set(index + 1);
            Ok(ids[index].to_owned())
        })?;
        Ok((probed.receipts, probed.outputs))
    }
}

const LONG: Duration = Duration::from_secs(30);

fn refused(outcome: Step<(Vec<Value>, Vec<String>)>) -> String {
    reason(outcome.expect_err("the observation must be refused"))
}

#[test]
fn an_honest_hook_yields_both_receipts_and_their_output_digests() {
    let (receipts, outputs) = Fixture::honest().modern(LONG).unwrap();
    assert_eq!(receipts[0]["decision"], "allow");
    assert_eq!(receipts[1]["decision"], "deny");
    assert_eq!(receipts[0]["request_id"], ALLOW_ID);
    assert_eq!(receipts[1]["request_id"], DENY_ID);
    assert_eq!(outputs.len(), 2);
    assert_ne!(outputs[0], outputs[1]);
    assert!(agreed(&receipts).is_ok());
}

#[test]
fn a_replayed_receipt_proves_nothing_for_the_next_probe() {
    let allow = honest(ALLOW_ID, "allow");
    let replay = Answer {
        out: DENIED.to_owned(),
        err: allow.err.clone(),
    };
    let fixture = Fixture::new(&allow, &replay);
    assert_eq!(refused(fixture.modern(LONG)), "admission_protection_failed");
}

#[test]
fn a_receipt_for_a_foreign_runtime_proves_nothing() {
    let mut foreign = receipt(DENY_ID, "deny", "block");
    foreign["runtime_identity"] = json!("c".repeat(64));
    seal(&mut foreign);
    let deny = Answer {
        out: DENIED.to_owned(),
        err: line(DENY_ID, &foreign),
    };
    let fixture = Fixture::new(&honest(ALLOW_ID, "allow"), &deny);
    assert_eq!(refused(fixture.modern(LONG)), "admission_protection_failed");
}

#[test]
fn output_that_does_not_show_the_decision_proves_nothing() {
    let honest_deny = honest(DENY_ID, "deny");
    for out in ["", "not json", "[]", "{}", "1e999"] {
        let deny = Answer {
            out: out.to_owned(),
            err: honest_deny.err.clone(),
        };
        let fixture = Fixture::new(&honest(ALLOW_ID, "allow"), &deny);
        assert_eq!(
            refused(fixture.modern(LONG)),
            "admission_protection_failed",
            "{out:?}"
        );
    }
    let blocking = Answer {
        out: r#"{"continue":false}"#.to_owned(),
        err: honest(ALLOW_ID, "allow").err,
    };
    let fixture = Fixture::new(&blocking, &honest(DENY_ID, "deny"));
    assert_eq!(refused(fixture.modern(LONG)), "admission_protection_failed");
}

#[test]
fn a_hook_that_leaves_no_receipt_proves_nothing() {
    let silent = Answer {
        out: "{}".to_owned(),
        err: "phase: resident\n".to_owned(),
    };
    let fixture = Fixture::new(&silent, &honest(DENY_ID, "deny"));
    assert_eq!(refused(fixture.modern(LONG)), "admission_protection_failed");
}

#[test]
fn a_launch_that_does_not_end_cleanly_proves_nothing() {
    let fixture = Fixture::honest();
    fs::write(fixture.dir.path().join("before"), "exit 3\n").unwrap();
    assert_eq!(
        refused(fixture.modern(LONG)),
        "admission_hook_launch_failed"
    );
    let fixture = Fixture::honest();
    fs::write(
        fixture.dir.path().join("before"),
        "head -c 70000 /dev/zero | tr '\\0' x\n",
    )
    .unwrap();
    assert_eq!(
        refused(fixture.modern(LONG)),
        "admission_hook_launch_failed"
    );
}

#[test]
fn containment_and_timeouts_are_launch_failures_not_proof() {
    let clean = BoundedHookProcessResult {
        returncode: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        output_limit_exceeded: false,
        timed_out: false,
        containment_failed: false,
    };
    assert!(launched(&clean).is_ok());
    let failures = [
        BoundedHookProcessResult {
            containment_failed: true,
            ..clean.clone()
        },
        BoundedHookProcessResult {
            timed_out: true,
            ..clean.clone()
        },
        BoundedHookProcessResult {
            output_limit_exceeded: true,
            ..clean.clone()
        },
        BoundedHookProcessResult {
            returncode: None,
            ..clean.clone()
        },
        BoundedHookProcessResult {
            returncode: Some(1),
            ..clean
        },
    ];
    for failure in failures {
        assert_eq!(
            reason(launched(&failure).unwrap_err()),
            "admission_hook_launch_failed",
            "{failure:?}"
        );
    }
}

#[test]
fn a_hook_that_outlives_the_deadline_is_killed_and_refused() {
    let fixture = Fixture::honest();
    fs::write(fixture.dir.path().join("before"), "sleep 30\n").unwrap();
    let started = Instant::now();
    assert_eq!(
        refused(fixture.modern(Duration::from_millis(500))),
        "admission_deadline_expired"
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    // An expired deadline launches nothing at all.
    let fixture = Fixture::honest();
    assert_eq!(
        refused(fixture.modern(Duration::ZERO)),
        "admission_deadline_expired"
    );
}

#[test]
fn two_receipts_must_name_one_policy_for_two_requests() {
    let allow = receipt(ALLOW_ID, "allow", "allow");
    let deny = receipt(DENY_ID, "deny", "block");
    let both = [allow.clone(), deny.clone()];
    let (generation, policy) = agreed(&both).unwrap();
    assert_eq!(generation, json!(1));
    assert_eq!(policy, json!("b".repeat(64)));
    let changed = |field: &str, value: Value| {
        let mut other = deny.clone();
        other[field] = value;
        [allow.clone(), other]
    };
    for (field, value) in [
        ("policy_generation", json!(2)),
        ("policy_digest", json!("c".repeat(64))),
        ("request_digest", allow["request_digest"].clone()),
    ] {
        assert_eq!(
            reason(agreed(&changed(field, value)).unwrap_err()),
            "admission_policy_mismatch",
            "{field}"
        );
    }
    for (field, value) in [
        ("policy_generation", json!("1")),
        ("policy_digest", Value::Null),
    ] {
        let mut broken = allow.clone();
        broken[field] = value.clone();
        let mut twin = deny.clone();
        twin[field] = value;
        assert_eq!(
            reason(agreed(&[broken, twin]).unwrap_err()),
            "admission_policy_mismatch",
            "{field}"
        );
    }
}

#[test]
fn a_signed_file_that_changed_after_the_binding_was_read_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let (config, manifest) = (dir.path().join("config.toml"), dir.path().join("manifest"));
    fs::write(&config, b"one").unwrap();
    fs::write(&manifest, b"two").unwrap();
    let args = serde_json::Map::new();
    let budget = Budget::none();
    let call = legacy_call(&args, &budget);
    let signed: [(&Path, &[u8]); 2] = [(&config, b"one"), (&manifest, b"two")];
    intact(&call, &signed).unwrap();
    fs::write(&config, b"changed").unwrap();
    assert_eq!(
        reason(intact(&call, &signed).unwrap_err()),
        "admission_hook_binding_changed"
    );
    fs::write(&config, b"one").unwrap();
    fs::remove_file(&manifest).unwrap();
    assert_eq!(
        reason(intact(&call, &signed).unwrap_err()),
        "admission_hook_binding_changed"
    );
}

/// A legacy package: no probe envelope, an installation key and a store.
fn legacy_fixture() -> (Fixture, tempfile::TempDir) {
    let home = super::private_home();
    build_database(&home.path().join("guard.db"));
    crate::hook_evidence_correlation::load_or_create_correlation_key(home.path()).unwrap();
    let plain = Answer {
        out: "{}".to_owned(),
        err: String::new(),
    };
    let fixture = Fixture::new(&plain, &plain);
    (fixture, home)
}

fn open(home: &Path, deadline: Instant) -> Legacy {
    let args = legacy_args(home, home);
    Legacy::open(&legacy_call(&args, &Budget::none()), home, deadline).unwrap()
}

#[test]
fn a_legacy_hook_with_no_stored_receipt_waits_for_the_deadline() {
    let (fixture, home) = legacy_fixture();
    let legacy = open(home.path(), Instant::now() + Duration::from_millis(600));
    assert_eq!(
        refused(fixture.run(Duration::from_millis(600), Some(&legacy))),
        "admission_deadline_expired"
    );
}

#[test]
fn a_legacy_key_that_changes_during_a_launch_refuses() {
    for rewrite in ["rm -f \"$HOME_KEY\"", "printf junk > \"$HOME_KEY\""] {
        let (fixture, home) = legacy_fixture();
        let key = home
            .path()
            .join(crate::hook_evidence_correlation::CORRELATION_KEY_FILE);
        let legacy = open(home.path(), Instant::now() + LONG);
        let script = rewrite.replace("$HOME_KEY", key.to_str().unwrap());
        fs::write(fixture.dir.path().join("before"), format!("{script}\n")).unwrap();
        assert_eq!(
            refused(fixture.run(LONG, Some(&legacy))),
            "legacy_probe_correlation_changed",
            "{rewrite}"
        );
    }
}
