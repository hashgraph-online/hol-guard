use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::*;
use crate::plugin_telemetry_host::Index;

/// 2026-10-21, a Wednesday in ISO week 43.
const WEEK: &str = "2026-W43";

struct FakeHol {
    index: Vec<Value>,
    sent: RefCell<Vec<Value>>,
    refuse_post: bool,
    /// Turns counts off while the index downloads.
    opt_out_home: Option<PathBuf>,
    /// Turns counts back on with a new device key after opting out.
    rekey: bool,
    /// What a second sender and the state file saw while the report posted.
    seen_mid_send: RefCell<Option<(Option<String>, String, String)>>,
    probe_home: Option<(PathBuf, PathBuf)>,
}

impl FakeHol {
    fn new() -> Self {
        Self {
            index: vec![
                json!({"slug": "acme/notes-kit", "repository": "https://github.com/acme/notes-kit"}),
                json!({"slug": "acme/other", "repository": "https://github.com/acme/other"}),
            ],
            sent: RefCell::new(Vec::new()),
            refuse_post: false,
            opt_out_home: None,
            rekey: false,
            seen_mid_send: RefCell::new(None),
            probe_home: None,
        }
    }
}

impl Hol for FakeHol {
    fn index(&self, index: Index) -> Result<Vec<Value>, String> {
        if let Some(guard_home) = &self.opt_out_home {
            turn_off(guard_home).expect("off");
            if self.rekey {
                turn_on(guard_home).expect("on again");
            }
        }
        match index {
            Index::Plugin => Ok(self.index.clone()),
            Index::Release => Ok(Vec::new()),
        }
    }

    fn post_report(&self, report: &Value) -> Result<i64, String> {
        if let Some((guard_home, user_home)) = &self.probe_home {
            let other = FakeHol::new();
            let due = send_if_due(&other, guard_home, user_home, WEEK);
            let now = send_now(&other, guard_home, user_home, WEEK);
            *self.seen_mid_send.borrow_mut() = Some((
                read_state(guard_home).last_week,
                format!("{due:?}"),
                format!("{now:?}"),
            ));
            assert!(other.sent.borrow().is_empty());
        }
        if self.refuse_post {
            return Err("HOL did not accept the report (HTTP 503).".to_owned());
        }
        self.sent.borrow_mut().push(report.clone());
        Ok(1)
    }

    /// Ignores `CLAUDE_CONFIG_DIR` and `CODEX_HOME`, so tests see only the
    /// temp home whatever the test process inherited.
    fn configured_dir(&self, _name: &str) -> Option<String> {
        None
    }
}

struct Homes {
    _root: tempfile::TempDir,
    guard: PathBuf,
    user: PathBuf,
}

fn plugin(user: &Path, owner: &str, name: &str, version: &str, repository: &str) {
    let manifest = user
        .join(".claude/plugins/cache")
        .join(owner)
        .join(name)
        .join(version)
        .join(".claude-plugin");
    std::fs::create_dir_all(&manifest).expect("plugin dir");
    std::fs::write(
        manifest.join("plugin.json"),
        json!({"name": name, "version": version, "repository": repository}).to_string(),
    )
    .expect("plugin manifest");
}

/// One listed plugin and one private plugin under a fresh user home.
fn homes() -> Homes {
    let root = tempfile::tempdir().expect("root");
    let guard = root.path().join("guard-home");
    let user = root.path().join("user");
    plugin(
        &user,
        "acme",
        "notes-kit",
        "1.2.0",
        "https://github.com/acme/notes-kit.git",
    );
    plugin(
        &user,
        "corp",
        "internal-tool",
        "0.1.0",
        "https://github.com/corp/internal-tool",
    );
    Homes {
        _root: root,
        guard,
        user,
    }
}

#[test]
fn iso_weeks_follow_the_calendar() {
    // 2026-10-21 is day 20_747 after the epoch.
    assert_eq!(iso_week(20_747), WEEK);
    // 2021-01-03 (Sunday) still belongs to 2020's week 53.
    assert_eq!(iso_week(18_630), "2020-W53");
    // 2024-12-30 (Monday) starts 2025's week 1.
    assert_eq!(iso_week(20_087), "2025-W01");
    assert_eq!(iso_week(0), "1970-W01");
}

#[test]
fn counts_are_off_until_turned_on_and_nothing_is_sent() {
    let homes = homes();
    let hol = FakeHol::new();
    assert!(!read_state(&homes.guard).enabled);
    assert_eq!(send_if_due(&hol, &homes.guard, &homes.user, WEEK), Ok(None));
    assert_eq!(
        send_now(&hol, &homes.guard, &homes.user, WEEK),
        Err(OFF_MESSAGE.to_owned())
    );
    assert!(hol.sent.borrow().is_empty());
    assert!(!homes.guard.join(SECRET_FILE).exists());
}

#[test]
fn on_creates_an_owner_only_key_and_off_deletes_it() {
    let homes = homes();
    turn_on(&homes.guard).expect("on");
    let secret = homes.guard.join(SECRET_FILE);
    let mode = std::fs::metadata(&secret)
        .expect("key")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(read_secret(&homes.guard).is_some());
    assert!(read_state(&homes.guard).enabled);
    turn_off(&homes.guard).expect("off");
    assert!(!secret.exists());
    assert_eq!(
        read_state(&homes.guard),
        State {
            enabled: false,
            last_week: None
        }
    );
}

#[test]
fn an_invalid_key_is_replaced_when_counts_turn_on() {
    let homes = homes();
    std::fs::create_dir_all(&homes.guard).expect("guard home");
    std::fs::write(homes.guard.join(SECRET_FILE), "not hex").expect("bad key");
    turn_on(&homes.guard).expect("on");
    assert!(read_secret(&homes.guard).is_some());
}

#[test]
fn report_names_only_listed_plugins_and_nothing_about_the_machine() {
    let homes = homes();
    let hol = FakeHol::new();
    turn_on(&homes.guard).expect("on");
    let result = send_if_due(&hol, &homes.guard, &homes.user, WEEK)
        .expect("send")
        .expect("due");
    assert_eq!(
        (&result["week"], &result["installed"], &result["listed"]),
        (&json!(WEEK), &json!(2), &json!(1))
    );
    assert_eq!(
        send_if_due(&hol, &homes.guard, &homes.user, WEEK),
        Ok(None),
        "one report per week"
    );
    let sent = hol.sent.borrow();
    let [report] = sent.as_slice() else {
        panic!("one report: {sent:?}");
    };
    let keys: Vec<&String> = report.as_object().expect("report").keys().collect();
    assert_eq!(keys, ["entries", "guardVersion", "schema", "week"]);
    let [entry] = report["entries"].as_array().expect("entries").as_slice() else {
        panic!("one entry: {report}");
    };
    assert_eq!(
        (&entry["slug"], &entry["runtime"], &entry["version"]),
        (
            &json!("acme/notes-kit"),
            &json!("claude-code"),
            &json!("1.2.0")
        )
    );
    assert_eq!(entry["key"].as_str().map(str::len), Some(64));
    assert!(entry.get("via").is_none());
    let text = report.to_string();
    for private in [
        "internal-tool".to_owned(),
        "corp".to_owned(),
        homes.user.to_string_lossy().into_owned(),
        homes.guard.to_string_lossy().into_owned(),
    ] {
        assert!(!text.contains(&private), "{private} leaked");
    }
}

#[test]
fn dry_run_builds_the_report_without_opt_in_or_sending() {
    let homes = homes();
    let hol = FakeHol::new();
    let built = dry_run(&hol, &homes.guard, &homes.user, WEEK).expect("dry run");
    assert_eq!(built["report"]["entries"].as_array().map(Vec::len), Some(1));
    assert!(hol.sent.borrow().is_empty());
    assert!(!homes.guard.join(SECRET_FILE).exists());
}

#[test]
fn turning_counts_off_during_a_send_stops_it_and_stays_off() {
    let homes = homes();
    turn_on(&homes.guard).expect("on");
    let mut hol = FakeHol::new();
    hol.opt_out_home = Some(homes.guard.clone());
    assert_eq!(
        send_now(&hol, &homes.guard, &homes.user, WEEK),
        Err(OFF_MESSAGE.to_owned())
    );
    assert!(hol.sent.borrow().is_empty());
    assert_eq!(
        read_state(&homes.guard),
        State {
            enabled: false,
            last_week: None
        }
    );
}

#[test]
fn a_new_device_key_during_a_send_stops_it() {
    let homes = homes();
    turn_on(&homes.guard).expect("on");
    let mut hol = FakeHol::new();
    hol.opt_out_home = Some(homes.guard.clone());
    hol.rekey = true;
    assert_eq!(
        send_now(&hol, &homes.guard, &homes.user, WEEK),
        Err(OFF_MESSAGE.to_owned())
    );
    assert!(hol.sent.borrow().is_empty());
    assert_eq!(read_state(&homes.guard).last_week, None);
}

#[test]
fn a_failed_send_leaves_the_week_due() {
    let homes = homes();
    turn_on(&homes.guard).expect("on");
    let mut hol = FakeHol::new();
    hol.refuse_post = true;
    assert_eq!(
        send_if_due(&hol, &homes.guard, &homes.user, WEEK),
        Err("HOL did not accept the report (HTTP 503).".to_owned())
    );
    assert_eq!(read_state(&homes.guard).last_week, None);
    hol.refuse_post = false;
    assert!(send_if_due(&hol, &homes.guard, &homes.user, WEEK)
        .expect("send")
        .is_some());
    assert_eq!(read_state(&homes.guard).last_week.as_deref(), Some(WEEK));
    assert_eq!(hol.sent.borrow().len(), 1);
}

#[test]
fn a_send_in_flight_records_nothing_and_holds_off_other_senders() {
    let homes = homes();
    turn_on(&homes.guard).expect("on");
    let mut hol = FakeHol::new();
    hol.probe_home = Some((homes.guard.clone(), homes.user.clone()));
    assert!(send_if_due(&hol, &homes.guard, &homes.user, WEEK)
        .expect("send")
        .is_some());
    // Mid-send the week is not yet recorded, so a sender killed at this point
    // leaves it due; the send lock it held is released with the process.
    assert_eq!(
        hol.seen_mid_send.take(),
        Some((
            None,
            "Ok(None)".to_owned(),
            format!("Err({BUSY_MESSAGE:?})"),
        ))
    );
    assert_eq!(read_state(&homes.guard).last_week.as_deref(), Some(WEEK));
    assert_eq!(hol.sent.borrow().len(), 1);
}

#[test]
fn a_released_send_lock_lets_the_week_be_sent() {
    let homes = homes();
    turn_on(&homes.guard).expect("on");
    let lock = try_send_lock(&homes.guard).expect("lock").expect("free");
    let hol = FakeHol::new();
    assert_eq!(send_if_due(&hol, &homes.guard, &homes.user, WEEK), Ok(None));
    drop(lock);
    assert!(send_if_due(&hol, &homes.guard, &homes.user, WEEK)
        .expect("send")
        .is_some());
    assert_eq!(hol.sent.borrow().len(), 1);
}

#[test]
fn listings_guard_installed_are_marked() {
    let homes = homes();
    let ledger = homes.guard.join("plugin-kit");
    std::fs::create_dir_all(&ledger).expect("ledger dir");
    std::fs::write(
        ledger.join("installs.json"),
        json!({
            "schema": "hol.plugin-kit.installs.v1",
            "installs": {"acme/notes-kit": {"targets": [{"runtime": "claude-code"}]}},
        })
        .to_string(),
    )
    .expect("ledger");
    let mut report = json!({"entries": [
        {"slug": "acme/notes-kit", "runtime": "claude-code"},
        {"slug": "acme/notes-kit", "runtime": "codex"},
    ]});
    mark_guard_installs(&mut report, &homes.guard);
    assert_eq!(report["entries"][0]["via"], json!("hol-guard"));
    assert!(report["entries"][1].get("via").is_none());
}

#[test]
fn an_unreadable_install_record_marks_nothing() {
    let homes = homes();
    let mut report = json!({"entries": [{"slug": "acme/notes-kit", "runtime": "claude-code"}]});
    let before = report.clone();
    mark_guard_installs(&mut report, &homes.guard);
    assert_eq!(report, before);
}
