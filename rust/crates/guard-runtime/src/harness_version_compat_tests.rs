use super::*;

const GUARD: &str = "9.9.9";
const PLATFORM: &str = "darwin-arm64";
const NOW: f64 = 1_800_000_000.0;
const FULL_EVENTS: [&str; 3] = ["PostToolUse", "PreToolUse", "UserPromptSubmit"];

fn record(version: &str) -> Value {
    json!({
        "harness_version": version,
        "guard_version": GUARD,
        "platforms": [PLATFORM],
        "transport": "managed_extension",
        "events": FULL_EVENTS,
        "suite": { "id": "guard-gauntlet-full-task", "result": "passed" },
        "evidence_level": "live_block",
        "evidence_reference": "https://github.com/hashgraph-online/hol-guard/actions/runs/1",
        "observed_at": "2026-10-16T00:00:00Z",
    })
}

fn unit_record(version: &str) -> Value {
    let mut record = record(version);
    record["suite"]["id"] = json!("pi-exact-continuation");
    record["evidence_level"] = json!("unit_test");
    record["events"] = json!(["PreToolUse"]);
    record
}

fn coverage(records: &[Value]) -> Value {
    json!({
        "schema_version": "hol-guard-harness-version-coverage.v1",
        "revision": "fixture.1",
        "harnesses": [{
            "harness": "omp",
            "version_source": "package-metadata",
            "limitations": ["Exact versions only."],
            "remediation": [{ "label": "Releases", "url": "https://github.com/can1357/oh-my-pi/releases" }],
            "records": records,
        }],
    })
}

fn contracts() -> Value {
    let rows: Vec<Value> = FULL_EVENTS
        .iter()
        .map(|event| {
            json!({ "event": event, "transport": "managed_extension", "declared_actions": ["block"] })
        })
        .chain([json!({ "event": "Stop", "transport": "none", "declared_actions": ["unavailable"] })])
        .collect();
    json!({ "omp": rows, "codex": [] })
}

fn contract_rows() -> BTreeMap<String, Vec<CapabilityRow>> {
    serde_json::from_value(contracts()).expect("contract rows")
}

fn valid(payload: &Value) -> bool {
    manifest::parse_manifest(payload, &contract_rows()).is_some()
}

struct Home {
    root: tempfile::TempDir,
}

impl Home {
    fn new(payload: &Value) -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        fs::write(root.path().join("manifest.json"), payload.to_string()).expect("manifest");
        Self { root }
    }

    fn request(&self, op: &str) -> Value {
        json!({
            "schema": SCHEMA,
            "op": op,
            "guard_home": self.root.path().join("guard"),
            "harness": "omp",
        })
    }

    fn decide_with(&self, observation: Value, tweak: impl FnOnce(&mut Value)) -> Value {
        let mut request = self.request("decide");
        request["manifest_path"] = json!(self.root.path().join("manifest.json"));
        request["guard_version"] = json!(GUARD);
        request["platform"] = json!(PLATFORM);
        request["now"] = json!(NOW);
        request["observation"] = observation;
        request["contracts"] = contracts();
        tweak(&mut request);
        run(&request).expect("decide answer")
    }

    fn decide(&self, observation: Value) -> Value {
        self.decide_with(observation, |_| {})
    }

    fn acknowledge(&self, key: &str) -> Result<Value, String> {
        let mut request = self.request("acknowledge");
        request["key"] = json!(key);
        run(&request)
    }
}

fn run(request: &Value) -> Result<Value, String> {
    let bytes = run_command(request.to_string().as_bytes())?;
    Ok(serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn observed(version: &str) -> Value {
    json!({
        "state": "observed",
        "version": version,
        "source": "package-metadata",
        "installation_id": "install-a",
        "reason": null,
        "observed_at": NOW,
    })
}

fn fixture() -> Value {
    coverage(&[record("18.4.12"), record("18.8.3")])
}

#[test]
fn exact_versions_parse_and_ranges_do_not() {
    for text in ["18.4.12", "v18.4.12", "18.4.12-rc.1", "18.4.12+build.5"] {
        assert!(manifest::parse_version(text).is_some(), "{text}");
    }
    for text in ["18.x", "^18.4.12", ">=18", "18.4", "18.4.*", "", "018.4.1"] {
        assert!(manifest::parse_version(text).is_none(), "{text}");
    }
    assert!(manifest::parse_version(&"1".repeat(70)).is_none());
    let version = manifest::parse_version(" v18.4.12-rc.1+abc ").expect("version");
    assert_eq!(version.canonical, "18.4.12-rc.1+abc");
    assert!(version.prerelease);
}

#[test]
fn manifest_rejects_ranges_and_ineligible_records() {
    assert!(valid(&fixture()));
    assert!(valid(&coverage(&[unit_record("18.4.12")])));
    for version in ["18.x", "^18.4.12", ">=18.4.12 <19", "18.4.12 - 18.8.3", "*"] {
        assert!(!valid(&coverage(&[record(version)])), "{version}");
    }
    let overrides = [
        ("suite", json!({ "id": "pi-sdk-pin", "result": "passed" })),
        (
            "suite",
            json!({ "id": "guard-gauntlet-full-task", "result": "failed" }),
        ),
        (
            "suite",
            json!({ "id": "pi-exact-continuation", "result": "passed" }),
        ),
        ("transport", json!("hooks")),
        ("evidence_level", json!("independent_review")),
        ("evidence_reference", json!("https://example.com/run/1")),
        ("observed_at", json!("2026-10-16T00:00:00")),
        ("observed_at", json!("2026-02-30T00:00:00Z")),
        ("platforms", json!(["plan9-mips"])),
        ("guard_version", json!("3.x")),
        ("unexpected", json!(true)),
    ];
    for (key, value) in overrides {
        let mut record = record("18.4.12");
        record[key] = value.clone();
        assert!(!valid(&coverage(&[record])), "{key}={value}");
    }
}

#[test]
fn manifest_rejects_duplicates_unknown_harnesses_and_unreviewed_links() {
    assert!(!valid(&coverage(&[record("18.4.12"), record("v18.4.12")])));
    let mut unsourced = fixture();
    unsourced["harnesses"][0]["version_source"] = json!("unavailable");
    assert!(!valid(&unsourced));
    for url in [
        "http://github.com/x",
        "https://evil.example/x",
        "javascript:alert(1)",
        "https://user@github.com/x",
        "https://github.com:8443/x",
    ] {
        let mut payload = fixture();
        payload["harnesses"][0]["remediation"] = json!([{ "label": "x", "url": url }]);
        assert!(!valid(&payload), "{url}");
    }
    let mut unknown = fixture();
    unknown["harnesses"][0]["harness"] = json!("not-a-harness");
    assert!(!valid(&unknown));
    let mut schema = fixture();
    schema["schema_version"] = json!("v0");
    assert!(!valid(&schema));
    // A record may only name events the adapter declares for its transport.
    let mut rows = contract_rows();
    rows.insert("omp".to_owned(), Vec::new());
    assert!(manifest::parse_manifest(&fixture(), &rows).is_none());
}

#[test]
fn exact_match_is_tested_with_full_scope() {
    let home = Home::new(&fixture());
    for version in ["18.4.12", "18.8.3"] {
        let payload = home.decide(observed(version));
        assert_eq!(payload["state"], "tested");
        assert_eq!(payload["reason"], Value::Null);
        assert_eq!(payload["tested_scope"], "all_declared_events");
        assert_eq!(payload["tested_events"], json!(FULL_EVENTS));
        assert_eq!(payload["declared_events"], json!(FULL_EVENTS));
        assert_eq!(payload["enforcement_effect"], "none");
        assert_eq!(payload["coverage_revision"], "fixture.1");
        assert_eq!(
            payload["acknowledgement"],
            json!({ "eligible": false, "acknowledged": false, "key": null })
        );
        assert_eq!(payload["evidence"][0]["harness_version"], version);
        assert_eq!(
            payload["evidence"][0]["suite"],
            json!({ "id": "guard-gauntlet-full-task", "result": "passed" })
        );
    }
}

#[test]
fn neighbouring_prerelease_and_build_versions_are_untested() {
    let home = Home::new(&fixture());
    for version in [
        "18.11.2",
        "18.4.11",
        "18.6.0",
        "18.8.3-rc.1",
        "18.8.3+build.7",
        "19.0.0",
    ] {
        let payload = home.decide(observed(version));
        assert_eq!(payload["state"], "untested", "{version}");
        assert_eq!(payload["reason"], "version_not_in_evidence");
        assert_eq!(payload["tested_versions"], json!(["18.4.12", "18.8.3"]));
        assert_eq!(payload["acknowledgement"]["eligible"], json!(true));
    }
    assert_eq!(
        home.decide(observed("18.9.0-beta.2"))["version_is_prerelease"],
        json!(true)
    );
}

#[test]
fn other_build_platform_or_partial_scope() {
    let home = Home::new(&fixture());
    let other_build = home.decide_with(observed("18.8.3"), |request| {
        request["guard_version"] = json!("9.9.10");
    });
    assert_eq!(other_build["state"], "coverage_unavailable");
    let other_platform = home.decide_with(observed("18.8.3"), |request| {
        request["platform"] = json!("linux-x86_64");
    });
    assert_eq!(other_platform["reason"], "no_evidence_for_this_build");

    let partial = Home::new(&coverage(&[unit_record("18.4.12")])).decide(observed("18.4.12"));
    assert_eq!(partial["state"], "tested");
    assert_eq!(partial["tested_scope"], "partial");
    assert_eq!(partial["tested_events"], json!(["PreToolUse"]));
}

#[test]
fn unknown_stale_and_missing_coverage_are_never_tested() {
    let home = Home::new(&fixture());
    for (state, reason) in [
        ("unavailable", "executable_missing"),
        ("ambiguous", "multiple_installations"),
    ] {
        let mut observation = observed("18.8.3");
        observation["state"] = json!(state);
        observation["version"] = Value::Null;
        observation["reason"] = json!(reason);
        let payload = home.decide(observation);
        assert_eq!(payload["state"], "version_unknown");
        assert_eq!(payload["reason"], reason);
        assert_eq!(payload["acknowledgement"]["eligible"], json!(false));
    }
    let mut stale = observed("18.8.3");
    stale["observed_at"] = json!(NOW - OBSERVATION_MAX_AGE_SECONDS - 1.0);
    assert_eq!(home.decide(stale)["reason"], "observation_stale");

    let missing = home.decide_with(observed("18.8.3"), |request| {
        request["manifest_path"] = json!(home.root.path().join("absent.json"));
    });
    assert_eq!(missing["state"], "coverage_unavailable");
    assert_eq!(missing["reason"], "manifest_missing");
    let broken = Home::new(&coverage(&[record("18.x")])).decide(observed("18.8.3"));
    assert_eq!(broken["reason"], "manifest_invalid");
    let empty = Home::new(&coverage(&[])).decide(observed("18.8.3"));
    assert_eq!(empty["reason"], "harness_not_covered");
}

#[test]
fn acknowledgement_key_changes_with_every_binding() {
    let home = Home::new(&fixture());
    let key = |payload: Value| payload["acknowledgement"]["key"].clone();
    let base = key(home.decide(observed("18.11.2")));
    let other_version = key(home.decide(observed("18.11.3")));
    let mut other_install_observation = observed("18.11.2");
    other_install_observation["installation_id"] = json!("install-b");
    let other_install = key(home.decide(other_install_observation));
    let mut revised = fixture();
    revised["revision"] = json!("fixture.2");
    let other_revision = key(Home::new(&revised).decide(observed("18.11.2")));
    let distinct: BTreeSet<String> = [&base, &other_version, &other_install, &other_revision]
        .iter()
        .map(|value| value.to_string())
        .collect();
    assert_eq!(distinct.len(), 4);
    assert_eq!(
        base,
        json!(acknowledgement_key(
            "omp",
            "install-a",
            "18.11.2",
            "fixture.1",
            GUARD
        ))
    );
}

#[test]
fn acknowledged_key_collapses_only_the_matching_warning() {
    let home = Home::new(&fixture());
    let key = home.decide(observed("18.11.2"))["acknowledgement"]["key"]
        .as_str()
        .expect("key")
        .to_owned();
    let entry = home.acknowledge(&key).expect("acknowledge");
    assert_eq!(entry["entry"]["key"], key.as_str());
    let acked = home.decide(observed("18.11.2"));
    assert_eq!(acked["state"], "untested");
    assert_eq!(acked["acknowledgement"]["acknowledged"], json!(true));
    assert_eq!(
        home.decide(observed("18.11.3"))["acknowledgement"]["acknowledged"],
        json!(false)
    );

    let cleared = run(&home.request("clear")).expect("clear");
    assert_eq!(cleared, json!({ "cleared": 1 }));
    assert_eq!(
        home.decide(observed("18.11.2"))["acknowledgement"]["acknowledged"],
        json!(false)
    );
    assert_eq!(
        run(&home.request("clear")).expect("clear"),
        json!({ "cleared": 0 })
    );
}

#[test]
fn acknowledging_replaces_the_harness_entry_and_keeps_the_store_bounded() {
    let home = Home::new(&fixture());
    home.acknowledge(&"a".repeat(64)).expect("first");
    home.acknowledge(&"b".repeat(64)).expect("second");
    let guard_home = home.root.path().join("guard");
    let entries = load_acknowledgements(&guard_home);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, "b".repeat(64));
    assert!(entries[0].acknowledged_at.ends_with('Z'));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(store_path(&guard_home))
            .expect("store")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn a_corrupt_store_acknowledges_nothing() {
    let home = Home::new(&fixture());
    let guard_home = home.root.path().join("guard");
    fs::create_dir_all(&guard_home).expect("guard home");
    let valid_item = json!({ "harness": "omp", "key": "c".repeat(64), "acknowledged_at": "x" });
    for body in [
        "not json".to_owned(),
        json!({ "version": 2, "items": [valid_item] }).to_string(),
        json!({ "version": 1, "items": {} }).to_string(),
        json!({ "version": 1, "items": [{ "harness": "omp", "key": "../../etc", "acknowledged_at": "x" }] })
            .to_string(),
        " ".repeat(17 * 1024),
    ] {
        fs::write(store_path(&guard_home), &body).expect("store");
        assert!(load_acknowledgements(&guard_home).is_empty(), "{body:.40}");
    }
    fs::write(
        store_path(&guard_home),
        json!({ "version": 1, "items": [valid_item] }).to_string(),
    )
    .expect("store");
    assert_eq!(load_acknowledgements(&guard_home).len(), 1);
}

#[test]
fn malformed_requests_are_refused() {
    let home = Home::new(&fixture());
    let invalid = Err("harness_version_request_invalid".to_owned());
    assert_eq!(home.acknowledge("../../etc"), invalid);
    let mut bad_harness = home.request("acknowledge");
    bad_harness["harness"] = json!("../x");
    bad_harness["key"] = json!("a".repeat(64));
    assert_eq!(run(&bad_harness), invalid);
    let mut relative = home.request("clear");
    relative["guard_home"] = json!("guard");
    assert_eq!(run(&relative), invalid);
    assert_eq!(run(&home.request("decide")), invalid);
    assert_eq!(run(&home.request("unknown")), invalid);
    let mut extra = home.request("clear");
    extra["unexpected"] = json!(true);
    assert_eq!(run(&extra), invalid);
}

#[test]
fn observation_time_renders_like_python_isoformat() {
    assert_eq!(iso_utc_z(NOW), "2027-01-15T08:00:00Z");
    assert_eq!(iso_utc_z(NOW + 0.25), "2027-01-15T08:00:00.250000Z");
    assert_eq!(iso_utc_z(0.0), "1970-01-01T00:00:00Z");
}

#[test]
fn payload_never_names_a_path() {
    let home = Home::new(&fixture());
    let payload = home.decide(observed("18.11.2")).to_string();
    assert!(!payload.contains(&home.root.path().display().to_string()));
}
