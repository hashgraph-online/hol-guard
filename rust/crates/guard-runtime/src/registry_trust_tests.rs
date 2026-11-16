use super::*;

fn home() -> tempfile::TempDir {
    tempfile::tempdir().expect("home")
}

fn lookup(home: &Path, name: &str, now: f64) -> Value {
    answer(json!({
        "op": "lookup",
        "home": home.to_str(),
        "artifact_type": "plugin",
        "name": name,
        "now": now,
    }))
    .expect("lookup")
}

fn record(home: &Path, name: &str, now: f64, status: Option<u16>, body: &[u8]) -> Value {
    answer(json!({
        "op": "record",
        "home": home.to_str(),
        "artifact_type": "plugin",
        "name": name,
        "now": now,
        "status": status,
        "body": STANDARD.encode(body),
    }))
    .expect("record")
}

fn plugins(entries: &[(&str, &str, Value)]) -> Vec<u8> {
    let plugins: Vec<Value> = entries
        .iter()
        .map(|(slug, display, score)| json!({"slug": slug, "displayName": display, "trustScore": score}))
        .collect();
    serde_json::to_vec(&json!({"plugins": plugins})).expect("body")
}

#[test]
fn an_uncached_plugin_is_fetched_by_its_stripped_name() {
    let home = home();
    assert_eq!(
        lookup(home.path(), "  github-helper ", 1000.0),
        json!({"fetch": "github-helper"})
    );
}

#[test]
fn unscored_kinds_and_unusable_names_are_never_fetched() {
    let home = home();
    for artifact_type in [
        json!("skill"),
        json!("mcp_server"),
        json!("hook"),
        Value::Null,
    ] {
        let request = json!({
            "op": "lookup",
            "home": home.path().to_str(),
            "artifact_type": artifact_type,
            "name": "helper",
            "now": 1,
        });
        assert_eq!(answer(request).expect("lookup"), json!({"score": null}));
    }
    assert_eq!(lookup(home.path(), "   ", 1.0), json!({"score": null}));
    assert_eq!(
        lookup(home.path(), &"x".repeat(257), 1.0),
        json!({"score": null})
    );
    assert_eq!(
        lookup(home.path(), &"é".repeat(256), 1.0)["fetch"],
        "é".repeat(256)
    );
}

#[test]
fn the_score_comes_from_the_exact_catalog_match() {
    let home = home();
    let body = plugins(&[
        ("acme/github-helper", "GitHub Helper", json!(61)),
        ("other/github", "GitHub", json!(94)),
    ]);
    assert_eq!(
        record(home.path(), "github-helper", 1.0, Some(200), &body),
        json!({"score": 61})
    );
    let display = plugins(&[("acme/x", "GitHub Helper", json!(60.5))]);
    assert_eq!(
        record(home.path(), "github helper", 1.0, Some(200), &display),
        json!({"score": 60})
    );
    let rounded = plugins(&[("acme/x", "Helper", json!(61.5))]);
    assert_eq!(
        record(home.path(), "acme/x", 1.0, Some(200), &rounded),
        json!({"score": 62})
    );
}

#[test]
fn unmatched_ambiguous_or_unscored_answers_have_no_score() {
    let home = home();
    let bodies = [
        plugins(&[("acme/github-helper-pro", "GitHub Helper Pro", json!(40))]),
        plugins(&[
            ("acme/helper", "Helper", json!(40)),
            ("other/helper", "helper", json!(90)),
        ]),
        plugins(&[("acme/helper", "Helper", Value::Null)]),
        plugins(&[("acme/helper", "Helper", json!(true))]),
        plugins(&[("acme/helper", "Helper", json!(101))]),
        br#"{"plugins": "nope"}"#.to_vec(),
        b"[]".to_vec(),
    ];
    for body in bodies {
        assert_eq!(
            record(home.path(), "helper", 1.0, Some(200), &body),
            json!({"score": null})
        );
    }
    let twice = plugins(&[
        ("acme/helper", "Helper", json!(40)),
        ("acme/helper", "x", json!(40)),
    ]);
    assert_eq!(
        record(home.path(), "helper", 1.0, Some(200), &twice),
        json!({"score": null})
    );
}

#[test]
fn answers_are_cached_and_transport_failures_pause_lookups_briefly() {
    let home = home();
    assert_eq!(
        record(home.path(), "helper", 1000.0, None, b""),
        json!({"score": null})
    );
    // An offline origin is not asked again for a few minutes, for any plugin.
    assert_eq!(lookup(home.path(), "other", 1100.0), json!({"score": null}));
    assert_eq!(
        lookup(home.path(), "other", 1000.0 + 6.0 * 60.0),
        json!({"fetch": "other"})
    );

    let body = plugins(&[("acme/helper", "Helper", json!(55))]);
    assert_eq!(
        record(home.path(), "helper", 1360.0, Some(200), &body),
        json!({"score": 55})
    );
    assert_eq!(lookup(home.path(), "Helper", 2000.0), json!({"score": 55}));
    assert_eq!(
        lookup(home.path(), "helper", 1360.0 + 25.0 * 3600.0),
        json!({"fetch": "helper"})
    );

    let cache: Value =
        serde_json::from_slice(&fs::read(home.path().join(CACHE_FILE_NAME)).expect("cache"))
            .expect("json");
    assert_eq!(cache["schema"], CACHE_SCHEMA);
    assert_eq!(
        cache["entries"],
        json!({"plugin:helper": {"score": 55, "checked_at": 1360.0}})
    );
}

#[test]
fn an_unscored_answer_is_kept_for_a_shorter_time() {
    let home = home();
    let body = plugins(&[]);
    assert_eq!(
        record(home.path(), "helper", 0.0, Some(200), &body),
        json!({"score": null})
    );
    assert_eq!(
        lookup(home.path(), "helper", 5.0 * 3600.0),
        json!({"score": null})
    );
    assert_eq!(
        lookup(home.path(), "helper", 6.0 * 3600.0),
        json!({"fetch": "helper"})
    );
}

#[test]
fn replies_that_are_no_answer_count_as_unreachable() {
    let home = home();
    let body = plugins(&[("acme/helper", "Helper", json!(55))]);
    let mut oversized = body.clone();
    oversized.resize(MAX_RESPONSE_BYTES + 1, b' ');
    for (status, reply) in [
        (Some(500), body.clone()),
        (Some(200), oversized),
        (Some(200), b"not json".to_vec()),
        (Some(200), b"\xff".to_vec()),
    ] {
        assert_eq!(
            record(home.path(), "helper", 10.0, status, &reply),
            json!({"score": null})
        );
        assert_eq!(lookup(home.path(), "helper", 11.0), json!({"score": null}));
    }
    let mut marked = b"\xef\xbb\xbf".to_vec();
    marked.extend_from_slice(&body);
    assert_eq!(
        record(home.path(), "helper", 20.0, Some(200), &marked),
        json!({"score": 55})
    );
}

#[test]
fn a_cache_from_the_future_or_of_another_schema_is_not_used() {
    let home = home();
    let path = home.path().join(CACHE_FILE_NAME);
    let entry = json!({"plugin:helper": {"score": 40, "checked_at": 500}});
    fs::write(
        &path,
        json!({"schema": CACHE_SCHEMA, "entries": entry}).to_string(),
    )
    .expect("cache");
    assert_eq!(
        lookup(home.path(), "helper", 400.0),
        json!({"fetch": "helper"})
    );
    assert_eq!(lookup(home.path(), "helper", 600.0), json!({"score": 40}));
    fs::write(
        &path,
        json!({"schema": "other", "entries": entry}).to_string(),
    )
    .expect("cache");
    assert_eq!(
        lookup(home.path(), "helper", 600.0),
        json!({"fetch": "helper"})
    );
    fs::write(&path, b"{").expect("cache");
    assert_eq!(
        lookup(home.path(), "helper", 600.0),
        json!({"fetch": "helper"})
    );
}

#[test]
fn the_cache_keeps_only_the_newest_entries() {
    let home = home();
    let mut entries = Map::new();
    for index in 0..MAX_CACHE_ENTRIES {
        entries.insert(
            format!("plugin:p{index}"),
            json!({"score": 1, "checked_at": index}),
        );
    }
    let document = json!({"schema": CACHE_SCHEMA, "entries": entries});
    fs::write(home.path().join(CACHE_FILE_NAME), document.to_string()).expect("cache");
    let body = plugins(&[("acme/helper", "Helper", json!(70))]);
    record(home.path(), "helper", 100_000.0, Some(200), &body);
    let cache = load_cache(Some(home.path().join(CACHE_FILE_NAME).as_path()));
    assert_eq!(cache.len(), MAX_CACHE_ENTRIES);
    assert!(cache.contains_key("plugin:helper"));
    assert!(!cache.contains_key("plugin:p0"));
}

#[test]
fn no_home_keeps_no_cache_and_a_relative_home_is_refused() {
    let request = json!({"op": "lookup", "home": null, "artifact_type": "plugin", "name": "helper", "now": 1});
    assert_eq!(answer(request).expect("lookup"), json!({"fetch": "helper"}));
    let relative = json!({"op": "lookup", "home": "guard", "artifact_type": "plugin", "name": "helper", "now": 1});
    assert_eq!(
        answer(relative),
        Err("registry_trust_home_invalid".to_owned())
    );
    let unknown =
        json!({"op": "forget", "home": null, "artifact_type": "plugin", "name": "x", "now": 1});
    assert_eq!(answer(unknown), Err(invalid()));
}

#[test]
fn the_command_names_registry_trust() {
    assert!(is_command("registry-trust"));
    assert!(!is_command("registry-trust-score"));
}
