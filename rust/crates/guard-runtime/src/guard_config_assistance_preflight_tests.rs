//! Native publication races, intent ordering and short-lock invariants. No SDK
//! is needed for these settings/CAS cases; real enrollment is separate.
use super::*;
use std::os::unix::fs::PermissionsExt;
fn home() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    t
}
fn request(home: &Path, value: Value) -> Value {
    let request = json!({"schema":"guard-config-update.v1","guard_home":home,"kind":"settings","value_text":value.to_string()});
    serde_json::from_slice(&run_command(request.to_string().as_bytes()).unwrap()).unwrap()
}
#[test]
fn ordinary_settings_prepare_without_owning_the_short_writer_lock() {
    let t = home();
    fs::write(t.path().join("config.toml"), "mode='prompt'\n").unwrap();
    let path = t.path().to_path_buf();
    let result = with_publication_hook(
        move || {
            let _lock = io::WriteLock::acquire(&path)
                .expect("preflight must not hold the config writer lock");
        },
        || request(t.path(), json!({"desktop_notifications":false})),
    );
    assert_eq!(result["ok"], true, "{result}");
}
#[test]
fn another_clients_edit_is_preserved_instead_of_replayed_over_it() {
    let t = home();
    fs::write(t.path().join("config.toml"), "mode='prompt'\n").unwrap();
    let path = t.path().to_path_buf();
    let result = with_publication_hook(
        move || {
            assert_eq!(
                request(&path, json!({"desktop_notifications":false}))["ok"],
                true
            );
        },
        || request(t.path(), json!({"approval_wait_timeout_seconds":123})),
    );
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"], "config_file_changed");
    let raw = read_home_config(t.path()).unwrap().unwrap();
    let value: toml::Value = raw.parse().unwrap();
    assert_eq!(value["desktop_notifications"].as_bool(), Some(false));
    assert!(value.get("approval_wait_timeout_seconds").is_none());
}
#[test]
fn stop_while_already_off_changes_the_fence_and_rejects_an_older_prepared_write() {
    let t = home();
    fs::write(
        t.path().join("config.toml"),
        "mode='enforce'\n[context_assistance]\nenabled=false\n",
    )
    .unwrap();
    disable_context_assistance(t.path()).unwrap();
    let before = read_home_config(t.path()).unwrap().unwrap();
    let path = t.path().to_path_buf();
    let result = with_publication_hook(
        move || {
            disable_context_assistance(&path).unwrap();
        },
        || request(t.path(), json!({"desktop_notifications":false})),
    );
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"], "config_file_changed");
    let after = read_home_config(t.path()).unwrap().unwrap();
    assert_ne!(before, after);
    assert_eq!(
        assistance_preferences(&before).unwrap(),
        assistance_preferences(&after).unwrap()
    );
    assert!(!assistance_preferences(&after).unwrap().enabled);
    let effective = |text: &str| {
        let table: toml::Table = text.parse().unwrap();
        let value = serde_json::to_value(table).unwrap();
        current_config(value.as_object().unwrap(), None)
    };
    assert_eq!(
        effective(&before),
        effective(&after),
        "the ordering marker changes no effective Guard or runtime preference"
    );
    let v: toml::Value = after.parse().unwrap();
    assert!(v["context_assistance_intent_revision"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(v["mode"].as_str(), Some("enforce"));
}
#[test]
fn intent_fence_needs_no_counter_reset_and_cannot_be_set_by_payload() {
    let t = home();
    fs::write(t.path().join("config.toml"),"mode='enforce'\ncontext_assistance_intent_revision='malformed-or-old'\n[context_assistance]\nenabled=false\n").unwrap();
    disable_context_assistance(t.path()).unwrap();
    let first = read_home_config(t.path()).unwrap().unwrap();
    let result = request(
        t.path(),
        json!({"context_assistance_intent_revision":"caller-controlled"}),
    );
    assert_eq!(result["ok"], true);
    let unchanged = read_home_config(t.path()).unwrap().unwrap();
    let a: toml::Value = first.parse().unwrap();
    let b: toml::Value = unchanged.parse().unwrap();
    assert_eq!(
        a["context_assistance_intent_revision"],
        b["context_assistance_intent_revision"]
    );
    disable_context_assistance(t.path()).unwrap();
    let second = read_home_config(t.path()).unwrap().unwrap();
    assert_ne!(first, second);
    assert!(!assistance_preferences(&second).unwrap().enabled);
}
#[test]
fn replacing_the_home_during_preflight_cannot_redirect_the_write() {
    let t = home();
    let path = t.path().join("profile");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path.join("config.toml"), "mode='prompt'\n").unwrap();
    let captured = path.clone();
    let moved = t.path().join("moved-profile");
    let old = moved.clone();
    let result = with_publication_hook(
        move || {
            fs::rename(&captured, &moved).unwrap();
            fs::create_dir(&captured).unwrap();
            fs::set_permissions(&captured, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(captured.join("config.toml"), "mode='prompt'\n").unwrap();
        },
        || request(&path, json!({"desktop_notifications":false})),
    );
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"], "config_directory_changed");
    assert_eq!(
        fs::read_to_string(path.join("config.toml")).unwrap(),
        "mode='prompt'\n"
    );
    assert_eq!(
        fs::read_to_string(old.join("config.toml")).unwrap(),
        "mode='prompt'\n"
    );
}

#[test]
fn ordinary_settings_cannot_replace_a_selected_sdk_in_any_enablement_combination() {
    for before_enabled in [false, true] {
        for after_enabled in [false, true] {
            let t = home();
            let before = format!("mode='enforce'\n[context_assistance]\nenabled={before_enabled}\nruntime_id='source'\n");
            fs::write(t.path().join("config.toml"), &before).unwrap();
            let result = request(
                t.path(),
                json!({"desktop_notifications":false,
                "context_assistance":{"enabled":after_enabled,"runtime_id":"different-target"}}),
            );
            assert_eq!(result["ok"], false, "{result}");
            assert_eq!(result["error"], "native_context_assistance_switch_required");
            assert!(result["invalid"]
                .as_str()
                .unwrap()
                .contains("Prepare and commit a CIGAR switch"));
            assert_eq!(
                read_home_config(t.path()).unwrap().as_deref(),
                Some(before.as_str())
            );
            assert!(!t.path().join("context-assistance").exists());
        }
    }
}

#[test]
fn the_selection_guard_preserves_same_id_edits_and_explicit_opt_out() {
    let t = home();
    fs::write(
        t.path().join("config.toml"),
        "mode='enforce'\n[context_assistance]\nenabled=false\nruntime_id='source'\n",
    )
    .unwrap();
    let answer = request(
        t.path(),
        json!({"context_assistance":{"enabled":false,"runtime_id":"source",
        "storage":{"mode":"sqlite","retention_hours":12}}}),
    );
    assert_eq!(answer["ok"], true, "{answer}");
    let selected = assistance_preferences(&read_home_config(t.path()).unwrap().unwrap()).unwrap();
    assert_eq!(selected.runtime_id, "source");
    assert_eq!(selected.storage.retention_hours, 12);
    assert!(!selected.enabled);
    let cleared = request(t.path(), json!({"context_assistance":null}));
    assert_eq!(cleared["ok"], true, "{cleared}");
    assert!(
        !assistance_preferences(&read_home_config(t.path()).unwrap().unwrap())
            .unwrap()
            .enabled
    );
}
