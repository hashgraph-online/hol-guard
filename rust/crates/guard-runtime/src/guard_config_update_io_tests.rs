use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "guard-config-transaction-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn write(home: &Path, payload: Value) -> Value {
    let input = json!({"schema":"guard-config-update.v1", "guard_home":home,
        "kind":"settings", "value_text":payload.to_string()});
    serde_json::from_slice(&run_command(input.to_string().as_bytes()).unwrap()).unwrap()
}
#[test]
fn native_settings_writer_shares_a_short_bounded_lane_with_future_selection_commits() {
    let home = Scratch::new();
    let lock = WriteLock::acquire(&home.0).unwrap();
    let started = std::time::Instant::now();
    let denied = write(&home.0, json!({"telemetry":true}));
    assert_eq!(denied["error"], "config_write_busy");
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    assert!(!home.0.join(HOME_CONFIG_FILENAME).exists());
    drop(lock);
    assert_eq!(write(&home.0, json!({"telemetry":true}))["ok"], true);
    let path = home.0.join(HOME_CONFIG_FILENAME);
    assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
}
#[test]
fn stale_compare_refuses_and_leaves_the_newer_user_settings_intact() {
    let home = Scratch::new();
    let lock = WriteLock::acquire(&home.0).unwrap();
    lock.publish(None, "mode = 'enforce'\n").unwrap();
    let path = home.0.join(HOME_CONFIG_FILENAME);
    fs::write(&path, "mode = 'observe'\n").unwrap();
    assert_eq!(
        lock.publish(Some("mode = 'enforce'\n"), "mode = 'enforce'\n"),
        Err(Failure::Error("config_file_changed".into()))
    );
    assert_eq!(fs::read_to_string(path).unwrap(), "mode = 'observe'\n");
    assert_eq!(fs::read_dir(&home.0).unwrap().count(), 2);
}
#[test]
fn lock_symlinks_hardlinks_permissions_and_replacement_refuse_without_writing_config() {
    let home = Scratch::new();
    let other = Scratch::new();
    let outside = other.0.join("outside");
    fs::write(&outside, b"outside").unwrap();
    let path = home.0.join("config-write.lock");
    symlink(&outside, &path).unwrap();
    assert!(WriteLock::acquire(&home.0).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&outside, &path).unwrap();
    assert!(WriteLock::acquire(&home.0).is_err());
    fs::remove_file(&path).unwrap();
    let lock = WriteLock::acquire(&home.0).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(lock.publish(None, "mode = 'enforce'\n").is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&path).unwrap();
    drop(WriteLock::acquire(&home.0).unwrap());
    assert!(lock.publish(None, "mode = 'enforce'\n").is_err());
    assert!(!home.0.join(HOME_CONFIG_FILENAME).exists());
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
}
#[test]
fn replaced_profile_directory_and_config_links_never_redirect_a_commit() {
    let home = Scratch::new();
    let other = Scratch::new();
    let original = home.0.join("profile");
    fs::create_dir(&original).unwrap();
    let lock = WriteLock::acquire(&original).unwrap();
    fs::rename(&original, home.0.join("retained")).unwrap();
    symlink(&other.0, &original).unwrap();
    assert!(lock.publish(None, "mode = 'enforce'\n").is_err());
    assert!(!other.0.join(HOME_CONFIG_FILENAME).exists());
    let lock = WriteLock::acquire(&other.0).unwrap();
    let outside = home.0.join("outside");
    fs::write(&outside, "outside").unwrap();
    symlink(&outside, other.0.join(HOME_CONFIG_FILENAME)).unwrap();
    assert!(lock.publish(None, "mode = 'enforce'\n").is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "outside");
}
#[test]
fn uncertain_post_rename_result_is_observable_without_replaying_or_reverting_it() {
    let home = Scratch::new();
    let lock = WriteLock::acquire(&home.0).unwrap();
    unix::AFTER_RENAME_FAULT.with(|flag| flag.set(true));
    assert_eq!(
        lock.publish(None, "mode = 'enforce'\n"),
        Err(Failure::Error("config_commit_outcome_unknown".into()))
    );
    assert_eq!(
        read_home_config(&home.0).unwrap().as_deref(),
        Some("mode = 'enforce'\n")
    );
    assert_eq!(fs::read_dir(&home.0).unwrap().count(), 2);
}
#[test]
fn stopping_preserves_the_latest_selected_runtime_and_source_preferences() {
    let home = Scratch::new();
    let original = "mode = 'enforce'\n[context_assistance]\nenabled = true\nruntime_id = 'candidate:kept'\n[context_assistance.sources]\nworkspace_documents = true\nsource_set_id = 'source:kept'\n[context_assistance.storage]\nmode = 'sqlite'\nretention_hours = 48\n";
    fs::write(home.0.join(HOME_CONFIG_FILENAME), original).unwrap();
    let lock = WriteLock::acquire(&home.0).unwrap();
    assert!(disable_context_assistance(&home.0).is_err());
    assert_eq!(
        read_home_config(&home.0).unwrap().as_deref(),
        Some(original)
    );
    drop(lock);
    disable_context_assistance(&home.0).unwrap();
    let current = assistance_preferences(&read_home_config(&home.0).unwrap().unwrap()).unwrap();
    assert!(!current.enabled);
    assert_eq!(current.runtime_id, "candidate:kept");
    assert!(current.sources.workspace_documents);
    assert_eq!(current.storage.retention_hours, 48);
}

#[test]
fn a_new_writer_recovers_only_its_private_reserved_orphan_staging() {
    let home = Scratch::new();
    let staged = home
        .0
        .join(format!(".config.toml.123.{}.tmp", "a".repeat(32)));
    fs::write(&staged, b"interrupted private settings").unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
    let unrelated = home.0.join(".config.toml.user-note.tmp");
    fs::write(&unrelated, b"keep").unwrap();
    drop(WriteLock::acquire(&home.0).unwrap());
    assert!(!staged.exists());
    assert_eq!(fs::read(&unrelated).unwrap(), b"keep");
    let outside = home.0.join("outside");
    fs::write(&outside, b"keep outside").unwrap();
    symlink(&outside, &staged).unwrap();
    assert!(WriteLock::acquire(&home.0).is_err());
    assert!(fs::symlink_metadata(&staged)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&outside).unwrap(), b"keep outside");
}
#[test]
fn orphan_staging_capacity_refuses_before_removing_any_ambiguous_batch() {
    let home = Scratch::new();
    for n in 0..33 {
        let path = home.0.join(format!(".config.toml.123.{n:032x}.tmp"));
        fs::write(&path, b"bounded abandoned write").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(WriteLock::acquire(&home.0).is_err());
    assert_eq!(fs::read_dir(&home.0).unwrap().count(), 34);
}

#[test]
fn atomic_replacement_preserves_an_existing_read_only_config_refusal() {
    let home = Scratch::new();
    let path = home.0.join(HOME_CONFIG_FILENAME);
    let text = "mode = 'observe'\n";
    fs::write(&path, text).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let lock = WriteLock::acquire(&home.0).unwrap();
    assert_eq!(
        lock.publish(Some(text), "mode = 'enforce'\n"),
        Err(Failure::Error("config_file_not_writable".into()))
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), text);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert_eq!(fs::read_dir(&home.0).unwrap().count(), 2);
}
