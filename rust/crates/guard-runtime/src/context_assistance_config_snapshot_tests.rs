//! Deterministic native control regression for transient configuration snapshots.
use super::*;
use crate::guard_config_load::with_changed_reads;
use std::os::unix::fs::PermissionsExt;

#[test]
fn metadata_polling_retries_only_a_changed_snapshot_without_revoking_the_generation() {
    let f = Fixture::new();
    let initial = f.ask("status");
    let generation = initial["payload"]["state"]["generation"].clone();
    // Provision a real file; missing-file defaults are metadata-only and do
    // not invoke the descriptor reader or its simulated Changed condition.
    std::fs::write(
        f.home.join("config.toml"),
        "# unchanged disabled preferences\n",
    )
    .unwrap();
    for action in ["status", "versions"] {
        let input = if action == "versions" {
            json!({"action":"jobs"})
        } else {
            json!({})
        };
        let answer = with_changed_reads(1, || f.ask_input(action, input));
        assert_eq!(answer["status"], "ok", "{answer}");
        assert_eq!(answer["payload"]["state"]["generation"], generation);
        assert!(answer["payload"]["state"]["diagnostic"].is_null());
        assert!(answer["payload"]["state"]["runtime"].is_null());
    }
    assert!(!f.home.join("context-assistance").exists());
}
#[test]
fn an_exhausted_changed_snapshot_or_real_invalid_file_still_revokes_optional_context() {
    let f = Fixture::new();
    let path = f.home.join("config.toml");
    std::fs::write(&path, "# valid disabled configuration\n").unwrap();
    let before = f.ask("status")["payload"]["state"]["generation"].clone();
    let answer = with_changed_reads(3, || f.ask("status"));
    assert_eq!(
        answer["code"],
        "native_context_assistance_configuration_unavailable"
    );
    assert_ne!(
        f.store.context_assistance().status().unwrap()["generation"],
        before
    );
    for invalid in ["malformed", "unreadable", "symlink", "hardlink"] {
        std::fs::write(
            &path,
            if invalid == "malformed" {
                "[broken\n"
            } else {
                "# valid\n"
            },
        )
        .unwrap();
        let other = f.home.join("original-config.toml");
        if invalid == "unreadable" {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        } else if invalid == "symlink" {
            std::fs::rename(&path, &other).unwrap();
            std::os::unix::fs::symlink(&other, &path).unwrap();
        } else if invalid == "hardlink" {
            std::fs::hard_link(&path, &other).unwrap();
        }
        let answer = f.ask("status");
        assert_eq!(
            answer["code"], "native_context_assistance_configuration_unavailable",
            "{invalid}: {answer}"
        );
        assert!(f.store.context_assistance().status().unwrap()["runtime"].is_null());
        if invalid == "unreadable" {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        } else if invalid == "symlink" {
            std::fs::remove_file(&path).unwrap();
            std::fs::rename(&other, &path).unwrap();
        } else if invalid == "hardlink" {
            std::fs::remove_file(&other).unwrap();
        }
    }
}
#[test]
fn retrying_a_snapshot_observes_a_later_stop_without_restoring_earlier_opt_in() {
    let f = Fixture::new();
    std::fs::write(
        f.home.join("config.toml"),
        "[context_assistance]\nenabled=true\nruntime_id='selected-but-not-started'\n",
    )
    .unwrap();
    assert_eq!(
        f.ask("status")["payload"]["state"]["requested_enabled"],
        true
    );
    let stopped = with_changed_reads(2, || f.ask("stop"));
    assert_eq!(stopped["status"], "ok", "{stopped}");
    assert_eq!(stopped["payload"]["state"]["requested_enabled"], false);
    assert_eq!(stopped["payload"]["state"]["effective_enabled"], false);
    assert!(stopped["payload"]["state"]["runtime"].is_null());
    assert!(
        !crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .enabled
    );
}
