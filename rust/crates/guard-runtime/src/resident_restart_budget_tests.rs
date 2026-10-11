use super::*;
#[cfg(windows)]
use std::fs;

#[test]
fn repeated_updates_replace_budget_without_leaving_temporary_state() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    fs::create_dir(&scope).unwrap();

    consume(&scope).unwrap();
    consume(&scope).unwrap();

    let encoded = fs::read(scope.join("restart-budget.json")).unwrap();
    let budget: RestartBudget = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(budget.schema, BUDGET_SCHEMA);
    assert_eq!(budget.attempts, 2);
    assert_eq!(
        fs::read_dir(&scope)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count(),
        0
    );

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn authenticated_stop_clears_restart_attempts() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-clear-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    std::fs::create_dir(&scope).unwrap();

    consume(&scope).unwrap();
    consume(&scope).unwrap();
    consume(&scope).unwrap();
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );
    clear(&scope).unwrap();
    consume(&scope).unwrap();

    std::fs::remove_dir_all(scope).unwrap();
}

fn temp_scope(label: &str) -> PathBuf {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    std::fs::create_dir(&scope).unwrap();
    scope
}

fn read_budget(scope: &Path) -> RestartBudget {
    serde_json::from_slice(&std::fs::read(scope.join("restart-budget.json")).unwrap()).unwrap()
}

#[test]
fn backoff_doubles_to_a_bounded_ceiling() {
    assert_eq!(backoff_ms(0), 2_000);
    assert_eq!(backoff_ms(1), 4_000);
    assert_eq!(backoff_ms(2), 8_000);
    assert_eq!(backoff_ms(4), 30_000);
    assert_eq!(backoff_ms(u32::MAX), 30_000);
}

#[test]
fn elapsed_backoff_allows_one_respawn_then_backs_off_longer() {
    let scope = temp_scope("backoff");
    for _ in 0..MAX_RESTARTS_PER_WINDOW {
        consume(&scope).unwrap();
    }
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );
    let first = read_budget(&scope);
    assert_eq!(first.backoff_steps, 1);
    assert!(first.circuit_until_ms > now_ms().unwrap());
    // While the backoff runs the respawn stays refused.
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );
    assert_eq!(read_budget(&scope).backoff_steps, 1);

    // Once the backoff has elapsed one respawn is allowed, and the next
    // refusal interval doubles instead of reusing a fixed circuit.
    let private_root = crate::resident_state::private_root_for_scope(&scope).unwrap();
    let elapsed = RestartBudget {
        circuit_until_ms: now_ms().unwrap() - 1,
        ..first
    };
    write_private(
        &scope.join("restart-budget.json"),
        &serde_json::to_vec(&elapsed).unwrap(),
        &private_root,
    )
    .unwrap();
    consume(&scope).unwrap();
    let second = read_budget(&scope);
    assert_eq!(second.backoff_steps, 2);
    assert_eq!(second.attempts, MAX_RESTARTS_PER_WINDOW + 1);
    let remaining = second.circuit_until_ms - now_ms().unwrap();
    assert!(remaining > 2_000 && remaining <= 4_000);
    assert_eq!(
        consume(&scope).unwrap_err(),
        "native_resident_restart_circuit_open"
    );

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn budget_written_before_backoff_steps_existed_is_still_valid() {
    let scope = temp_scope("legacy-budget");
    let private_root = crate::resident_state::private_root_for_scope(&scope).unwrap();
    let legacy = format!(
        "{{\"schema\":\"{BUDGET_SCHEMA}\",\"window_start_ms\":{},\"attempts\":1,\"circuit_until_ms\":0}}",
        now_ms().unwrap()
    );
    write_private(
        &scope.join("restart-budget.json"),
        legacy.as_bytes(),
        &private_root,
    )
    .unwrap();

    consume(&scope).unwrap();

    let budget = read_budget(&scope);
    assert_eq!(budget.attempts, 2);
    assert_eq!(budget.backoff_steps, 0);
    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn clear_reopens_a_tripped_circuit() {
    let scope = temp_scope("clear-circuit");
    for _ in 0..MAX_RESTARTS_PER_WINDOW {
        consume(&scope).unwrap();
    }
    assert!(consume(&scope).is_err());
    clear(&scope).unwrap();
    let budget = read_budget(&scope);
    assert_eq!(
        (
            budget.attempts,
            budget.circuit_until_ms,
            budget.backoff_steps
        ),
        (0, 0, 0)
    );
    consume(&scope).unwrap();
    std::fs::remove_dir_all(scope).unwrap();
}

#[cfg(windows)]
#[test]
fn restart_budget_lock_retains_directory_binding_until_drop() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-directory-binding-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    crate::resident_state::ensure_private_directory(&scope, true).unwrap();
    let renamed = scope.with_file_name(format!(
        "{}-renamed",
        scope.file_name().unwrap().to_string_lossy()
    ));
    let lock = acquire_budget_lock(&scope).unwrap();

    assert!(fs::rename(&scope, &renamed).is_err());

    drop(lock);
    fs::rename(&scope, &renamed).unwrap();
    fs::remove_dir_all(renamed).unwrap();
}

#[cfg(windows)]
#[test]
fn interrupted_windows_replace_restores_previous_budget() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-recovery-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    fs::create_dir(&scope).unwrap();
    consume(&scope).unwrap();
    let path = scope.join("restart-budget.json");
    let encoded = {
        let mut file =
            crate::resident_state::open_private_read(&path, 4096, "restart_budget", &scope)
                .unwrap()
                .unwrap();
        let mut encoded = Vec::new();
        file.read_to_end(&mut encoded).unwrap();
        encoded
    };
    let backup = backup_path(&path);
    let mut backup_file = crate::resident_state::private_file(&backup, true, &scope).unwrap();
    backup_file.write_all(&encoded).unwrap();
    backup_file.sync_all().unwrap();
    drop(backup_file);
    crate::resident_state::remove_windows_private_file(&path, &scope).unwrap();

    consume(&scope).unwrap();

    let budget: RestartBudget = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(budget.attempts, 2);
    fs::remove_dir_all(scope).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_budget_existence_requires_private_regular_file_handle() {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-budget-handle-check-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    crate::resident_state::ensure_private_directory(&scope, true).unwrap();
    let path = scope.join("restart-budget.json");

    assert!(!existing_private_file(&path, &scope).unwrap());
    let file = crate::resident_state::private_file(&path, true, &scope).unwrap();
    drop(file);
    assert!(existing_private_file(&path, &scope).unwrap());
    assert!(existing_private_file(&scope, &scope).is_err());

    fs::remove_dir_all(scope).unwrap();
}
