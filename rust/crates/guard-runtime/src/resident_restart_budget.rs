use serde::{Deserialize, Serialize};
use std::fs::File;
#[cfg(not(windows))]
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const RESTART_WINDOW_MS: u64 = 60_000;
const RESTART_CIRCUIT_MS: u64 = 30_000;
const MAX_RESTARTS_PER_WINDOW: u32 = 3;
const BUDGET_SCHEMA: &str = "hol-guard-resident-restart-budget.v1";
const BUDGET_LOCK_FILE: &str = "restart-budget.lock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartBudget {
    schema: String,
    window_start_ms: u64,
    attempts: u32,
    circuit_until_ms: u64,
}

struct RestartBudgetLock {
    file: File,
    #[cfg(windows)]
    _directory_binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

impl Drop for RestartBudgetLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn acquire_budget_lock(scope: &Path) -> Result<RestartBudgetLock, String> {
    let path = scope.join(BUDGET_LOCK_FILE);
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    #[cfg(windows)]
    let (file, directory_binding) = crate::resident_state::private_lock_file(&path, &private_root)
        .map_err(|_| "native_resident_restart_budget_lock_failed".to_owned())?;
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, &private_root)
        .map_err(|_| "native_resident_restart_budget_lock_failed".to_owned())?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            "native_resident_restart_budget_busy".to_owned()
        } else {
            "native_resident_restart_budget_lock_failed".to_owned()
        }
    })?;
    Ok(RestartBudgetLock {
        file,
        #[cfg(windows)]
        _directory_binding: directory_binding,
    })
}

fn now_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "native_resident_clock_invalid".to_owned())?
            .as_millis(),
    )
    .map_err(|_| "native_resident_clock_invalid".to_owned())
}

fn write_private(path: &Path, bytes: &[u8], private_root: &Path) -> Result<(), String> {
    let temporary = temporary_path(path)?;
    if existing_private_file(&temporary, private_root)? {
        #[cfg(windows)]
        crate::resident_state::remove_windows_private_file(&temporary, private_root)
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
        #[cfg(not(windows))]
        fs::remove_file(&temporary)
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    }
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    let mut file = crate::resident_state::private_file(&temporary, true, private_root)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    #[cfg(not(windows))]
    let mut file = options
        .open(&temporary)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned());
    drop(file);
    if write_result.is_err() {
        #[cfg(windows)]
        let _ = crate::resident_state::remove_windows_private_file(&temporary, private_root);
        #[cfg(not(windows))]
        let _ = fs::remove_file(&temporary);
        return write_result;
    }
    let replace_result = replace_temporary(&temporary, path, private_root);
    if replace_result.is_err() {
        #[cfg(windows)]
        let _ = crate::resident_state::remove_windows_private_file(&temporary, private_root);
        #[cfg(not(windows))]
        let _ = fs::remove_file(&temporary);
        return replace_result;
    }
    #[cfg(unix)]
    File::open(
        path.parent()
            .ok_or_else(|| "native_resident_restart_budget_write_failed".to_owned())?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    Ok(())
}

fn existing_private_file(path: &Path, private_root: &Path) -> Result<bool, String> {
    #[cfg(not(windows))]
    let _ = private_root;

    #[cfg(windows)]
    {
        // Existence and type are established by one validated handle.  Do
        // not use pathname metadata here: a same-name replacement between a
        // stat and the subsequent open must never be treated as our budget
        // file, and foreign-owner/reparse objects must fail closed.
        crate::resident_state::open_private_read(path, 4096, "restart_budget", private_root)
            .map(|file| file.is_some())
            .map_err(|_| "native_resident_restart_budget_invalid".to_owned())
    }

    #[cfg(not(windows))]
    {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err("native_resident_restart_budget_stat_failed".to_owned()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
            return Err("native_resident_restart_budget_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let owner = path
                .parent()
                .and_then(|parent| fs::symlink_metadata(parent).ok())
                .map(|parent| parent.uid());
            if owner != Some(metadata.uid()) || metadata.permissions().mode() & 0o077 != 0 {
                return Err("native_resident_restart_budget_invalid".to_owned());
            }
        }
        Ok(true)
    }
}

#[cfg(not(windows))]
fn replace_temporary(temporary: &Path, path: &Path, _private_root: &Path) -> Result<(), String> {
    fs::rename(temporary, path).map_err(|_| {
        let _ = fs::remove_file(temporary);
        "native_resident_restart_budget_write_failed".to_owned()
    })
}

#[cfg(windows)]
fn replace_temporary(temporary: &Path, path: &Path, private_root: &Path) -> Result<(), String> {
    crate::resident_state::replace_windows_private_file(temporary, path, private_root)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())
}

#[cfg(windows)]
fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("json.previous")
}

#[cfg(windows)]
fn recover_interrupted_replace(path: &Path, private_root: &Path) -> Result<(), String> {
    let backup = backup_path(path);
    let path_exists = existing_private_file(path, private_root)
        .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    let backup_exists = existing_private_file(&backup, private_root)
        .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    match (path_exists, backup_exists) {
        (false, true) => {
            crate::resident_state::replace_windows_private_file(&backup, path, private_root)
                .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())
        }
        (true, true) => crate::resident_state::remove_windows_private_file(&backup, private_root)
            .map(|_| ())
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned()),
        _ => Ok(()),
    }
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "native_resident_restart_budget_write_failed".to_owned())?;
    Ok(path.with_file_name(format!(".{name}.{}.tmp", std::process::id())))
}

pub(super) fn consume(scope: &Path) -> Result<(), String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = acquire_budget_lock(scope)?;
    let path = scope.join("restart-budget.json");
    #[cfg(windows)]
    recover_interrupted_replace(&path, &private_root)?;
    let now = now_ms()?;
    let budget_exists = existing_private_file(&path, &private_root)?;
    let mut budget = if budget_exists {
        let mut bytes = Vec::new();
        let file = {
            #[cfg(windows)]
            {
                crate::resident_state::open_private_read(
                    &path,
                    4096,
                    "restart_budget",
                    &private_root,
                )?
                .ok_or_else(|| "native_resident_restart_budget_read_failed".to_owned())?
            }
            #[cfg(not(windows))]
            {
                let mut options = OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
                }
                options
                    .open(&path)
                    .map_err(|_| "native_resident_restart_budget_read_failed".to_owned())?
            }
        };
        let metadata = file
            .metadata()
            .map_err(|_| "native_resident_restart_budget_stat_failed".to_owned())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
            return Err("native_resident_restart_budget_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let path_metadata = fs::symlink_metadata(&path)
                .map_err(|_| "native_resident_restart_budget_stat_failed".to_owned())?;
            if path_metadata.file_type().is_symlink()
                || !path_metadata.is_file()
                || path_metadata.dev() != metadata.dev()
                || path_metadata.ino() != metadata.ino()
                || metadata.nlink() != 1
                || path
                    .parent()
                    .and_then(|parent| fs::symlink_metadata(parent).ok())
                    .map(|parent| parent.uid())
                    != Some(metadata.uid())
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err("native_resident_restart_budget_invalid".to_owned());
            }
        }
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "native_resident_restart_budget_read_failed".to_owned())?;
        let value = crate::strict_json_value(&bytes)
            .map_err(|_| "native_resident_restart_budget_invalid".to_owned())?;
        serde_json::from_value::<RestartBudget>(value)
            .map_err(|_| "native_resident_restart_budget_invalid".to_owned())?
    } else {
        RestartBudget {
            schema: BUDGET_SCHEMA.to_owned(),
            window_start_ms: now,
            attempts: 0,
            circuit_until_ms: 0,
        }
    };
    if budget.schema != BUDGET_SCHEMA {
        return Err("native_resident_restart_budget_invalid".to_owned());
    }
    if budget.circuit_until_ms > now {
        return Err("native_resident_restart_circuit_open".to_owned());
    }
    if now.saturating_sub(budget.window_start_ms) >= RESTART_WINDOW_MS {
        budget.window_start_ms = now;
        budget.attempts = 0;
        budget.circuit_until_ms = 0;
    }
    if budget.attempts >= MAX_RESTARTS_PER_WINDOW {
        budget.circuit_until_ms = now.saturating_add(RESTART_CIRCUIT_MS);
        let encoded = serde_json::to_vec(&budget)
            .map_err(|_| "native_resident_restart_budget_encode_failed".to_owned())?;
        write_private(&path, &encoded, &private_root)?;
        return Err("native_resident_restart_circuit_open".to_owned());
    }
    budget.attempts += 1;
    let encoded = serde_json::to_vec(&budget)
        .map_err(|_| "native_resident_restart_budget_encode_failed".to_owned())?;
    write_private(&path, &encoded, &private_root)
}

#[cfg(test)]
mod tests {
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
}
