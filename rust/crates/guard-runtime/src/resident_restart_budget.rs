use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const RESTART_WINDOW_MS: u64 = 60_000;
const RESTART_CIRCUIT_MS: u64 = 30_000;
const MAX_RESTARTS_PER_WINDOW: u32 = 3;
const BUDGET_SCHEMA: &str = "hol-guard-resident-restart-budget.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartBudget {
    schema: String,
    window_start_ms: u64,
    attempts: u32,
    circuit_until_ms: u64,
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

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = temporary_path(path)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned());
    drop(file);
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
        return write_result;
    }
    fs::rename(&temporary, path).map_err(|_| {
        let _ = fs::remove_file(&temporary);
        "native_resident_restart_budget_write_failed".to_owned()
    })?;
    #[cfg(unix)]
    File::open(
        path.parent()
            .ok_or_else(|| "native_resident_restart_budget_write_failed".to_owned())?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    Ok(())
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "native_resident_restart_budget_write_failed".to_owned())?;
    Ok(path.with_file_name(format!(".{name}.{}.tmp", std::process::id())))
}

pub(super) fn consume(scope: &Path) -> Result<(), String> {
    let path = scope.join("restart-budget.json");
    let now = now_ms()?;
    let mut budget = if path.exists() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "native_resident_restart_budget_stat_failed".to_owned())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
            return Err("native_resident_restart_budget_invalid".to_owned());
        }
        let mut bytes = Vec::new();
        File::open(&path)
            .and_then(|file| file.take(4097).read_to_end(&mut bytes))
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
        write_private(&path, &encoded)?;
        return Err("native_resident_restart_circuit_open".to_owned());
    }
    budget.attempts += 1;
    let encoded = serde_json::to_vec(&budget)
        .map_err(|_| "native_resident_restart_budget_encode_failed".to_owned())?;
    write_private(&path, &encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
