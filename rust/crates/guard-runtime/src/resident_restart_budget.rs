use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
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
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())
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
