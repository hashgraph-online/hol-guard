//! The weekly plugin install report and its consent state.
//!
//! Counts are off until the user runs `hol-guard telemetry plugins on`. The
//! consent file and the device key live in the Guard home; the key only keys
//! the weekly counting hashes and never leaves the machine. Turning counts
//! off deletes it, so turning them on again starts a new, unlinkable series.
//!
//! A sender holds `plugin-telemetry-send.lock` for the whole send, so two
//! senders never both send one week, and records the week only after the
//! report is accepted. The operating system drops that lock when a sender
//! exits, so a send that is interrupted or killed leaves the week due.
//! `plugin-telemetry.lock` guards only the state files and is never held
//! across a network call.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::plugin_telemetry_host::{self as host, Hol};

const SETTINGS_FILE: &str = "plugin-telemetry.json";
const SECRET_FILE: &str = "plugin-telemetry.key";
const LOCK_FILE: &str = "plugin-telemetry.lock";
const SEND_LOCK_FILE: &str = "plugin-telemetry-send.lock";
const SECRET_BYTES: usize = 32;
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(50);
/// `report.entries[*].via` for a listing `plugin install --apply` installed.
const VIA_GUARD: &str = "hol-guard";

pub(crate) const OFF_MESSAGE: &str =
    "Plugin install counts are off. Run: hol-guard telemetry plugins on";
pub(crate) const BUSY_MESSAGE: &str =
    "Another Guard process is sending the report. Try again shortly.";
const STATE_BUSY_MESSAGE: &str = "The plugin telemetry settings are in use. Try again shortly.";
const STATE_UNWRITABLE_MESSAGE: &str = "The plugin telemetry settings could not be saved.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct State {
    pub(crate) enabled: bool,
    pub(crate) last_week: Option<String>,
}

enum LockError {
    Busy,
    Unwritable,
}

/// Runs `work` holding the state lock, waiting up to ten seconds for it.
fn with_state_lock<T>(
    guard_home: &Path,
    work: impl FnOnce() -> Result<T, String>,
) -> Result<T, LockError> {
    fs::create_dir_all(guard_home).map_err(|_| LockError::Unwritable)?;
    let lock = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(guard_home.join(LOCK_FILE))
        .map_err(|_| LockError::Unwritable)?;
    let deadline = Instant::now() + LOCK_WAIT;
    while fs2::FileExt::try_lock_exclusive(&lock).is_err() {
        if Instant::now() >= deadline {
            return Err(LockError::Busy);
        }
        std::thread::sleep(LOCK_POLL);
    }
    let result = work();
    let _ = fs2::FileExt::unlock(&lock);
    result.map_err(|_| LockError::Unwritable)
}

fn locked<T>(guard_home: &Path, work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    with_state_lock(guard_home, work).map_err(|error| match error {
        LockError::Busy => STATE_BUSY_MESSAGE.to_owned(),
        LockError::Unwritable => STATE_UNWRITABLE_MESSAGE.to_owned(),
    })
}

/// Consent and the last claimed week. Anything unreadable counts as off.
pub(crate) fn read_state(guard_home: &Path) -> State {
    let off = State {
        enabled: false,
        last_week: None,
    };
    let Ok(text) = fs::read_to_string(guard_home.join(SETTINGS_FILE)) else {
        return off;
    };
    let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(&text) else {
        return off;
    };
    State {
        enabled: payload.get("enabled") == Some(&Value::Bool(true)),
        last_week: payload
            .get("lastWeek")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

fn write_state(guard_home: &Path, state: &State) -> Result<(), String> {
    let unwritable = |_| STATE_UNWRITABLE_MESSAGE.to_owned();
    fs::create_dir_all(guard_home).map_err(unwritable)?;
    let temporary = guard_home.join(format!("{SETTINGS_FILE}.tmp"));
    let text = json!({"enabled": state.enabled, "lastWeek": state.last_week}).to_string();
    fs::write(&temporary, text).map_err(unwritable)?;
    fs::rename(&temporary, guard_home.join(SETTINGS_FILE)).map_err(unwritable)
}

/// The hex device key, or `None` when there is no valid one.
pub(crate) fn read_secret(guard_home: &Path) -> Option<String> {
    let text = fs::read_to_string(guard_home.join(SECRET_FILE)).ok()?;
    let value = text.trim();
    let valid = value.len() == SECRET_BYTES * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    valid.then(|| value.to_owned())
}

fn random_hex() -> Result<String, String> {
    let mut bytes = [0_u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| STATE_UNWRITABLE_MESSAGE.to_owned())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn create_owner_only(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// The device key, created owner-only when missing. Callers hold the state
/// lock. Only an invalid key file is replaced; a key another process created
/// first wins.
fn ensure_secret(guard_home: &Path) -> Result<String, String> {
    if let Some(existing) = read_secret(guard_home) {
        return Ok(existing);
    }
    let unwritable = |_| STATE_UNWRITABLE_MESSAGE.to_owned();
    fs::create_dir_all(guard_home).map_err(unwritable)?;
    let target = guard_home.join(SECRET_FILE);
    if fs::symlink_metadata(&target).is_ok() {
        fs::remove_file(&target).map_err(unwritable)?;
    }
    let value = random_hex()?;
    match create_owner_only(&target) {
        Ok(mut file) => {
            file.write_all(value.as_bytes()).map_err(unwritable)?;
            Ok(value)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_secret(guard_home).ok_or_else(|| STATE_UNWRITABLE_MESSAGE.to_owned())
        }
        Err(_) => Err(STATE_UNWRITABLE_MESSAGE.to_owned()),
    }
}

pub(crate) fn turn_on(guard_home: &Path) -> Result<(), String> {
    locked(guard_home, || {
        ensure_secret(guard_home)?;
        let last_week = read_state(guard_home).last_week;
        write_state(
            guard_home,
            &State {
                enabled: true,
                last_week,
            },
        )
    })
}

pub(crate) fn turn_off(guard_home: &Path) -> Result<(), String> {
    locked(guard_home, || {
        write_state(
            guard_home,
            &State {
                enabled: false,
                last_week: None,
            },
        )?;
        match fs::remove_file(guard_home.join(SECRET_FILE)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(STATE_UNWRITABLE_MESSAGE.to_owned())
            }
            _ => Ok(()),
        }
    })
}

/// Held for a whole send. Dropping it, or the sender exiting, frees it.
struct SendLock(File);

impl Drop for SendLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

/// The send lock, or `None` while another sender holds it.
fn try_send_lock(guard_home: &Path) -> Result<Option<SendLock>, String> {
    fs::create_dir_all(guard_home).map_err(|_| STATE_UNWRITABLE_MESSAGE.to_owned())?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(guard_home.join(SEND_LOCK_FILE))
        .map_err(|_| STATE_UNWRITABLE_MESSAGE.to_owned())?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(Some(SendLock(file))),
        Err(_) => Ok(None),
    }
}

/// Records `week` as sent, unless counts were turned off meanwhile.
fn record_week(guard_home: &Path, week: &str) {
    let _ = with_state_lock(guard_home, || {
        if read_state(guard_home).enabled {
            write_state(
                guard_home,
                &State {
                    enabled: true,
                    last_week: Some(week.to_owned()),
                },
            )?;
        }
        Ok(())
    });
}

/// `YYYY-Www`, the ISO week of the current UTC date.
pub(crate) fn current_week() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    iso_week(seconds.div_euclid(86_400))
}

/// The ISO week of the UTC date `days` after 1970-01-01.
pub(crate) fn iso_week(days: i64) -> String {
    // 1970-01-01 was a Thursday; ISO weekdays run Monday 1 to Sunday 7.
    let weekday = (days + 3).rem_euclid(7) + 1;
    let thursday = days - weekday + 4;
    let (year, _, _) = civil_from_days(thursday);
    let week = (thursday - days_from_civil(year, 1, 1)) / 7 + 1;
    format!("{year}-W{week:02}")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `{"installed": n, "report": {...}}` for this machine and week.
fn build_report(hol: &dyn Hol, home: &Path, secret: &str, week: &str) -> Result<Value, String> {
    let homes = host::runtime_homes(hol, home);
    let index = host::installed_index(host::plugin_index(hol)?, &homes)?;
    host::native_request(&json!({
        "command": "report",
        "homes": homes,
        "index": index,
        "secret": secret,
        "week": week,
        "guardVersion": crate::daemon_edge::package_version(),
    }))
}

/// Tags the report entries for listings `plugin install --apply` installed.
/// Without a readable install record nothing is tagged.
pub(crate) fn mark_guard_installs(report: &mut Value, guard_home: &Path) {
    let request = json!({"command": "installs", "guard_home": guard_home.to_string_lossy()});
    let response = guard_plugin_kit::run_request(request.to_string().as_bytes());
    if response.get("ok") != Some(&Value::Bool(true)) {
        return;
    }
    let Some(Value::Object(installs)) = response.get("result") else {
        return;
    };
    let Some(Value::Array(entries)) = report.get_mut("entries") else {
        return;
    };
    for entry in entries.iter_mut() {
        let Value::Object(fields) = entry else {
            continue;
        };
        let slug = fields.get("slug").map(text_of).unwrap_or_default();
        let installed_here = match (installs.get(&slug), fields.get("runtime")) {
            (Some(Value::Array(runtimes)), Some(Value::String(runtime))) => runtimes
                .iter()
                .any(|item| item.as_str() == Some(runtime.as_str())),
            _ => false,
        };
        if installed_here {
            fields.insert("via".to_owned(), Value::String(VIA_GUARD.to_owned()));
        }
    }
}

/// Python's `str()` of a JSON value, enough to look a slug up.
fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The report Guard would send this week, built without sending it. Before
/// opt-in there is no device key, so the counting keys use a throwaway one.
pub(crate) fn dry_run(
    hol: &dyn Hol,
    guard_home: &Path,
    home: &Path,
    week: &str,
) -> Result<Value, String> {
    let secret = match read_secret(guard_home) {
        Some(secret) => secret,
        None => random_hex()?,
    };
    let mut built = build_report(hol, home, &secret, week)?;
    if let Some(report @ Value::Object(_)) = built.get_mut("report") {
        mark_guard_installs(report, guard_home);
    }
    Ok(built)
}

fn send_claimed(
    hol: &dyn Hol,
    guard_home: &Path,
    home: &Path,
    week: &str,
) -> Result<Value, String> {
    let secret = read_secret(guard_home).ok_or_else(|| OFF_MESSAGE.to_owned())?;
    let built = build_report(hol, home, &secret, week)?;
    let mut report = built.get("report").cloned().unwrap_or(Value::Null);
    mark_guard_installs(&mut report, guard_home);
    let listed = report
        .get("entries")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    // Counts can be turned off while the index downloads and the report builds.
    // A key reset in the meantime must not ship a report keyed to the old one.
    if !read_state(guard_home).enabled
        || read_secret(guard_home).as_deref() != Some(secret.as_str())
    {
        return Err(OFF_MESSAGE.to_owned());
    }
    let accepted = if listed > 0 {
        hol.post_report(&report)?
    } else {
        0
    };
    Ok(json!({
        "week": week,
        "installed": built.get("installed").cloned().unwrap_or(json!(0)),
        "listed": listed,
        "accepted": accepted,
    }))
}

fn send_and_record(
    hol: &dyn Hol,
    guard_home: &Path,
    home: &Path,
    week: &str,
) -> Result<Value, String> {
    let answer = send_claimed(hol, guard_home, home, week)?;
    record_week(guard_home, week);
    Ok(answer)
}

/// Sends this week's report now. Requires opt-in; records the week on
/// success.
pub(crate) fn send_now(
    hol: &dyn Hol,
    guard_home: &Path,
    home: &Path,
    week: &str,
) -> Result<Value, String> {
    let Some(_lock) = try_send_lock(guard_home)? else {
        return Err(BUSY_MESSAGE.to_owned());
    };
    if !read_state(guard_home).enabled {
        return Err(OFF_MESSAGE.to_owned());
    }
    send_and_record(hol, guard_home, home, week)
}

/// Sends at most one report per ISO week, and only after opt-in. `Ok(None)`
/// when nothing was due.
pub(crate) fn send_if_due(
    hol: &dyn Hol,
    guard_home: &Path,
    home: &Path,
    week: &str,
) -> Result<Option<Value>, String> {
    let due = |state: &State| state.enabled && state.last_week.as_deref() != Some(week);
    if !due(&read_state(guard_home)) {
        return Ok(None);
    }
    let Some(_lock) = try_send_lock(guard_home)? else {
        return Ok(None);
    };
    // Another sender may have finished this week while we waited.
    if !due(&read_state(guard_home)) {
        return Ok(None);
    }
    send_and_record(hol, guard_home, home, week).map(Some)
}

#[cfg(all(test, unix))]
#[path = "plugin_telemetry_weekly_tests.rs"]
mod tests;
