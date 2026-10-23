//! Passive host resource sample corresponding to Python `telemetry.host`.
//! It never grants admission or publishes a dashboard snapshot.

#[cfg(target_os = "macos")]
use crate::fixed_process::run_fixed;
use rustix::fs::statvfs;
use serde_json::{json, Value};
use std::fmt;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const MEMORY_NOTE: &str = "Free plus inactive/speculative pages; estimate of reclaimable memory.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostTelemetryError {
    InvalidPath,
    Unavailable,
    Overflow,
}

impl fmt::Display for HostTelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPath => "host telemetry path must be absolute",
            Self::Unavailable => "host resource telemetry unavailable",
            Self::Overflow => "host resource telemetry exceeds numeric bounds",
        })
    }
}

impl std::error::Error for HostTelemetryError {}

fn disk_bytes(path: &Path) -> Result<(u64, u64), HostTelemetryError> {
    if !path.is_absolute() {
        return Err(HostTelemetryError::InvalidPath);
    }
    let stats = statvfs(path).map_err(|_| HostTelemetryError::Unavailable)?;
    let unit = u128::from(stats.f_frsize);
    let total = u128::from(stats.f_blocks)
        .checked_mul(unit)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(HostTelemetryError::Overflow)?;
    let free = u128::from(stats.f_bavail)
        .checked_mul(unit)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(HostTelemetryError::Overflow)?;
    if total == 0 || free > total {
        return Err(HostTelemetryError::Unavailable);
    }
    Ok((total, free))
}

fn load_one() -> Result<f64, HostTelemetryError> {
    let mut values = [0.0_f64; 3];
    // POSIX getloadavg only writes the first element when it returns one.
    let read = unsafe { libc::getloadavg(values.as_mut_ptr(), 1) };
    if read != 1 || !values[0].is_finite() || values[0] < 0.0 {
        return Err(HostTelemetryError::Unavailable);
    }
    Ok(values[0])
}

fn current_time() -> Result<f64, HostTelemetryError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostTelemetryError::Unavailable)?;
    Ok(now.as_secs_f64())
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_memory(total: &[u8], pages: &[u8]) -> Result<(u64, u64), HostTelemetryError> {
    if total.len() > 128 || pages.len() > 16 * 1024 {
        return Err(HostTelemetryError::Unavailable);
    }
    let total = std::str::from_utf8(total)
        .map_err(|_| HostTelemetryError::Unavailable)?
        .trim()
        .parse::<u64>()
        .map_err(|_| HostTelemetryError::Unavailable)?;
    let pages = std::str::from_utf8(pages).map_err(|_| HostTelemetryError::Unavailable)?;
    let mut lines = pages.lines();
    let header = lines.next().ok_or(HostTelemetryError::Unavailable)?;
    let size = header
        .split_once("page size of ")
        .and_then(|(_, tail)| tail.split_once(" bytes"))
        .and_then(|(number, _)| number.parse::<u64>().ok())
        .filter(|number| *number > 0 && *number <= 65_536)
        .ok_or(HostTelemetryError::Unavailable)?;
    let mut free = None;
    let mut inactive = None;
    let mut speculative = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let slot = match name.trim() {
            "Pages free" => &mut free,
            "Pages inactive" => &mut inactive,
            "Pages speculative" => &mut speculative,
            _ => continue,
        };
        if slot.is_some() {
            return Err(HostTelemetryError::Unavailable);
        }
        *slot = Some(
            value
                .trim()
                .trim_end_matches('.')
                .parse::<u64>()
                .map_err(|_| HostTelemetryError::Unavailable)?,
        );
    }
    let available = free
        .unwrap_or(0_u64)
        .checked_add(inactive.unwrap_or(0))
        .and_then(|value| value.checked_add(speculative.unwrap_or(0)))
        .and_then(|value| value.checked_mul(size))
        .ok_or(HostTelemetryError::Overflow)?;
    if total == 0 || available > total {
        return Err(HostTelemetryError::Unavailable);
    }
    Ok((total, available))
}

#[cfg(target_os = "macos")]
fn memory() -> Result<(u64, u64), HostTelemetryError> {
    let total = run_fixed(
        &["/usr/sbin/sysctl".into(), "-n".into(), "hw.memsize".into()],
        Duration::from_secs(5),
        128,
        512,
        &[],
    )
    .map_err(|_| HostTelemetryError::Unavailable)?;
    let pages = run_fixed(
        &["/usr/bin/vm_stat".into()],
        Duration::from_secs(5),
        16 * 1024,
        512,
        &[],
    )
    .map_err(|_| HostTelemetryError::Unavailable)?;
    parse_macos_memory(&total, &pages)
}

#[cfg(target_os = "linux")]
fn memory() -> Result<(u64, u64), HostTelemetryError> {
    use std::io::Read;

    let mut content = Vec::new();
    std::fs::File::open("/proc/meminfo")
        .map_err(|_| HostTelemetryError::Unavailable)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut content)
        .map_err(|_| HostTelemetryError::Unavailable)?;
    if content.len() > 64 * 1024 {
        return Err(HostTelemetryError::Unavailable);
    }
    let content = std::str::from_utf8(&content).map_err(|_| HostTelemetryError::Unavailable)?;
    let mut total = None;
    let mut available = None;
    for line in content.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let slot = match name {
            "MemTotal" => &mut total,
            "MemAvailable" => &mut available,
            _ => continue,
        };
        if slot.is_some() {
            return Err(HostTelemetryError::Unavailable);
        }
        *slot = Some(
            value
                .split_whitespace()
                .next()
                .ok_or(HostTelemetryError::Unavailable)?
                .parse::<u64>()
                .map_err(|_| HostTelemetryError::Unavailable)?
                .checked_mul(1024)
                .ok_or(HostTelemetryError::Overflow)?,
        );
    }
    match (total, available) {
        (Some(total), Some(available)) if total > 0 && available <= total => Ok((total, available)),
        _ => Err(HostTelemetryError::Unavailable),
    }
}

/// Sample the current machine and a caller-selected absolute path's volume.
/// Memory failures remain explicit nulls while the disk/CPU sample can still
/// be reported. Consumers must enforce freshness and independent admission.
pub fn sample_host(path: &Path) -> Result<Value, HostTelemetryError> {
    let (disk_total, disk_free) = disk_bytes(path)?;
    let cpus = std::thread::available_parallelism()
        .map_err(|_| HostTelemetryError::Unavailable)?
        .get();
    let load = load_one()?;
    let checked_at = current_time()?;
    let platform = if cfg!(target_os = "macos") {
        "Darwin"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        return Err(HostTelemetryError::Unavailable);
    };
    let mut result = json!({
        "status":"online",
        "checked_at":checked_at,
        "platform":platform,
        "cpus":cpus,
        "load":load,
        "disk_total":disk_total,
        "disk_free":disk_free,
        "memory_total":null,
        "memory_available":null,
    });
    match memory() {
        Ok((total, available)) => {
            result["memory_total"] = json!(total);
            result["memory_available"] = json!(available);
            if cfg!(target_os = "macos") {
                result["memory_note"] = json!(MEMORY_NOTE);
            }
        }
        Err(_) => result["memory_error"] = json!("host memory sample unavailable"),
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_memory_formula_matches_pinned_python_and_refuses_bad_pages() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/python_host_telemetry_v1.json")).unwrap();
        let manifest: Value =
            serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
        let source = manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == "ci/gauntlet/control_plane/telemetry.py")
            .unwrap();
        assert_eq!(fixture["source_sha256"], source["sha256"]);
        assert_eq!(fixture["schema"], "gauntlet-host-telemetry-fixtures.v1");
        let total = fixture["sysctl_stdout"].as_str().unwrap().as_bytes();
        let pages = fixture["vm_stat_stdout"].as_str().unwrap().as_bytes();
        let (memory_total, memory_available) = parse_macos_memory(total, pages).unwrap();
        assert_eq!(json!(memory_total), fixture["python_host"]["memory_total"]);
        assert_eq!(
            json!(memory_available),
            fixture["python_host"]["memory_available"]
        );
        assert_eq!(
            parse_macos_memory(total, &vec![b'x'; 16 * 1024 + 1]),
            Err(HostTelemetryError::Unavailable)
        );
        assert_eq!(
            parse_macos_memory(total, b"page size of 16384 bytes\nPages free: nope.\n"),
            Err(HostTelemetryError::Unavailable)
        );
        assert_eq!(
            parse_macos_memory(
                total,
                b"page size of 16384 bytes\nPages free: 1.\nPages free: 2.\n"
            ),
            Err(HostTelemetryError::Unavailable)
        );
    }

    #[test]
    fn live_host_probe_reports_truthful_positive_disk_and_cpu() {
        let temporary = tempfile::tempdir().unwrap();
        let sample = sample_host(temporary.path()).unwrap();
        assert_eq!(sample["status"], "online");
        assert!(sample["checked_at"].as_f64().unwrap() > 0.0);
        assert!(sample["cpus"].as_u64().unwrap() > 0);
        let total = sample["disk_total"].as_u64().unwrap();
        let free = sample["disk_free"].as_u64().unwrap();
        assert!(total > 0 && free <= total);
        assert!(sample["load"].as_f64().unwrap() >= 0.0);
        assert_eq!(
            sample_host(Path::new("relative")),
            Err(HostTelemetryError::InvalidPath)
        );
    }
}
