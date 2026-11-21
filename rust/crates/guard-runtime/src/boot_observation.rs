//! This boot's session identifier and an uptime that never goes backwards
//! within the boot, which the installation continuity record compares each
//! lease against (`mdm/continuity.py` before it moved here).
//!
//! - macOS: `kern.bootsessionuuid` and `mach_continuous_time`, which keeps
//!   counting while the machine sleeps.
//! - Windows: the firmware boot identifier and `GetTickCount64`, which keeps
//!   counting while the machine sleeps.
//! - Linux: `/proc/sys/kernel/random/boot_id` and `CLOCK_MONOTONIC`, which
//!   stops while the machine is suspended, so the uptime is not wall time
//!   since boot there.

use serde_json::{json, Value};

const MAX_BOOT_SESSION_CHARS: usize = 256;
const BOOT_PROBE_FAILED: &str = "lease_continuity_boot_probe_failed";
const MONOTONIC_PROBE_FAILED: &str = "lease_continuity_monotonic_probe_failed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootObservation {
    pub(crate) boot_session_id: String,
    pub(crate) monotonic_uptime_ns: u64,
}

impl BootObservation {
    pub(crate) fn to_value(&self) -> Value {
        json!({
            "boot_session_id": self.boot_session_id,
            "monotonic_uptime_ns": self.monotonic_uptime_ns,
        })
    }
}

/// Observe this boot, or the `lease_continuity_*` code of the probe that failed.
pub(crate) fn observe() -> Result<BootObservation, &'static str> {
    let (boot_session_id, monotonic_uptime_ns) = system::observe()?;
    Ok(BootObservation {
        boot_session_id: validated_boot_session_id(&boot_session_id)?,
        monotonic_uptime_ns,
    })
}

/// A session identifier that is present, bounded and not all zeros.
fn validated_boot_session_id(value: &str) -> Result<String, &'static str> {
    let normalized = value.trim();
    if normalized.is_empty()
        || normalized.chars().count() > MAX_BOOT_SESSION_CHARS
        || normalized
            .chars()
            .all(|character| "0-{}".contains(character))
    {
        return Err(BOOT_PROBE_FAILED);
    }
    Ok(normalized.to_owned())
}

/// A GUID's in-memory bytes in the canonical lowercase form Python's
/// `uuid.UUID(bytes_le=...)` prints.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn guid_string(raw: [u8; 16]) -> String {
    let data1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let data2 = u16::from_le_bytes([raw[4], raw[5]]);
    let data3 = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{data1:08x}-{data2:04x}-{data3:04x}-{}-{}",
        hex::encode(&raw[8..10]),
        hex::encode(&raw[10..16]),
    )
}

/// Tick-count milliseconds as nanoseconds.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn milliseconds_as_ns(milliseconds: u64) -> Result<u64, &'static str> {
    milliseconds
        .checked_mul(1_000_000)
        .ok_or(MONOTONIC_PROBE_FAILED)
}

#[cfg(target_os = "macos")]
mod system {
    use super::{BOOT_PROBE_FAILED, MONOTONIC_PROBE_FAILED};

    pub(super) fn observe() -> Result<(String, u64), &'static str> {
        let raw = guard_seatbelt::boot_session_uuid().ok_or(BOOT_PROBE_FAILED)?;
        let boot_session_id = String::from_utf8(raw)
            .ok()
            .filter(|value| value.is_ascii())
            .ok_or(BOOT_PROBE_FAILED)?;
        let uptime = guard_seatbelt::continuous_uptime_ns().ok_or(MONOTONIC_PROBE_FAILED)?;
        Ok((boot_session_id, uptime))
    }
}

#[cfg(windows)]
mod system {
    use super::{guid_string, milliseconds_as_ns, BOOT_PROBE_FAILED};

    pub(super) fn observe() -> Result<(String, u64), &'static str> {
        let identifier =
            guard_runtime_windows_process::boot_identifier().ok_or(BOOT_PROBE_FAILED)?;
        let uptime = milliseconds_as_ns(guard_runtime_windows_process::tick_count_ms())?;
        Ok((guid_string(identifier), uptime))
    }
}

#[cfg(target_os = "linux")]
mod system {
    use super::{BOOT_PROBE_FAILED, MONOTONIC_PROBE_FAILED};

    const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

    pub(super) fn observe() -> Result<(String, u64), &'static str> {
        let boot_session_id =
            std::fs::read_to_string(BOOT_ID_PATH).map_err(|_| BOOT_PROBE_FAILED)?;
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        let uptime = u64::try_from(now.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|nanos| nanos.checked_add(u64::try_from(now.tv_nsec).ok()?))
            .ok_or(MONOTONIC_PROBE_FAILED)?;
        Ok((boot_session_id, uptime))
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
mod system {
    pub(super) fn observe() -> Result<(String, u64), &'static str> {
        Err("lease_continuity_platform_unsupported")
    }
}

#[cfg(test)]
#[path = "boot_observation_tests.rs"]
mod tests;
