//! Fixed read-only Lima VM probe and Python-compatible resource-admission
//! reasons. No result from this module grants a queue or worker lease.

use crate::fixed_process::{run_fixed, FixedProcessError};
use crate::load_operations_bytes;
use gauntlet_contracts::canonicalize;
use serde_json::{json, Map, Value};
use std::fmt;
use std::time::Duration;

const GIB: f64 = 1_073_741_824.0;
const MAX_PROBE_BYTES: usize = 8192;
const VM_PROBE: &str = r#"import json,os,shutil,time
from pathlib import Path
m={k:int(v.split()[0])*1024 for k,v in (s.split(":",1) for s in Path("/proc/meminfo").read_text().splitlines())}
d=shutil.disk_usage("/")
print(json.dumps({"status":"running","checked_at":time.time(),"cpus":os.cpu_count(),
"load":os.getloadavg()[0],"memory_total":m["MemTotal"],"memory_available":m["MemAvailable"],
"disk_total":d.total,"disk_free":d.free}))"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryError {
    InvalidConfig,
    InvalidSnapshot,
    InvalidProbe,
    TooLarge,
    Unavailable,
    TimedOut,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid reviewed VM telemetry configuration",
            Self::InvalidSnapshot => "invalid resource snapshot",
            Self::InvalidProbe => "VM resource probe returned invalid data",
            Self::TooLarge => "VM resource probe exceeded byte limit",
            Self::Unavailable => "VM resource probe unavailable",
            Self::TimedOut => "VM resource probe timed out",
        })
    }
}

impl std::error::Error for TelemetryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmProbePlan {
    pub argv: Vec<String>,
    pub name: String,
}

fn verified_config(operations: &Value) -> Result<Value, TelemetryError> {
    let raw = serde_json::to_vec(operations).map_err(|_| TelemetryError::InvalidConfig)?;
    load_operations_bytes(&raw).map_err(|_| TelemetryError::InvalidConfig)
}

fn finite_number(object: &Map<String, Value>, key: &str) -> Result<f64, TelemetryError> {
    match object.get(key) {
        None => Ok(0.0),
        Some(Value::Number(number)) => number
            .as_f64()
            .filter(|value| value.is_finite())
            .ok_or(TelemetryError::InvalidSnapshot),
        _ => Err(TelemetryError::InvalidSnapshot),
    }
}

fn object_or_empty<'a>(
    snapshot: &'a Value,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, TelemetryError> {
    match snapshot.get(key) {
        None => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        _ => Err(TelemetryError::InvalidSnapshot),
    }
}

fn number_or_zero(object: Option<&Map<String, Value>>, key: &str) -> Result<f64, TelemetryError> {
    match object {
        Some(object) => finite_number(object, key),
        None => Ok(0.0),
    }
}

/// Apply the pinned Python `telemetry.admission` resource checks to a supplied
/// snapshot at a caller-supplied time. This is one admission input only; source,
/// lease, deployment, VM receipt and provider checks remain separate.
pub fn resource_admission_reasons(
    snapshot: &Value,
    operations: &Value,
    now: f64,
) -> Result<Vec<&'static str>, TelemetryError> {
    let config = verified_config(operations)?;
    if !now.is_finite() || now <= 0.0 || !snapshot.is_object() {
        return Err(TelemetryError::InvalidSnapshot);
    }
    let host = object_or_empty(snapshot, "host")?;
    let vm = object_or_empty(snapshot, "vm")?;
    let deployment = object_or_empty(snapshot, "deployment")?;
    let vm_running = vm
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        == Some("running");
    let mut reasons = Vec::new();
    if deployment.is_some()
        && deployment
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            != Some("installed")
    {
        reasons.push("Reviewed VM controller deployment is not installed");
    }
    if now - number_or_zero(host, "checked_at")? > 90.0
        || now - number_or_zero(vm, "checked_at")? > 90.0
    {
        reasons.push("Resource telemetry is stale");
    }
    let floor = |key: &str| -> Result<f64, TelemetryError> {
        config[key]
            .as_u64()
            .map(|value| value as f64 * GIB)
            .ok_or(TelemetryError::InvalidConfig)
    };
    if number_or_zero(host, "disk_free")? < floor("host_disk_floor_gib")? {
        reasons.push("Host disk headroom below configured floor");
    }
    if !vm_running {
        reasons.push("Benchmark VM unavailable");
    } else if number_or_zero(vm, "disk_free")? < floor("vm_disk_floor_gib")? {
        reasons.push("VM disk headroom below configured floor");
    }
    if vm_running {
        if number_or_zero(vm, "memory_total")? < floor("vm_memory_gib")? - GIB {
            reasons.push("VM memory is below its configured allocation; run gauntlet repair");
        }
        if number_or_zero(vm, "disk_total")? < floor("vm_disk_gib")? - 3.0 * GIB {
            reasons
                .push("VM filesystem is below its configured disk allocation; run gauntlet repair");
        }
        if number_or_zero(vm, "memory_available")? < GIB {
            reasons.push("VM has less than 1 GiB available memory");
        }
    }
    Ok(reasons)
}

impl VmProbePlan {
    pub fn new(operations: &Value) -> Result<Self, TelemetryError> {
        let config = verified_config(operations)?;
        let limactl = config["limactl"]
            .as_str()
            .ok_or(TelemetryError::InvalidConfig)?;
        let name = config["vm"].as_str().ok_or(TelemetryError::InvalidConfig)?;
        Ok(Self {
            argv: vec![
                limactl.to_owned(),
                "shell".to_owned(),
                name.to_owned(),
                "--".to_owned(),
                "/usr/bin/python3".to_owned(),
                "-c".to_owned(),
                VM_PROBE.to_owned(),
            ],
            name: name.to_owned(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "argv":self.argv,
            "timeout_seconds":12,
            "read_only":true,
            "admission_eligible":false,
        })
    }

    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, TelemetryError> {
        if stdout.len() > MAX_PROBE_BYTES {
            return Err(TelemetryError::TooLarge);
        }
        let canonical = canonicalize(stdout).map_err(|_| TelemetryError::InvalidProbe)?;
        let mut value: Value =
            serde_json::from_slice(&canonical).map_err(|_| TelemetryError::InvalidProbe)?;
        let object = value.as_object_mut().ok_or(TelemetryError::InvalidProbe)?;
        let fields = [
            "status",
            "checked_at",
            "cpus",
            "load",
            "memory_total",
            "memory_available",
            "disk_total",
            "disk_free",
        ];
        if object.len() != 8
            || fields.iter().any(|name| !object.contains_key(*name))
            || object.get("status").and_then(Value::as_str) != Some("running")
            || object
                .get("cpus")
                .and_then(Value::as_u64)
                .is_none_or(|cpus| !(1..=512).contains(&cpus))
        {
            return Err(TelemetryError::InvalidProbe);
        }
        let number = |name: &str| -> Result<f64, TelemetryError> {
            object
                .get(name)
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite() && *value >= 0.0)
                .ok_or(TelemetryError::InvalidProbe)
        };
        let checked_at = number("checked_at")?;
        let _load = number("load")?;
        let memory_total = number("memory_total")?;
        let memory_available = number("memory_available")?;
        let disk_total = number("disk_total")?;
        let disk_free = number("disk_free")?;
        if checked_at <= 0.0
            || memory_total <= 0.0
            || disk_total <= 0.0
            || memory_available > memory_total
            || disk_free > disk_total
        {
            return Err(TelemetryError::InvalidProbe);
        }
        object.insert("name".to_owned(), Value::String(self.name.clone()));
        Ok(value)
    }

    pub fn execute_read_only(&self) -> Result<Value, TelemetryError> {
        let stdout = run_fixed(
            &self.argv,
            Duration::from_secs(12),
            MAX_PROBE_BYTES,
            1000,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                TelemetryError::Unavailable
            }
            FixedProcessError::TimedOut => TelemetryError::TimedOut,
            FixedProcessError::TooLarge => TelemetryError::TooLarge,
        })?;
        self.parse_response(&stdout)
    }
}
