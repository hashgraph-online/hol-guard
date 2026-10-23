//! Bounded, read-only projection of the Python observer's public files.

use rustix::fs::{open, openat, Mode, OFlags};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

const SNAPSHOT_MAX: u64 = 4 * 1024 * 1024;
const LIVE_MAX: u64 = 64 * 1024;
const FEATURE_MAX: u64 = 128 * 1024;

pub struct PublicRoot {
    dir: OwnedFd,
}

impl PublicRoot {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let dir = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { dir })
    }

    fn read_json(&self, name: &str, max: u64) -> Option<Value> {
        let descriptor = openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?;
        let mut file = File::from(descriptor);
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() || metadata.len() > max {
            return None;
        }
        let mut bytes = Vec::new();
        file.by_ref().take(max + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > max {
            return None;
        }
        serde_json::from_slice(&bytes).ok()
    }

    pub fn identity(&self) -> Option<String> {
        let value = self.read_json("dashboard-id.json", 4096)?;
        let id = value.get("instance_id")?.as_str()?;
        (id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        .then(|| id.to_owned())
    }

    pub fn snapshot(&self, now: f64) -> Value {
        let Some(mut value) = self.read_json("snapshot.json", SNAPSHOT_MAX) else {
            return unavailable();
        };
        let Some(updated) = value.get("updated_at").and_then(Value::as_f64) else {
            return unavailable();
        };
        if !updated.is_finite()
            || value.get("schema").and_then(Value::as_str) != Some("hol-gauntlet-dashboard.v1")
            || !value.get("jobs").is_some_and(Value::is_array)
        {
            return unavailable();
        }
        let age = (now - updated).max(0.0);
        let Some(object) = value.as_object_mut() else {
            return unavailable();
        };
        object.insert(
            "collector_age_seconds".into(),
            json!((age * 10.0).round() / 10.0),
        );
        object.insert(
            "collector_status".into(),
            json!(if age < 90.0 { "online" } else { "stale" }),
        );
        for (name, field, max) in [
            ("live.json", "live_e2e", LIVE_MAX),
            ("feature-ai.json", "feature_ai", LIVE_MAX),
            ("feature-audit.json", "feature_audit", FEATURE_MAX),
        ] {
            if let Some(row) = self.auxiliary(name, now, max) {
                object.insert(field.into(), row);
            }
        }
        value
    }

    fn auxiliary(&self, name: &str, now: f64, max: u64) -> Option<Value> {
        let mut row = self.read_json(name, max)?;
        let expected = if name == "feature-audit.json" {
            "hol-gauntlet-feature-operations.v1"
        } else {
            "hol-gauntlet-live-operations.v1"
        };
        if row.get("schema")?.as_str()? != expected {
            return None;
        }
        let updated = row.get("updated_at")?.as_f64()?;
        if !updated.is_finite() {
            return None;
        }
        if name == "feature-ai.json" {
            let profile = row.get("profile")?.as_str()?;
            if !matches!(profile, "feature-ai" | "feature-ai-protocol") {
                return None;
            }
            if profile == "feature-ai-protocol"
                && row.get("status").and_then(Value::as_str) == Some("passed")
                && row.get("model_ingestion_proven").is_none_or(Value::is_null)
            {
                let proven = row
                    .get("cells")
                    .and_then(Value::as_array)
                    .is_some_and(|cells| {
                        cells.len() == 2
                            && cells.iter().all(|cell| {
                                cell.get("model_ingestion_proven").and_then(Value::as_bool)
                                    == Some(true)
                                    && cell.get("protocol_exposure_stage").and_then(Value::as_str)
                                        == Some("model-context-forwarded")
                            })
                    });
                row.as_object_mut()?
                    .insert("model_ingestion_proven".into(), json!(proven));
            }
        }
        let active = if name == "feature-audit.json" {
            matches!(
                row.get("status").and_then(Value::as_str),
                Some("starting" | "running")
            )
        } else {
            matches!(
                row.get("status").and_then(Value::as_str),
                Some(
                    "queued"
                        | "provider-startup"
                        | "model-ready"
                        | "vm-preflight"
                        | "prepared"
                        | "running"
                )
            )
        };
        let freshness = if active && now - updated > 90.0 {
            "stale"
        } else {
            "current"
        };
        row.as_object_mut()?
            .insert("telemetry_status".into(), json!(freshness));
        Some(row)
    }
}

fn unavailable() -> Value {
    json!({
        "collector_status": "unavailable",
        "collector_age_seconds": null,
        "jobs": [],
        "github": {"status": "unknown"},
        "gate": {"required": null},
        "admission_reasons": ["Host collector has not published a valid snapshot"]
    })
}
