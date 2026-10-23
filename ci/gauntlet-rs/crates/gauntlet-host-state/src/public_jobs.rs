//! Pure projection of already-read private jobs into the pinned Python
//! dashboard's public allowlist. It never publishes a snapshot or lease.

use crate::truthy;
use serde_json::{json, Map, Value};
use std::fmt;

const PUBLIC_KEYS: &[&str] = &[
    "id",
    "pr",
    "title",
    "url",
    "sha",
    "base_sha",
    "state",
    "reason",
    "created_at",
    "started_at",
    "finished_at",
    "updated_at",
    "status_error",
    "result",
    "posted_state",
    "kind",
    "tag",
    "phase",
    "phase_started_at",
    "events",
    "vm_progress",
    "progress_error",
    "build_run",
    "build_dispatch",
    "source_error",
    "local_build",
    "stage_error",
    "stage_result",
    "diagnostic_result",
];
const LOCAL_BUILD_KEYS: [&str; 10] = [
    "source_sha",
    "job_id",
    "tag",
    "status",
    "builder_image",
    "error",
    "failure_phase",
    "exit_code",
    "log_path",
    "version",
];
const MAX_PUBLIC_JOBS: usize = 200;
const MAX_PROJECTION_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicJobsError {
    InvalidJob,
    TooLarge,
}

impl fmt::Display for PublicJobsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidJob => "invalid private job for public projection",
            Self::TooLarge => "public job projection exceeds byte limit",
        })
    }
}

impl std::error::Error for PublicJobsError {}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicJobsProjection {
    pub jobs: Vec<Value>,
    pub archived_jobs: usize,
    pub publication_eligible: bool,
}

impl PublicJobsProjection {
    pub fn to_json(&self) -> Value {
        json!({
            "jobs": self.jobs,
            "archived_jobs": self.archived_jobs,
            "publication_eligible": self.publication_eligible,
        })
    }
}

/// Match `Agent.publish`'s job ordering, archive exclusion and public fields.
/// The whole input is validated first; malformed history yields no partial
/// projection. This cannot safely publish without the observer's lease and a
/// complete, coherent status snapshot.
pub fn project_public_jobs(jobs: &[Value]) -> Result<PublicJobsProjection, PublicJobsError> {
    let mut ordered = Vec::with_capacity(jobs.len());
    for (index, job) in jobs.iter().enumerate() {
        let object = job.as_object().ok_or(PublicJobsError::InvalidJob)?;
        let created_at = object
            .get("created_at")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite())
            .ok_or(PublicJobsError::InvalidJob)?;
        if object.get("id").and_then(Value::as_str).is_none()
            || object.get("state").and_then(Value::as_str).is_none()
            || (object.contains_key("local_build")
                && !object.get("local_build").is_some_and(Value::is_object))
        {
            return Err(PublicJobsError::InvalidJob);
        }
        ordered.push((index, created_at));
    }
    ordered.sort_by(|left, right| right.1.partial_cmp(&left.1).expect("finite timestamps"));
    let archived_jobs = jobs
        .iter()
        .filter(|job| truthy(job.get("archived_at")))
        .count();
    let mut public = Vec::new();
    for (index, _) in ordered {
        let job = &jobs[index];
        if truthy(job.get("archived_at")) {
            continue;
        }
        let mut row = Map::new();
        for &key in PUBLIC_KEYS {
            if let Some(value) = job.get(key) {
                row.insert(key.to_owned(), value.clone());
            }
        }
        if let Some(local_build) = job.get("local_build") {
            let source = local_build.as_object().ok_or(PublicJobsError::InvalidJob)?;
            let mut filtered = Map::new();
            for key in LOCAL_BUILD_KEYS {
                if let Some(value) = source.get(key) {
                    filtered.insert(key.to_owned(), value.clone());
                }
            }
            row.insert("local_build".to_owned(), Value::Object(filtered));
        }
        public.push(Value::Object(row));
        if public.len() == MAX_PUBLIC_JOBS {
            break;
        }
    }
    let projection = PublicJobsProjection {
        jobs: public,
        archived_jobs,
        publication_eligible: false,
    };
    let bytes = serde_json::to_vec(&projection.to_json()).map_err(|_| PublicJobsError::TooLarge)?;
    if bytes.len() > MAX_PROJECTION_BYTES {
        return Err(PublicJobsError::TooLarge);
    }
    Ok(projection)
}
