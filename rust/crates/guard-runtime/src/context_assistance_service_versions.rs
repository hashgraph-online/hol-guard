//! Native operator controls. No path, hash, supplied trust key or SDK readiness
//! fact is admitted through this resident API.
use super::*;
use serde::Deserialize;
#[path = "context_assistance_service_version_jobs.rs"]
mod jobs;
#[cfg(test)]
#[path = "context_assistance_service_versions_tests.rs"]
mod tests;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Jobs,
    Job {
        job_id: String,
    },
    Cancel {
        job_id: String,
    },
    Recover {
        job_id: String,
        expected_generation: Option<String>,
    },
    PrepareSwitch {
        job_id: String,
        target_runtime_id: String,
        expected_generation: String,
    },
    PrepareRollback {
        job_id: String,
        expected_generation: String,
    },
    Commit {
        job_id: String,
        expected_generation: String,
        reconnect: bool,
    },
}
impl Service {
    pub(crate) fn versions(&self, home: &std::path::Path, input: Value) -> Result<Value, String> {
        if lock(&self.state)?.closed {
            return Err("native_context_assistance_shutdown".into());
        }
        let action: Action = crate::strict_json::from_value(input)
            .map_err(|_| "native_context_assistance_versions_request_invalid")?;
        match action {
            Action::Jobs => jobs::list(self, home),
            Action::Job { job_id } => jobs::get(self, home, &job_id),
            Action::Cancel { job_id } => jobs::cancel(self, home, &job_id),
            Action::Recover {
                job_id,
                expected_generation,
            } => jobs::recover(self, home, &job_id, expected_generation.as_deref()),
            Action::PrepareSwitch {
                job_id,
                target_runtime_id,
                expected_generation,
            } => jobs::prepare(
                self,
                home,
                &job_id,
                Some(&target_runtime_id),
                &expected_generation,
            ),
            Action::PrepareRollback {
                job_id,
                expected_generation,
            } => jobs::prepare(self, home, &job_id, None, &expected_generation),
            Action::Commit {
                job_id,
                expected_generation,
                reconnect,
            } => jobs::commit(self, home, &job_id, &expected_generation, reconnect),
        }
    }
}
