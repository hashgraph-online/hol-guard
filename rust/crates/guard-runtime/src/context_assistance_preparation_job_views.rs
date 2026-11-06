//! Bounded metadata views for SDK, Python and catalog preparation jobs.
use super::*;
impl Jobs {
    pub(super) fn liveness(&self, home: &Path, id: &str) -> Result<Option<bool>, String> {
        let canonical = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
        Ok(state(self)?
            .live
            .as_ref()
            .filter(|live| live.home == canonical && live.job_id == id)
            .map(|live| !live.thread.is_finished()))
    }
    pub(super) fn view(&self, home: &Path, job: &store::Job) -> Result<Value, String> {
        let live = self.liveness(home, &job.request.job_id)?;
        // After observing completion, reload progress written before thread exit.
        let latest = if live != Some(true) {
            store::get(home, &job.request.job_id)?
        } else {
            None
        };
        let job = latest.as_ref().unwrap_or(job);
        let cancel_requested =
            fs::symlink_metadata(store::cancel_path(home, &job.request.job_id)?).is_ok();
        Ok(
            json!({"schema":job.schema,"job_id":job.request.job_id,"operation":if job.refresh.is_some() { "verify" } else { "install" },
            "build_id":job.request.build_id,"interpreter_id":job.request.interpreter_id,
            "sdk_version":job.release.identity.sdk_version,"core_version":job.release.identity.core_version,
            "runtime_id":job.runtime_id,"phase":job.phase,"code":job.code,
            "created_at_ms":job.created_at_ms,"updated_at_ms":job.updated_at_ms,
            "deadline_at_ms":job.deadline_at_ms,"worker_live":live,"cancel_requested":cancel_requested,
            "recovery_available":live != Some(true) && (!job.phase.terminal() || job.phase == store::Phase::RecoveryRequired),
            "activation_granted":false}),
        )
    }
    pub(crate) fn get(&self, home: &Path, id: &str) -> Result<Value, String> {
        if let Some(job) = catalog_store::get(home, id)? {
            if store::get(home, id)?.is_some() || python_store::get(home, id)?.is_some() {
                return Err(error("install_idempotency_conflict"));
            }
            return self.catalog_view(home, &job);
        }
        if let Some(job) = python_store::get(home, id)? {
            if store::get(home, id)?.is_some() {
                return Err(error("install_idempotency_conflict"));
            }
            return self.python_view(home, &job);
        }
        let job = store::get(home, id)?.ok_or_else(|| error("install_job_missing"))?;
        self.view(home, &job)
    }
    pub(crate) fn list(&self, home: &Path) -> Result<Vec<Value>, String> {
        let mut values: Vec<_> = store::list(home)?
            .iter()
            .map(|job| self.view(home, job))
            .collect::<Result<_, _>>()?;
        for job in python_store::list(home)? {
            if values
                .iter()
                .any(|value| value["job_id"] == job.request.job_id)
            {
                return Err(error("install_idempotency_conflict"));
            }
            values.push(self.python_view(home, &job)?);
        }
        for job in catalog_store::list(home)? {
            if values.iter().any(|v| v["job_id"] == job.job_id) {
                return Err(error("install_idempotency_conflict"));
            }
            values.push(self.catalog_view(home, &job)?);
        }
        if values.len() > store::MAX_JOBS {
            return Err(error("install_job_limit"));
        }
        values.sort_by(|a, b| {
            b["created_at_ms"]
                .as_u64()
                .cmp(&a["created_at_ms"].as_u64())
                .then(a["job_id"].as_str().cmp(&b["job_id"].as_str()))
        });
        Ok(values)
    }
    pub(crate) fn cancel(&self, home: &Path, id: &str) -> Result<Value, String> {
        if let Some(job) = catalog_store::get(home, id)? {
            if store::get(home, id)?.is_some() || python_store::get(home, id)?.is_some() {
                return Err(error("install_idempotency_conflict"));
            }
            return self.cancel_catalog(home, &job);
        }
        if let Some(job) = python_store::get(home, id)? {
            if store::get(home, id)?.is_some() {
                return Err(error("install_idempotency_conflict"));
            }
            return self.cancel_python(home, &job);
        }
        let job = store::get(home, id)?.ok_or_else(|| error("install_job_missing"))?;
        if !job.phase.terminal() {
            store::mark_cancel(home, &job)?;
            let canonical = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
            let state = state(self)?;
            if let Some(live) = &state.live {
                if live.home == canonical && live.job_id == id {
                    live.cancel.store(true, Ordering::Release);
                }
            }
        }
        self.get(home, id)
    }
    pub(crate) fn recover(&self, home: &Path, id: &str) -> Result<Value, String> {
        if let Some(job) = catalog_store::get(home, id)? {
            if store::get(home, id)?.is_some() || python_store::get(home, id)?.is_some() {
                return Err(error("install_idempotency_conflict"));
            }
            return self.recover_catalog(home, job);
        }
        if let Some(job) = python_store::get(home, id)? {
            if store::get(home, id)?.is_some() {
                return Err(error("install_idempotency_conflict"));
            }
            return self.recover_python(home, job);
        }
        let mut job = store::get(home, id)?.ok_or_else(|| error("install_job_missing"))?;
        if self.liveness(home, id)? == Some(true) {
            return Err(error("install_busy"));
        }
        if !matches!(
            job.phase,
            store::Phase::Ready | store::Phase::Failed | store::Phase::Cancelled
        ) {
            worker::recover(home, &mut job)?;
        }
        self.view(home, &job)
    }
}
