//! Catalog refresh shares the one native preparation worker and unified jobs.
use super::*;
#[cfg(all(test, unix))]
#[path = "context_assistance_catalog_refresh_tests.rs"]
mod tests;
impl Jobs {
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn refresh_test_catalog(
        &self,
        home: &Path,
        id: &str,
        raw: Vec<u8>,
        pause: InstallPause,
    ) -> Result<Value, String> {
        self.refresh_catalog_inner(
            home,
            id,
            Some(Box::new(move |control, _| {
                pause
                    .entered
                    .send(())
                    .map_err(|_| error("install_test_pause_closed"))?;
                loop {
                    control.checkpoint().map_err(|e| error(e.code()))?;
                    match pause
                        .proceed
                        .recv_timeout(std::time::Duration::from_millis(25))
                    {
                        Ok(()) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(_) => return Err(error("install_test_pause_closed")),
                    }
                }
                Ok(raw)
            })),
        )
    }
    pub(crate) fn refresh_catalog(&self, home: &Path, id: &str) -> Result<Value, String> {
        self.refresh_catalog_inner(
            home,
            id,
            #[cfg(test)]
            None,
        )
    }
    fn refresh_catalog_inner(
        &self,
        home: &Path,
        id: &str,
        #[cfg(test)] test_fetch: Option<catalog_worker::TestFetch>,
    ) -> Result<Value, String> {
        #[cfg(not(unix))]
        {
            let _ = (home, id);
            Err(error("cigar_catalog_platform_unqualified"))
        }
        #[cfg(unix)]
        {
            catalog_store::request_sha(id)?;
            let conflict = |home: &Path| -> Result<bool, String> {
                Ok(store::get(home, id)?.is_some()
                    || python_store::get(home, id)?.is_some()
                    || super::super::switching::jobs::get(home, id)?.is_some())
            };
            if conflict(home)? {
                return Err(error("install_idempotency_conflict"));
            }
            if let Some(job) = catalog_store::get(home, id)? {
                return self.catalog_view(home, &job);
            }
            worker::policy(home)?;
            let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
            let mut state = state(self)?;
            if state.closed {
                return Err(error("shutdown"));
            }
            if state.live.as_ref().is_some_and(|v| !v.thread.is_finished()) {
                return Err(error("install_busy"));
            }
            if let Some(old) = state.live.take() {
                let _ = old.thread.join();
            }
            let owner = super::super::catalog::feed::begin(&home)?;
            acquisition::catalog_network_policy()?;
            if conflict(&home)? {
                return Err(error("install_idempotency_conflict"));
            }
            if let Some(job) = catalog_store::get(&home, id)? {
                drop(state);
                return self.catalog_view(&home, &job);
            }
            if total_job_count(&home)? >= store::MAX_JOBS {
                return Err(error("install_job_limit"));
            }
            let now = store::now()?;
            let mut job = catalog_store::Job {
                schema: "guard-cigar-catalog-refresh-job.v1".into(),
                job_id: id.into(),
                request_sha256: catalog_store::request_sha(id)?,
                feed_sha256: owner.fingerprint().into(),
                target: None,
                phase: store::Phase::Queued,
                code: "queued".into(),
                created_at_ms: now,
                updated_at_ms: now,
                deadline_at_ms: now
                    .checked_add(30_000)
                    .ok_or_else(|| error("clock_invalid"))?,
            };
            catalog_store::save(&home, &mut job, store::Phase::Queued, "queued")?;
            let cancel = Arc::new(AtomicBool::new(false));
            let wc = Arc::clone(&cancel);
            let wh = home.clone();
            let wj = job.clone();
            let (begin, pending) = mpsc::sync_channel::<()>(1);
            let thread = std::thread::Builder::new()
                .name("guard-cigar-catalog-refresh".into())
                .spawn(move || {
                    if pending.recv().is_err() {
                        return;
                    }
                    let mut job = wj;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        catalog_worker::run(
                            &wh,
                            &mut job,
                            &owner,
                            wc,
                            #[cfg(test)]
                            test_fetch,
                        )
                    }))
                    .unwrap_or_else(|_| Err(error("cigar_catalog_refresh_worker_failed")));
                    if let Err(code) = result {
                        let _ = catalog_worker::fail(&wh, &mut job, &code);
                    }
                })
                .map_err(|_| error("install_worker_unavailable"))?;
            state.live = Some(Live {
                home: home.clone(),
                job_id: id.into(),
                cancel,
                thread,
            });
            begin
                .send(())
                .map_err(|_| error("install_worker_unavailable"))?;
            drop(state);
            self.catalog_view(&home, &job)
        }
    }
    pub(super) fn catalog_view(
        &self,
        home: &Path,
        job: &catalog_store::Job,
    ) -> Result<Value, String> {
        let live = self.liveness(home, &job.job_id)?;
        let latest = if live != Some(true) {
            catalog_store::get(home, &job.job_id)?
        } else {
            None
        };
        let job = latest.as_ref().unwrap_or(job);
        let cancel_requested =
            fs::symlink_metadata(catalog_store::cancel_path(home, &job.job_id)?).is_ok();
        Ok(
            json!({"schema":job.schema,"job_id":job.job_id,"operation":"refresh_catalog","phase":job.phase,"code":job.code,"created_at_ms":job.created_at_ms,"updated_at_ms":job.updated_at_ms,"deadline_at_ms":job.deadline_at_ms,"feed_sha256":job.feed_sha256,"catalog_checkpoint":job.target,"worker_live":live,"cancel_requested":cancel_requested,"recovery_available":live!=Some(true)&&(!job.phase.terminal()||job.phase==store::Phase::RecoveryRequired),"activation_granted":false}),
        )
    }
    pub(super) fn cancel_catalog(
        &self,
        home: &Path,
        job: &catalog_store::Job,
    ) -> Result<Value, String> {
        if !job.phase.terminal() {
            catalog_store::mark_cancel(home, job)?;
            let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
            if let Some(live) = &state(self)?.live {
                if live.home == home && live.job_id == job.job_id {
                    live.cancel.store(true, Ordering::Release);
                }
            }
        }
        self.get(home, &job.job_id)
    }
    pub(super) fn recover_catalog(
        &self,
        home: &Path,
        mut job: catalog_store::Job,
    ) -> Result<Value, String> {
        if self.liveness(home, &job.job_id)? == Some(true) {
            return Err(error("install_busy"));
        }
        if !matches!(
            job.phase,
            store::Phase::Ready | store::Phase::Failed | store::Phase::Cancelled
        ) {
            catalog_worker::recover(home, &mut job)?;
        }
        self.catalog_view(home, &job)
    }
}
