//! Explicit rollback chooses only an authenticated last-good runtime. The
//! ordinary preparation pipeline reads current data, never an old checkpoint.
use super::*;

impl Service {
    pub(crate) fn prepare_rollback(
        &self,
        home: &Path,
        id: &str,
        generation: u64,
    ) -> Result<Value, String> {
        if let Some(job) = jobs::get(home, id)? {
            if !job.request.rollback || job.request.expected_generation != generation {
                return Err(error("switch_idempotency_conflict"));
            }
            return self.switch_job(home, id);
        }
        let owner = switching::Owner::acquire(home)?;
        let target = owner.rollback_target()?;
        drop(owner);
        self.prepare_switch(
            home,
            SwitchRequest {
                job_id: id.into(),
                target_runtime_id: target.installation_id,
                expected_generation: generation,
                rollback: true,
            },
        )
    }
}
