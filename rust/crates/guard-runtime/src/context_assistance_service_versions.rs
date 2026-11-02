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
    Releases,
    Preferences,
    SetPreferences {
        expected_revision: String,
        preferences: guard_cigar_release::UpdatePreferences,
    },
    Catalog,
    RefreshCatalog {
        job_id: String,
    },
    ImportCatalog {
        signed_catalog: String,
    },
    Interpreters,
    Jobs,
    Job {
        job_id: String,
    },
    SetupInterpreter {
        job_id: String,
        build_id: String,
    },
    Install {
        job_id: String,
        build_id: String,
        interpreter_id: String,
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
            Action::Releases => self.updates.releases(home),
            Action::Preferences => crate::guard_config_load::cigar_updates::read(home),
            Action::SetPreferences {
                expected_revision,
                preferences,
            } => crate::guard_config_load::cigar_updates::write(
                home,
                &expected_revision,
                preferences,
            ),
            Action::RefreshCatalog { job_id } => self.updates.refresh_catalog(home, &job_id),
            Action::Catalog => {
                crate::policy_store::context_assistance_registry::catalog::status(home)
            }
            Action::ImportCatalog { signed_catalog } => {
                crate::policy_store::context_assistance_registry::catalog::import(
                    home,
                    signed_catalog.as_bytes(),
                )
            }
            Action::Interpreters => Ok(json!({"interpreters":self.updates.interpreters(home)?})),
            Action::Jobs => jobs::list(self, home),
            Action::Job { job_id } => jobs::get(self, home, &job_id),
            Action::SetupInterpreter { job_id, build_id } => self.updates.setup_interpreter(
                home,
                crate::policy_store::context_assistance_registry::SetupInterpreterRequest {
                    job_id,
                    build_id,
                },
            ),
            Action::Install {
                job_id,
                build_id,
                interpreter_id,
            } => self.updates.install(
                home,
                crate::policy_store::context_assistance_registry::InstallRequest {
                    job_id,
                    build_id,
                    interpreter_id,
                },
            ),
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

#[cfg(test)]
impl Service {
    #[cfg(target_os = "macos")]
    pub(crate) fn refresh_test_catalog(
        &self,
        home: &std::path::Path,
        id: &str,
        raw: Vec<u8>,
        pause: crate::policy_store::context_assistance_registry::InstallPause,
    ) -> Result<Value, String> {
        self.updates.refresh_test_catalog(home, id, raw, pause)
    }

    #[cfg(unix)]
    pub(crate) fn install_test_catalog(
        &self,
        home: &std::path::Path,
        request: crate::policy_store::context_assistance_registry::InstallRequest,
        catalog: &guard_cigar_release::TrustedCatalog,
        pause: crate::policy_store::context_assistance_registry::InstallPause,
    ) -> Result<Value, String> {
        self.updates
            .install_test_catalog(home, request, catalog, pause)
    }
}
