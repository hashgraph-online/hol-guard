//! Verify a newly enabled selection outside the short config writer lock.
//! The profile lease excludes catalog/install/switch changes until byte CAS.
//! Every explicit Stop changes an intent marker even when already disabled.
use super::*;
use sha2::{Digest, Sha256};
const REVISION: &str = "context_assistance_intent_revision";
pub(super) fn selection_error(code: String) -> Failure {
    if code.ends_with("_busy")
        || code.contains("_cigar_catalog_")
        || code.ends_with("_cigar_build_withdrawn")
    {
        Failure::Error(code)
    } else {
        Failure::Invalid("Context assistance requires an enrolled, verified CPython 3.14 installation. Set it up before enabling.".into())
    }
}
pub(super) fn needs_verification(
    previous: Option<&str>,
    next: &str,
) -> Result<Option<String>, Failure> {
    let next = assistance_preferences(next)?;
    if !next.enabled {
        return Ok(None);
    }
    let old = assistance_preferences(previous.unwrap_or_default())?;
    Ok((!old.enabled || old.runtime_id != next.runtime_id).then_some(next.runtime_id))
}
/// Replacing an existing selected installation must use the coupled SDK/data
/// owner. Initial setup and clearing/resetting preferences are separate flows.
fn require_selection_job(previous: Option<&str>, next: &str) -> Result<(), Failure> {
    let previous = assistance_preferences(previous.unwrap_or_default())?;
    let next = assistance_preferences(next)?;
    if !previous.runtime_id.is_empty()
        && !next.runtime_id.is_empty()
        && previous.runtime_id != next.runtime_id
    {
        return Err(Failure::Error(
            "native_context_assistance_switch_required".into(),
        ));
    }
    Ok(())
}
pub(super) fn fence(previous: Option<&str>, next: &mut String, force: bool) -> Result<(), Failure> {
    let old = assistance_preferences(previous.unwrap_or_default())?;
    let new = assistance_preferences(next)?;
    if !force && old == new {
        return Ok(());
    }
    let mut hash = Sha256::new();
    hash.update(b"guard-cigar-intent-ordering.v1\0");
    hash.update([u8::from(previous.is_some())]);
    hash.update(previous.unwrap_or_default().as_bytes());
    hash.update(
        serde_json::to_vec(&new)
            .map_err(|_| Failure::Error("context_assistance_revision_invalid".into()))?,
    );
    let mut document: toml_edit::DocumentMut = next
        .parse()
        .map_err(|_| Failure::Error("config_malformed".into()))?;
    document[REVISION] = toml_edit::value(format!("sha256:{:x}", hash.finalize()));
    *next = document.to_string();
    Ok(())
}
struct HomeStamp {
    canonical: PathBuf,
    node: io::RootIdentity,
}
impl HomeStamp {
    fn capture(home: &Path) -> Result<Self, Failure> {
        let unavailable = || Failure::Error("config_directory_unavailable".into());
        let canonical = fs::canonicalize(home).map_err(|_| unavailable())?;
        let node = io::root_identity_of(home).map_err(|_| unavailable())?;
        Ok(Self { canonical, node })
    }
    fn check(&self, home: &Path) -> Result<(), Failure> {
        let now = Self::capture(home)?;
        if now.canonical != self.canonical || now.node != self.node {
            return Err(Failure::Error("config_directory_changed".into()));
        }
        Ok(())
    }
}
pub(super) fn write(request: &UpdateRequest, value: &PyVal) -> Result<Value, Failure> {
    let home = &request.guard_home;
    let identity = HomeStamp::capture(home)?;
    let stored = read_home_config(home)?;
    let mut computed = compute(
        &request.kind,
        stored.as_deref(),
        value,
        request.managed.as_ref(),
        request.cloud_sync_entitled,
        &now_iso(),
    )?;
    fence(stored.as_deref(), &mut computed.text, false)?;
    let mut lease = None;
    if request.kind == "settings" {
        require_selection_job(stored.as_deref(), &computed.text)?;
        if let Some(id) = needs_verification(stored.as_deref(), &computed.text)? {
            // A malformed/missing enrollment must not provision job stores.
            // This first read is metadata only; full byte validation repeats
            // under the shared lifecycle lease, with no config lock held.
            crate::policy_store::context_assistance_registry::load(home, &id)
                .map_err(selection_error)?;
            lease = Some(
                crate::policy_store::context_assistance_registry::selection_lease(home)
                    .map_err(Failure::Error)?,
            );
            identity.check(home)?;
            crate::guard_config_load::cigar_updates::check_target(home, &id)
                .map_err(Failure::Error)?;
            verify_assistance_opt_in(home, stored.as_deref(), &computed.text)?;
        }
    }
    before_publish();
    let lock = io::WriteLock::acquire(home)?;
    identity.check(home)?;
    lock.publish(stored.as_deref(), &computed.text)?;
    drop(lease);
    Ok(computed.previous.unwrap_or(Value::Null))
}
#[cfg(test)]
thread_local! {static HOOK:std::cell::RefCell<Option<Box<dyn FnOnce()>>>=const{std::cell::RefCell::new(None)};}
fn before_publish() {
    #[cfg(test)]
    {
        let hook = HOOK.with(|h| h.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }
}
#[cfg(all(test, unix))]
pub(crate) fn with_publication_hook<T>(
    hook: impl FnOnce() + 'static,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with(|h| {
                h.borrow_mut().take();
            });
        }
    }
    HOOK.with(|h| {
        assert!(h.borrow().is_none());
        *h.borrow_mut() = Some(Box::new(hook));
    });
    let _reset = Reset;
    run()
}
