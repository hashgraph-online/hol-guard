//! Profile update intent is separate from serving SDK settings and authority.
//! Native machine policy and the existing short writer lane own publication.
use super::*;
use guard_cigar_release::{UpdateMode, UpdatePreferences};
use sha2::{Digest, Sha256};
pub(crate) const KEY: &str = "context_assistance_updates";
fn error(s: &str) -> String {
    format!("native_context_assistance_{s}")
}
fn storage(e: crate::guard_config_update::Failure) -> String {
    match e {
        crate::guard_config_update::Failure::Error(c) => error(&c),
        crate::guard_config_update::Failure::Invalid(_) => error("update_preferences_invalid"),
    }
}
pub(crate) fn native_source() -> crate::managed_policy_load::ManagedPolicySource {
    let mut s = crate::managed_policy_load::ManagedPolicySource::native();
    s.write_cache = false;
    s
}
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Settings {
    pub(crate) requested: UpdatePreferences,
    pub(crate) effective: UpdatePreferences,
    pub(crate) diagnostic: Option<String>,
    locked: Vec<String>,
}
fn revision(raw: Option<&str>) -> String {
    let mut h = Sha256::new();
    h.update(b"guard-cigar-update-preferences-revision.v1\0");
    h.update([u8::from(raw.is_some())]);
    h.update(raw.unwrap_or_default().as_bytes());
    format!("sha256:{:x}", h.finalize())
}
fn parse(raw: Option<&str>) -> Result<(UpdatePreferences, Option<String>), String> {
    let table: toml::Table = raw
        .unwrap_or_default()
        .parse()
        .map_err(|_| error("config_malformed"))?;
    let v = serde_json::to_value(table).map_err(|_| error("config_malformed"))?;
    match v.get(KEY) {
        None => Ok((UpdatePreferences::default(), None)),
        Some(v) => match UpdatePreferences::parse(v.clone()) {
            Ok(p) => Ok((p, None)),
            Err(e) => Ok((UpdatePreferences::default(), Some(error(e.code())))),
        },
    }
}
fn resolve(
    raw: Option<&str>,
    source: &crate::managed_policy_load::ManagedPolicySource,
) -> Result<Settings, String> {
    let (requested, mut diagnostic) = parse(raw)?;
    let state = crate::managed_policy_load::load_managed_policy(source);
    if state.status.fails_closed() {
        return Err(error("update_policy_unavailable"));
    }
    let mut effective = requested.clone();
    let mut locked = Vec::new();
    if let Some(policy) = crate::managed_policy_floor::effective_managed_policy(&state) {
        locked = policy
            .locked_settings
            .into_iter()
            .filter(|s| s == KEY || s.starts_with(&format!("{KEY}.")))
            .collect();
        if let Some(value) = policy.settings.get(KEY) {
            match requested.restrict(value) {
                Ok(p) => effective = p,
                Err(e) => {
                    effective = UpdatePreferences::default();
                    diagnostic = Some(error(e.code()));
                }
            }
        }
    }
    Ok(Settings {
        requested,
        effective,
        diagnostic,
        locked,
    })
}
pub(crate) fn load_with_source(
    home: &Path,
    source: &crate::managed_policy_load::ManagedPolicySource,
) -> Result<Settings, String> {
    let raw = crate::guard_config_update::read_home_config(home).map_err(storage)?;
    resolve(raw.as_deref(), source)
}
pub(crate) fn selection_rules(
    home: &Path,
    source: &crate::managed_policy_load::ManagedPolicySource,
) -> Result<UpdatePreferences, String> {
    let s = load_with_source(home, source)?;
    if let Some(code) = s.diagnostic {
        return Err(code);
    }
    Ok(s.effective)
}
fn view(s: Settings, raw: Option<&str>) -> Value {
    json!({"schema":"guard-cigar-update-preferences.v1","requested":s.requested,"effective":s.effective,
        "diagnostic":s.diagnostic,"locked_settings":s.locked,"revision":revision(raw),
        "capabilities":{"modes":["manual","notify"],"automatic_preparation":false,"automatic_selection":false,"retention_reduction":false}})
}
pub(crate) fn read(home: &Path) -> Result<Value, String> {
    let raw = crate::guard_config_update::read_home_config(home).map_err(storage)?;
    Ok(view(
        resolve(raw.as_deref(), &native_source())?,
        raw.as_deref(),
    ))
}
fn lock_conflict(s: &Settings) -> Result<bool, String> {
    let r = serde_json::to_value(&s.requested).map_err(|_| error("update_preferences_invalid"))?;
    let e = serde_json::to_value(&s.effective).map_err(|_| error("update_preferences_invalid"))?;
    Ok(s.locked.iter().any(|key| {
        if key == KEY {
            r != e
        } else {
            let part = key.strip_prefix(&format!("{KEY}.")).unwrap_or_default();
            r.get(part) != e.get(part)
        }
    }))
}
pub(crate) fn write(
    home: &Path,
    expected: &str,
    preferences: UpdatePreferences,
) -> Result<Value, String> {
    write_with_source(home, expected, preferences, &native_source())
}
fn write_with_source(
    home: &Path,
    expected: &str,
    preferences: UpdatePreferences,
    source: &crate::managed_policy_load::ManagedPolicySource,
) -> Result<Value, String> {
    preferences.validate().map_err(|e| error(e.code()))?;
    if preferences.mode == UpdateMode::Prepare {
        return Err(error("update_preparation_policy_unavailable"));
    }
    if !preferences.retain_last_good {
        return Err(error("update_retention_reduction_unavailable"));
    }
    if expected.len() != 71
        || !expected.starts_with("sha256:")
        || !expected[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error("versions_request_invalid"));
    }
    let lock = crate::guard_config_update::io::WriteLock::acquire(home).map_err(storage)?;
    let raw = crate::guard_config_update::read_home_config(home).map_err(storage)?;
    if revision(raw.as_deref()) != expected {
        return Err(error("update_preferences_conflict"));
    }
    let mut doc: toml_edit::DocumentMut = raw
        .as_deref()
        .unwrap_or_default()
        .parse()
        .map_err(|_| error("config_malformed"))?;
    let table = toml_edit::ser::to_document(&preferences)
        .map_err(|_| error("update_preferences_invalid"))?;
    doc[KEY] = toml_edit::Item::Table(table.as_table().clone());
    let next = doc.to_string();
    let state = resolve(Some(&next), source)?;
    if let Some(code) = &state.diagnostic {
        return Err(code.clone());
    }
    if lock_conflict(&state)? {
        return Err(error("update_preferences_locked"));
    }
    lock.publish(raw.as_deref(), &next).map_err(storage)?;
    Ok(view(state, Some(&next)))
}
/// Called only for a new selection, never to revoke a healthy running SDK.
pub(crate) fn check_target(home: &Path, id: &str) -> Result<(), String> {
    let prefs = selection_rules(home, &native_source())?;
    let installed = crate::policy_store::context_assistance_registry::load(home, id)?;
    check_installation(home, &prefs, &installed)
}
pub(crate) fn check_installation(
    home: &Path,
    prefs: &UpdatePreferences,
    installation: &crate::policy_store::context_assistance_registry::Installation,
) -> Result<(), String> {
    let binding = installation.approval.release.as_ref();
    if prefs
        .pinned_build
        .as_deref()
        .is_some_and(|p| binding.is_none_or(|b| b.identity.build_id != p))
    {
        return Err(error("update_pin_conflict"));
    }
    let Some(binding) = binding else {
        return Ok(());
    };
    let snapshot = crate::policy_store::context_assistance_registry::catalog::installed(home)?;
    snapshot.check_sdk(&binding.identity.build_id)?;
    let build = snapshot
        .catalog
        .document()
        .builds
        .iter()
        .find(|b| b.identity == binding.identity)
        .ok_or_else(|| error("cigar_build_unknown"))?;
    if build.channel == guard_cigar_release::Channel::Preview && !prefs.allow_preview {
        return Err(error("cigar_preview_disabled"));
    }
    Ok(())
}
#[cfg(all(test, unix))]
#[path = "context_assistance_update_preferences_tests.rs"]
mod tests;
