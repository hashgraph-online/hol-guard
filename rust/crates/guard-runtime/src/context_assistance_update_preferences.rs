//! Profile update intent is separate from serving SDK settings and authority.
//! Native machine policy and the existing short writer lane own publication.
use super::*;
use guard_cigar_release::UpdatePreferences;
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
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Settings {
    pub(crate) requested: UpdatePreferences,
    pub(crate) effective: UpdatePreferences,
    pub(crate) diagnostic: Option<String>,
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
    if let Some(policy) = crate::managed_policy_floor::effective_managed_policy(&state) {
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
