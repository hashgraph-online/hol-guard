//! Native authority for the existing Cloud Review opt-in. No SDK state fallback.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Mutex;

pub(crate) static CONSENT_LOCK: Mutex<()> = Mutex::new(());
const MAX_BYTES: usize = 4096;
pub(crate) fn transaction(home: &Path) -> Result<std::fs::File, String> {
    let root = crate::resident_state::private_root_for_state_base(home)?;
    let path = home.join("cloud-review-authority.lock");
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, &root)?;
    #[cfg(windows)]
    let (file, _directory_binding) = crate::resident_state::private_lock_file(&path, &root)?;
    fs2::FileExt::try_lock_exclusive(&file)
        .map_err(|_| "native_cloud_review_authority_busy".to_owned())?;
    Ok(file)
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsentRequest {
    pub schema: String,
    pub version: u16,
    pub operation: String,
    pub ttl_seconds: Option<u64>,
    pub approval_gate_input: Option<ConsentFactors>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsentFactors {
    pub password: Option<String>,
    pub totp_code: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsentState {
    schema: String,
    version: u16,
    pub(crate) revision: u64,
    pub(crate) revocation_epoch: u64,
    pub(crate) enabled: bool,
    issued_at_ms: u64,
    expires_at_ms: u64,
}
impl Default for ConsentState {
    fn default() -> Self {
        Self {
            schema: "guard-native-cloud-review-consent-state.v1".into(),
            version: 1,
            revision: 0,
            revocation_epoch: 0,
            enabled: false,
            issued_at_ms: 0,
            expires_at_ms: 0,
        }
    }
}
pub(crate) fn load(home: &Path) -> Result<ConsentState, String> {
    let Some(text) = read_secret(home)? else {
        return Ok(ConsentState::default());
    };
    let state: ConsentState = serde_json::from_str(&text)
        .map_err(|_| "native_cloud_review_consent_invalid".to_owned())?;
    if state.schema != "guard-native-cloud-review-consent-state.v1"
        || state.version != 1
        || (state.enabled && (state.revision == 0 || state.expires_at_ms <= state.issued_at_ms))
    {
        return Err("native_cloud_review_consent_invalid".into());
    }
    Ok(state)
}
pub(crate) fn require_enabled(home: &Path, now: u64) -> Result<ConsentState, String> {
    let state = load(home)?;
    if !state.enabled {
        return Err("native_cloud_review_consent_disabled".into());
    }
    if now < state.issued_at_ms || now >= state.expires_at_ms {
        return Err("native_cloud_review_consent_expired".into());
    }
    Ok(state)
}
pub(crate) fn evaluate(
    request: ConsentRequest,
    store: &super::PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != "guard-native-cloud-review-consent-request.v1" || request.version != 1 {
        return Err("native_cloud_review_consent_request_invalid".into());
    }
    let _lock = CONSENT_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_consent_unavailable".to_owned())?;
    let home = store.state_base();
    let _transaction = transaction(home)?;
    let now = super::now_ms()?;
    let mut state = load(home)?;
    match request.operation.as_str() {
        "read" => {
            if request.ttl_seconds.is_some() || request.approval_gate_input.is_some() {
                return Err("native_cloud_review_consent_request_invalid".into());
            }
        }
        "enable" => {
            let ttl = request.ttl_seconds.unwrap_or(30 * 24 * 60 * 60);
            if ttl == 0 || ttl > 365 * 24 * 60 * 60 {
                return Err("native_cloud_review_consent_ttl_invalid".into());
            }
            let factors = request
                .approval_gate_input
                .ok_or("approval_gate_password_required")?;
            // Factor authority belongs to the canonical Guard scope, not the
            // native-runtime storage subdirectory (which may have a shadow gate).
            let (scope_home, _) = super::policy_store_authority::scope_binding_for_state_base(home);
            authenticate_enable(Path::new(&scope_home), factors)?;
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or("native_cloud_review_consent_revision_invalid")?;
            state.enabled = true;
            state.issued_at_ms = now;
            state.expires_at_ms = now
                .checked_add(ttl * 1000)
                .ok_or("native_cloud_review_consent_clock_invalid")?;
            persist(home, &state)?;
        }
        "disable" => {
            if request.ttl_seconds.is_some() || request.approval_gate_input.is_some() {
                return Err("native_cloud_review_consent_request_invalid".into());
            }
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or("native_cloud_review_consent_revision_invalid")?;
            state.revocation_epoch = state
                .revocation_epoch
                .checked_add(1)
                .ok_or("native_cloud_review_consent_revision_invalid")?;
            state.enabled = false;
            state.expires_at_ms = now;
            persist(home, &state)?;
        }
        _ => return Err("native_cloud_review_consent_request_invalid".into()),
    }
    crate::encode_response(
        &json!({"schema":"guard-native-cloud-review-consent-result.v1", "version":1,
        "status": if !state.enabled { "disabled" } else if now < state.issued_at_ms || now >= state.expires_at_ms { "expired" } else { "enabled" },
        "revision": state.revision, "revocation_epoch": state.revocation_epoch,
        "issued_at_ms": state.issued_at_ms, "expires_at_ms": state.expires_at_ms, "native": true}),
    )
}
fn persist(home: &Path, state: &ConsentState) -> Result<(), String> {
    write_secret(
        home,
        &serde_json::to_string(state)
            .map_err(|_| "native_cloud_review_consent_invalid".to_owned())?,
    )
}

fn authenticate_enable(home: &Path, factors: ConsentFactors) -> Result<(), String> {
    let _gate_lock = crate::approval_gate_op::PRIVILEGE_LOCK
        .lock()
        .map_err(|_| "native_approval_gate_unavailable".to_owned())?;
    let mut gate = crate::approval_gate_state::load_state(home);
    if crate::approval_gate_state::verifier(&gate).is_none() {
        return Err("approval_gate_recovery_required".into());
    }
    if factors.password.as_deref().is_none_or(str::is_empty) {
        return Err("approval_gate_password_required".into());
    }
    if gate.get("totp_enabled") == Some(&Value::Bool(true)) && factors.totp_code.is_none() {
        return Err("approval_gate_totp_required".into());
    }
    // A TOTP grant records password_verified false: the password stage does not
    // run on that path. Consent still has to check the password itself.
    crate::approval_gate_verify::verify_password_stage(
        home,
        &mut gate,
        factors.password.as_deref(),
        None,
    )
    .map_err(|error| error.code)?;
    let input = crate::approval_gate_verify::ApprovalGateInputV1 {
        password: factors.password,
        totp_code: factors.totp_code,
        ..Default::default()
    };
    let grant = crate::approval_gate_verify::verify_or_raise_locked(
        home,
        &mut gate,
        crate::approval_gate_op::grants(),
        "native_cloud_review_consent",
        Some(&input),
        true,
        None,
        None,
        None,
        None,
        None,
    )
    .map_err(|error| error.code)?;
    if grant.used_cooldown
        || (gate.get("totp_enabled") == Some(&Value::Bool(true)) && !grant.totp_verified)
    {
        return Err("native_cloud_review_consent_factor_invalid".into());
    }
    Ok(())
}
#[cfg(not(test))]
fn account(home: &Path) -> Result<String, String> {
    Ok(format!(
        "{}:cloud-review-consent-v1",
        super::approval_enrollment::account_for_state_base(home)?
    ))
}
#[cfg(not(test))]
fn read_secret(home: &Path) -> Result<Option<String>, String> {
    super::approval_enrollment::read_platform_secret_for_v4_state(home, &account(home)?, MAX_BYTES)
}
#[cfg(not(test))]
fn write_secret(home: &Path, text: &str) -> Result<(), String> {
    super::approval_enrollment::write_platform_secret_for_v4_state(
        home,
        &account(home)?,
        text,
        MAX_BYTES,
    )
}
#[cfg(test)]
fn read_secret(home: &Path) -> Result<Option<String>, String> {
    Ok(super::policy_store_persistence::read_private_json(
        &home.join("cloud-review-consent.test.json"),
        MAX_BYTES as u64,
        "cloud_review_consent",
        home,
    )?
    .map(|(_, bytes)| String::from_utf8_lossy(&bytes).into_owned()))
}
#[cfg(test)]
fn write_secret(home: &Path, text: &str) -> Result<(), String> {
    super::policy_store_persistence::persist_private_bytes(
        &home.join("cloud-review-consent.test.json"),
        text.as_bytes(),
        MAX_BYTES as u64,
        "cloud_review_consent",
        home,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_is_disabled_and_client_factor_booleans_are_rejected() {
        let home = std::env::temp_dir().join(format!(
            "native-cloud-consent-missing-{}-{}",
            std::process::id(),
            super::super::now_ms().unwrap()
        ));
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let state = load(&home).unwrap();
        assert!(!state.enabled);
        assert_eq!(state.revision, 0);
        assert_eq!(
            require_enabled(&home, 1).unwrap_err(),
            "native_cloud_review_consent_disabled"
        );
        assert!(serde_json::from_value::<ConsentRequest>(json!({
            "schema":"guard-native-cloud-review-consent-request.v1", "version":1,
            "operation":"enable", "approval_gate_input":{"passwordVerified":true}
        }))
        .is_err());
        assert_eq!(
            authenticate_enable(
                &home,
                ConsentFactors {
                    password: Some("supplied-without-native-verifier".into()),
                    totp_code: None,
                }
            )
            .unwrap_err(),
            "approval_gate_recovery_required"
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn persisted_revocation_and_expiry_never_authorize() {
        let home = std::env::temp_dir().join(format!(
            "native-cloud-consent-revoked-{}-{}",
            std::process::id(),
            super::super::now_ms().unwrap()
        ));
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut state = ConsentState {
            revision: 4,
            revocation_epoch: 2,
            enabled: true,
            issued_at_ms: 100,
            expires_at_ms: 200,
            ..Default::default()
        };
        persist(&home, &state).unwrap();
        assert_eq!(require_enabled(&home, 100).unwrap().revocation_epoch, 2);
        assert_eq!(
            require_enabled(&home, 200).unwrap_err(),
            "native_cloud_review_consent_expired"
        );
        assert_eq!(
            require_enabled(&home, 99).unwrap_err(),
            "native_cloud_review_consent_expired"
        );
        state.enabled = false;
        state.revision += 1;
        state.revocation_epoch += 1;
        persist(&home, &state).unwrap();
        let reread = load(&home).unwrap();
        assert_eq!(reread.revision, 5);
        assert_eq!(reread.revocation_epoch, 3);
        assert_eq!(
            require_enabled(&home, 150).unwrap_err(),
            "native_cloud_review_consent_disabled"
        );
        std::fs::remove_dir_all(home).unwrap();
    }
}
