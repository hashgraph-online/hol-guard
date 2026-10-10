#![forbid(unsafe_code)]
//! `approval_gate.py` `_ACTIVE_GRANTS` lifecycle — resident-process grant table.
//!
//! Port scope: the grant *table* (register/validate/consume/invalidate/prune)
//! plus the `ApprovalGateGrant` frozen-handle semantics. The verification arm
//! (`_verify_or_raise_locked`: password verify, TOTP, cooldown) is a sibling
//! slice (RTM-013) — this module takes the *outcome* of verification
//! (`factor_set`, `password_verified`, `totp_verified`, `factor_generation`,
//! `totp_enabled`) as parameters, mirroring how `policy_integrity_resolver`
//! keeps key bytes caller-side.
//!
//! Conventions follow `approval_replay_memory.rs`: `Mutex` over a `HashMap`,
//! capacity-bounded, poison → fail-closed error.
//!
//! # Fork-safety
//!
//! Python's `_ACTIVE_GRANTS` is never registered with `fork_safety.forget_in_child`,
//! so a POSIX `fork()` child inherits live grants for the residual TTL (the
//! `_factor_generation` re-read still revokes rotated grants, but an unexpired
//! same-generation grant validates in the child). The resident is the sole
//! grant authority post-port — children never hold the table — and `owner_pid`
//! is stamped into metadata and re-checked at validate as belt-and-braces for
//! any embedding that keeps an in-process table. See `/tmp/rtm009c-grant-map.md`.

use std::collections::HashMap;
use std::sync::Mutex;

/// `APPROVAL_GATE_GRANT_TTL_SECONDS = 30` (`approval_gate.py:70`).
#[allow(dead_code)]
pub const APPROVAL_GATE_GRANT_TTL_SECONDS: f64 = 30.0;
/// Capacity bound — mirrors `NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES`.
/// Python has no bound; the port adds one to cap unbounded in-memory growth.
pub const NATIVE_APPROVAL_GRANTS_MAX_ENTRIES: usize = 4096;
/// `expires_at` parity tolerance (`approval_gate.py:891`): ±1 ms.
pub const EXPIRES_AT_TOLERANCE_SECONDS: f64 = 0.001;

/// `ApprovalGateError` (`approval_gate.py:103-126`) — code + message + HTTP status.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalGateErrorV1 {
    pub code: String,
    pub message: String,
    pub status: u16,
}

impl ApprovalGateErrorV1 {
    fn new(code: &str, message: &str, status: u16) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
            status,
        }
    }
    fn required(message: &str) -> Self {
        Self::new("approval_gate_required", message, 403)
    }
    fn totp_required(message: &str) -> Self {
        Self::new("approval_gate_totp_required", message, 403)
    }
    fn password_required(message: &str) -> Self {
        Self::new("approval_gate_password_required", message, 403)
    }
    fn expired() -> Self {
        Self::new(
            "approval_gate_grant_expired",
            "Approval proof expired. Enter your approval proof again.",
            403,
        )
    }
}

/// `ApprovalGateGrant` (`approval_gate.py:140-158`) — the frozen wire handle.
/// Self-describing but unforgeable: authenticity is table-presence + parity.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalGateGrantV1 {
    pub grant_id: String,
    pub purpose: String,
    pub issued_at: String,
    pub expires_at: String,
    pub action: String,
    pub scope: String,
    pub subject: String,
    pub session_nonce: String,
    pub factor_set: Vec<String>,
    pub strict: bool,
    pub used_cooldown: bool,
    pub cooldown_expires_at: Option<String>,
    pub password_verified: bool,
    pub totp_verified: bool,
}

/// `_ACTIVE_GRANTS[grant_id]` metadata (:1102-1116) + `owner_pid` (fork fix).
#[derive(Debug, Clone)]
struct GrantMetadata {
    guard_home: String,
    expires_epoch: f64,
    purpose: String,
    strict: bool,
    used_cooldown: bool,
    password_verified: bool,
    totp_verified: bool,
    action: String,
    scope: String,
    subject: String,
    session_nonce: String,
    factor_set: Vec<String>,
    factor_generation: i64,
    /// `std::process::id()` at register; validate rejects a mismatch (fork /
    /// stale-table guard absent in Python).
    owner_pid: u32,
}

/// Caller-supplied grant fields — everything `_register_grant` takes except the
/// generated ids/timestamps (which the table owns).
pub(crate) struct GrantFields<'a> {
    pub purpose: &'a str,
    pub action: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub session_nonce: Option<&'a str>,
    pub factor_set: Vec<String>,
    pub strict: bool,
    pub used_cooldown: bool,
    pub cooldown_expires_at: Option<String>,
    pub password_verified: bool,
    pub totp_verified: bool,
    /// `_factor_generation(state)` — caller re-reads `approval-gate.json`.
    pub factor_generation: i64,
    /// Caller-supplied `secrets.token_urlsafe(24)` — 32-char id. The table does
    /// not mint randomness; the caller injects it for determinism/testability.
    pub grant_id: String,
    /// Caller-supplied `secrets.token_urlsafe(18)` for auto subject/nonce.
    pub subject_token: String,
    pub nonce_token: String,
}

#[derive(Default)]
struct GrantState {
    entries: HashMap<String, GrantMetadata>,
}

/// One-resident grant table. `Mutex` (not `RwLock`) matches Python's single
/// RLock discipline; poison → `approval_gate_required` (fail-closed).
pub(crate) struct ApprovalGateGrants {
    state: Mutex<GrantState>,
}

#[allow(dead_code)]
impl ApprovalGateGrants {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(GrantState::default()),
        }
    }

    /// `prune_grants` (`approval_gate_state.py:202-208`) — drop `expires_epoch <= now`.
    fn prune_locked(state: &mut GrantState, now_epoch: f64) {
        state.entries.retain(|_, m| m.expires_epoch > now_epoch);
    }

    /// `_register_grant` (:1063-1119). Lazy insert-side prune (Python parity),
    /// capacity check, then insert. `owner_pid` = current process.
    ///
    /// `now_epoch`/`expires_epoch`/`issued_at`/`expires_at` are caller-resolved
    /// (the caller owns epoch↔ISO conversion via `utc_timestamp`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register(
        &self,
        guard_home: &str,
        fields: GrantFields<'_>,
        now_epoch: f64,
        issued_at: &str,
        expires_at: &str,
        expires_epoch: f64,
    ) -> Result<ApprovalGateGrantV1, ApprovalGateErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ApprovalGateErrorV1::required("Approval proof is required."))?;
        // Insert-side prune runs before insert (Python calls it after insert;
        // order is observably identical — both leave only unexpired + the new row).
        Self::prune_locked(&mut state, now_epoch);
        if state.entries.len() >= NATIVE_APPROVAL_GRANTS_MAX_ENTRIES {
            return Err(ApprovalGateErrorV1::required("Approval proof is required."));
        }
        let resolved_action = fields.action.unwrap_or(fields.purpose).to_owned();
        let resolved_scope = fields.scope.unwrap_or("local").to_owned();
        let resolved_subject = fields
            .subject
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{}:transaction:{}", fields.purpose, fields.subject_token));
        let resolved_nonce = fields
            .session_nonce
            .map(str::to_owned)
            .unwrap_or_else(|| fields.nonce_token.clone());
        let metadata = GrantMetadata {
            guard_home: guard_home.to_owned(),
            expires_epoch,
            purpose: fields.purpose.to_owned(),
            strict: fields.strict,
            used_cooldown: fields.used_cooldown,
            password_verified: fields.password_verified,
            totp_verified: fields.totp_verified,
            action: resolved_action.clone(),
            scope: resolved_scope.clone(),
            subject: resolved_subject.clone(),
            session_nonce: resolved_nonce.clone(),
            factor_set: fields.factor_set.clone(),
            factor_generation: fields.factor_generation,
            owner_pid: std::process::id(),
        };
        state.entries.insert(fields.grant_id.clone(), metadata);
        Ok(ApprovalGateGrantV1 {
            grant_id: fields.grant_id,
            purpose: fields.purpose.to_owned(),
            issued_at: issued_at.to_owned(),
            expires_at: expires_at.to_owned(),
            action: resolved_action,
            scope: resolved_scope,
            subject: resolved_subject,
            session_nonce: resolved_nonce,
            factor_set: fields.factor_set,
            strict: fields.strict,
            used_cooldown: fields.used_cooldown,
            cooldown_expires_at: fields.cooldown_expires_at,
            password_verified: fields.password_verified,
            totp_verified: fields.totp_verified,
        })
    }

    /// `_validate_grant_locked` (:846-915) — check order preserved verbatim.
    ///
    /// `grant_expires_epoch` is `metadata.expires_epoch` re-derived via the
    /// caller's `_epoch(grant.expires_at)` for the numeric-parity arm; the
    /// caller parses the ISO wire `expires_at` to seconds (Python `_epoch`),
    /// returning `None`→`0.0` for unparseable (mirrors `optional_float`).
    /// `totp_enabled`/`current_factor_generation`/`totp_state_valid` come from
    /// the caller's fresh `approval-gate.json` read.
    #[allow(clippy::too_many_arguments)]
    fn validate_locked(
        state: &mut GrantState,
        grant_home: &str,
        grant: Option<&ApprovalGateGrantV1>,
        grant_expires_epoch: f64,
        purpose: Option<&str>,
        strict: bool,
        action: Option<&str>,
        scope: Option<&str>,
        subject: Option<&str>,
        session_nonce: Option<&str>,
        current_factor_generation: i64,
        totp_enabled: bool,
        totp_state_valid: bool,
        now_epoch: f64,
    ) -> Result<(), ApprovalGateErrorV1> {
        // (1) missing grant
        let grant = match grant {
            Some(g) => g,
            None => {
                return Err(if totp_enabled {
                    ApprovalGateErrorV1::totp_required("TOTP code is required.")
                } else {
                    ApprovalGateErrorV1::required("Approval password is required.")
                });
            }
        };
        // (2) unknown grant_id
        let metadata = match state.entries.get(&grant.grant_id) {
            Some(m) => m.clone(),
            None => return Err(ApprovalGateErrorV1::required("Approval proof is required.")),
        };
        // (3) cross-home → "invalid" (distinct message from missing, same code)
        if metadata.guard_home != grant_home {
            return Err(ApprovalGateErrorV1::required("Approval proof is invalid."));
        }
        // (4) expiry — inclusive `<=`, pop on expiry
        if metadata.expires_epoch <= now_epoch {
            state.entries.remove(&grant.grant_id);
            return Err(ApprovalGateErrorV1::expired());
        }
        // (5) immutable-field parity — `factor_set` compared as Vec (tuple eq)
        let parity_fail = metadata.purpose != grant.purpose
            || metadata.strict != grant.strict
            || metadata.used_cooldown != grant.used_cooldown
            || metadata.password_verified != grant.password_verified
            || metadata.totp_verified != grant.totp_verified
            || metadata.action != grant.action
            || metadata.scope != grant.scope
            || metadata.subject != grant.subject
            || metadata.session_nonce != grant.session_nonce
            || metadata.factor_set != grant.factor_set;
        if parity_fail {
            return Err(ApprovalGateErrorV1::required("Approval proof is invalid."));
        }
        // (6) expires_at numeric parity, ±1 ms (NOT string equality)
        if (grant_expires_epoch - metadata.expires_epoch).abs() > EXPIRES_AT_TOLERANCE_SECONDS {
            return Err(ApprovalGateErrorV1::required("Approval proof is invalid."));
        }
        // (7) factor_generation — rotation revokes; pop on mismatch
        if metadata.factor_generation != current_factor_generation {
            state.entries.remove(&grant.grant_id);
            return Err(ApprovalGateErrorV1::required(
                "Approval proof was revoked. Enter your approval proof again.",
            ));
        }
        // (8) owner_pid — fork/stale-table guard (port hardening; absent in Python).
        if metadata.owner_pid != std::process::id() {
            state.entries.remove(&grant.grant_id);
            return Err(ApprovalGateErrorV1::required("Approval proof is required."));
        }
        // (9) expected-field matchers — purpose/action/scope/subject/nonce
        if let Some(p) = purpose {
            if grant.purpose != p {
                return Err(ApprovalGateErrorV1::required(
                    "Approval proof does not match this purpose.",
                ));
            }
        }
        if let Some(a) = action {
            if grant.action != a {
                return Err(ApprovalGateErrorV1::required(
                    "Approval proof does not match this action.",
                ));
            }
        }
        if let Some(sc) = scope {
            if grant.scope != sc {
                return Err(ApprovalGateErrorV1::required(
                    "Approval proof does not match this scope.",
                ));
            }
        }
        if let Some(su) = subject {
            if grant.subject != su {
                return Err(ApprovalGateErrorV1::required(
                    "Approval proof does not match this subject.",
                ));
            }
        }
        if let Some(sn) = session_nonce {
            if grant.session_nonce != sn {
                return Err(ApprovalGateErrorV1::required(
                    "Approval proof does not match this session.",
                ));
            }
        }
        // (10) strict ⇒ grant.strict
        if strict && !grant.strict {
            return Err(ApprovalGateErrorV1::required(
                "A fresh approval proof is required.",
            ));
        }
        // (11) TOTP-enabled path vs strict-password path
        if totp_enabled {
            if !totp_state_valid {
                return Err(ApprovalGateErrorV1 {
                    code: "approval_gate_recovery_required".to_owned(),
                    message: "Approval gate TOTP secret is unavailable.".to_owned(),
                    status: 423,
                });
            }
            let is_totp_factor = grant.factor_set == ["totp"];
            if !is_totp_factor || !grant.totp_verified {
                return Err(ApprovalGateErrorV1::totp_required("TOTP code is required."));
            }
        } else if strict && grant.factor_set != ["password"] {
            return Err(ApprovalGateErrorV1::password_required(
                "Approval password is required.",
            ));
        }
        Ok(())
    }

    /// `validate_grant` (:832-846) — multi-use within TTL (does NOT pop).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate(
        &self,
        grant_home: &str,
        grant: Option<&ApprovalGateGrantV1>,
        grant_expires_epoch: f64,
        purpose: Option<&str>,
        strict: bool,
        action: Option<&str>,
        scope: Option<&str>,
        subject: Option<&str>,
        session_nonce: Option<&str>,
        current_factor_generation: i64,
        totp_enabled: bool,
        totp_state_valid: bool,
        now_epoch: f64,
    ) -> Result<(), ApprovalGateErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ApprovalGateErrorV1::required("Approval proof is required."))?;
        Self::validate_locked(
            &mut state,
            grant_home,
            grant,
            grant_expires_epoch,
            purpose,
            strict,
            action,
            scope,
            subject,
            session_nonce,
            current_factor_generation,
            totp_enabled,
            totp_state_valid,
            now_epoch,
        )
    }

    /// `consume_*_grant` (:725-748 / :781-804) — validate then pop, single-use.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_and_consume(
        &self,
        grant_home: &str,
        grant: &ApprovalGateGrantV1,
        grant_expires_epoch: f64,
        purpose: Option<&str>,
        strict: bool,
        action: Option<&str>,
        scope: Option<&str>,
        subject: Option<&str>,
        session_nonce: Option<&str>,
        current_factor_generation: i64,
        totp_enabled: bool,
        totp_state_valid: bool,
        now_epoch: f64,
    ) -> Result<(), ApprovalGateErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ApprovalGateErrorV1::required("Approval proof is required."))?;
        Self::validate_locked(
            &mut state,
            grant_home,
            Some(grant),
            grant_expires_epoch,
            purpose,
            strict,
            action,
            scope,
            subject,
            session_nonce,
            current_factor_generation,
            totp_enabled,
            totp_state_valid,
            now_epoch,
        )?;
        state.entries.remove(&grant.grant_id);
        Ok(())
    }

    /// `_invalidate_active_grants` (:1138-1141) — drop every row for `guard_home`.
    pub(crate) fn invalidate_for_home(&self, guard_home: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.entries.retain(|_, m| m.guard_home != guard_home);
        }
    }

    /// `prune_grants` exposed for tests / periodic maintenance.
    pub(crate) fn prune(&self, now_epoch: f64) {
        if let Ok(mut state) = self.state.lock() {
            Self::prune_locked(&mut state, now_epoch);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.state.lock().map(|s| s.entries.len()).unwrap_or(0)
    }
}

impl Default for ApprovalGateGrants {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/g/home";

    fn fields(purpose: &str) -> GrantFields<'_> {
        GrantFields {
            purpose,
            action: None,
            scope: None,
            subject: None,
            session_nonce: None,
            factor_set: vec!["password".into()],
            strict: false,
            used_cooldown: false,
            cooldown_expires_at: None,
            password_verified: true,
            totp_verified: false,
            factor_generation: 1,
            grant_id: format!("grant-{purpose}"),
            subject_token: "tok-subj".into(),
            nonce_token: "tok-nonce".into(),
        }
    }

    /// Common validate args (no expected matchers, gen 1, TOTP off).
    #[allow(clippy::too_many_arguments)]
    // All test grants register at issued_now=100 -> expires_epoch=130.
    const ISSUE_EPOCH: f64 = 100.0;
    const GRANT_EPOCH: f64 = ISSUE_EPOCH + APPROVAL_GATE_GRANT_TTL_SECONDS; // 130

    fn val(
        t: &ApprovalGateGrants,
        g: Option<&ApprovalGateGrantV1>,
        now: f64,
    ) -> Result<(), ApprovalGateErrorV1> {
        t.validate(
            HOME,
            g,
            GRANT_EPOCH,
            None,
            false,
            None,
            None,
            None,
            None,
            1,
            false,
            true,
            now,
        )
    }

    fn reg(t: &ApprovalGateGrants, purpose: &str, now: f64) -> ApprovalGateGrantV1 {
        let exp_epoch = now + APPROVAL_GATE_GRANT_TTL_SECONDS;
        t.register(
            HOME,
            fields(purpose),
            now,
            "issued-iso",
            "expires-iso",
            exp_epoch,
        )
        .unwrap()
    }

    // 1. register then validate within TTL
    #[test]
    fn register_then_validate_within_ttl() {
        let t = ApprovalGateGrants::new();
        let g = reg(&t, "policy_write", ISSUE_EPOCH);
        assert_eq!(g.action, "policy_write"); // action defaults to purpose
        assert_eq!(g.scope, "local");
        assert_eq!(g.subject, "policy_write:transaction:tok-subj");
        assert_eq!(g.session_nonce, "tok-nonce");
        assert!(val(&t, Some(&g), 110.0).is_ok());
    }

    // 2. expired at exact boundary is expired + popped
    #[test]
    fn expired_at_exact_boundary() {
        let t = ApprovalGateGrants::new();
        let g = reg(&t, "policy_write", ISSUE_EPOCH);
        let e = val(&t, Some(&g), 130.0).unwrap_err(); // now == expires_epoch
        assert_eq!(e.code, "approval_gate_grant_expired");
        assert_eq!(t.len(), 0);
    }

    // 3. unknown grant_id -> required
    #[test]
    fn unknown_grant_is_required() {
        let t = ApprovalGateGrants::new();
        let mut g = reg(&t, "policy_write", 100.0);
        g.grant_id = "nope".into();
        let e = val(&t, Some(&g), 110.0).unwrap_err();
        assert_eq!(e.code, "approval_gate_required");
        assert_eq!(e.message, "Approval proof is required.");
    }

    // 4. cross-home -> invalid (distinct message, same code), no pop
    #[test]
    fn foreign_home_is_invalid() {
        let t = ApprovalGateGrants::new();
        let g = reg(&t, "policy_write", ISSUE_EPOCH);
        let e = t
            .validate(
                "/other",
                Some(&g),
                999.0,
                None,
                false,
                None,
                None,
                None,
                None,
                1,
                false,
                true,
                110.0,
            )
            .unwrap_err();
        assert_eq!(e.code, "approval_gate_required");
        assert_eq!(e.message, "Approval proof is invalid.");
        assert_eq!(t.len(), 1); // not popped
    }

    // 5. immutable-field tamper rejected
    #[test]
    fn immutable_tamper_rejected() {
        let t = ApprovalGateGrants::new();
        let g = reg(&t, "policy_write", ISSUE_EPOCH);
        for mutate in [
            |x: &mut ApprovalGateGrantV1| x.action = "evil".into(),
            |x: &mut ApprovalGateGrantV1| x.purpose = "other".into(),
            |x: &mut ApprovalGateGrantV1| x.strict = !x.strict,
            |x: &mut ApprovalGateGrantV1| x.factor_set = vec!["totp".into()],
            |x: &mut ApprovalGateGrantV1| x.subject = "subj-x".into(),
        ] {
            let mut gg = g.clone();
            mutate(&mut gg);
            let e = val(&t, Some(&gg), 110.0).unwrap_err();
            assert_eq!(e.code, "approval_gate_required");
            assert_eq!(e.message, "Approval proof is invalid.");
        }
    }

    // 6. factor_generation advance revokes + pops
    #[test]
    fn generation_advance_revokes() {
        let t = ApprovalGateGrants::new();
        let g = reg(&t, "policy_write", ISSUE_EPOCH); // gen 1
        let e = t
            .validate(
                HOME,
                Some(&g),
                130.0,
                None,
                false,
                None,
                None,
                None,
                None,
                2,
                false,
                true,
                110.0,
            )
            .unwrap_err();
        assert_eq!(e.code, "approval_gate_required");
        assert!(e.message.contains("revoked"));
        assert_eq!(t.len(), 0);
    }

    // 7. consume is single-use
    #[test]
    fn consume_single_use() {
        let t = ApprovalGateGrants::new();
        let g = reg(&t, "extension_control_mutation", ISSUE_EPOCH);
        let epoch = 130.0;
        assert!(t
            .validate_and_consume(
                HOME, &g, epoch, None, false, None, None, None, None, 1, false, true, 110.0
            )
            .is_ok());
        let e = t
            .validate_and_consume(
                HOME, &g, epoch, None, false, None, None, None, None, 1, false, true, 111.0,
            )
            .unwrap_err();
        assert_eq!(e.code, "approval_gate_required");
    }

    // 8. non-consume purpose multi-use within TTL
    #[test]
    fn non_consume_multi_use() {
        let t = ApprovalGateGrants::new();
        let g = reg(&t, "policy_write", ISSUE_EPOCH);
        assert!(val(&t, Some(&g), 110.0).is_ok());
        assert!(val(&t, Some(&g), 120.0).is_ok()); // still valid, not popped
    }

    // 9. prune runs only on register (lazy) — expired entries linger until then
    #[test]
    fn prune_is_lazy() {
        let t = ApprovalGateGrants::new();
        let _g = reg(&t, "policy_write", ISSUE_EPOCH);
        // entry expired at 130 but not pruned (no register since)
        assert_eq!(t.len(), 1);
        let _g2 = reg(&t, "policy_clear", 200.0); // register prunes expired
        assert_eq!(t.len(), 1); // only g2 remains
    }

    // 10. owner_pid mismatch rejected + popped (fork guard)
    #[test]
    fn owner_pid_mismatch_rejected() {
        let t = ApprovalGateGrants::new();
        let g = reg(&t, "policy_write", ISSUE_EPOCH);
        // Inject a foreign owner_pid directly into the table.
        {
            let mut s = t.state.lock().unwrap();
            s.entries.get_mut("grant-policy_write").unwrap().owner_pid = std::process::id() + 1;
        }
        let e = val(&t, Some(&g), 110.0).unwrap_err();
        assert_eq!(e.code, "approval_gate_required");
        assert_eq!(t.len(), 0); // popped
    }

    // 11. capacity bounded
    #[test]
    fn capacity_bounded() {
        let t = ApprovalGateGrants::new();
        for i in 0..NATIVE_APPROVAL_GRANTS_MAX_ENTRIES {
            let mut f = fields("policy_write");
            f.grant_id = format!("g{i}");
            t.register(HOME, f, 100.0, "i", "e", 130.0).unwrap();
        }
        let mut f = fields("policy_write");
        f.grant_id = "overflow".into();
        assert!(t.register(HOME, f, 100.0, "i", "e", 130.0).is_err());
    }

    // 12. cooldown factor_set grant validates
    #[test]
    fn cooldown_factor_set_validates() {
        let t = ApprovalGateGrants::new();
        let mut f = fields("policy_write");
        f.factor_set = vec!["cooldown".into()];
        f.used_cooldown = true;
        f.password_verified = false;
        f.grant_id = "cd".into();
        let g = t.register(HOME, f, 100.0, "i", "e", 130.0).unwrap();
        assert!(val(&t, Some(&g), 110.0).is_ok());
    }

    // invalidate_for_home drops only matching rows
    #[test]
    fn invalidate_for_home() {
        let t = ApprovalGateGrants::new();
        let _a = reg(&t, "policy_write", ISSUE_EPOCH);
        {
            let mut s = t.state.lock().unwrap();
            s.entries.insert(
                "other-home".into(),
                GrantMetadata {
                    guard_home: "/other".into(),
                    expires_epoch: 130.0,
                    purpose: "p".into(),
                    strict: false,
                    used_cooldown: false,
                    password_verified: true,
                    totp_verified: false,
                    action: "p".into(),
                    scope: "local".into(),
                    subject: "s".into(),
                    session_nonce: "n".into(),
                    factor_set: vec![],
                    factor_generation: 1,
                    owner_pid: std::process::id(),
                },
            );
        }
        assert_eq!(t.len(), 2);
        t.invalidate_for_home(HOME);
        assert_eq!(t.len(), 1); // only /other remains
    }
}
