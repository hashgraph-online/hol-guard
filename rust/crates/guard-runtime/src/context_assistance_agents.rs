//! Host-issued, memory-only MCP principals. A connection code is public;
//! possession of its separate private credential authenticates the session.
use guard_context_assistance::RuntimeError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const CAPACITY: usize = 8;
const PENDING_TTL: Duration = Duration::from_secs(300);
const ACTIVE_TTL: Duration = Duration::from_secs(3600);

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct Credential(String);
impl Drop for Credential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential([redacted])")
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompileArguments {
    pub(crate) query: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExplainArguments {
    pub(crate) snapshot_id: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActionArguments {
    pub(crate) decision_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) snapshot_id: Option<String>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NoteArguments {
    pub(crate) snapshot_id: String,
    pub(crate) request_key: String,
    pub(crate) text: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProposalArguments {
    pub(crate) request_key: String,
}
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyArguments {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Input {
    Discover {},
    Begin {},
    Status {
        credential: Credential,
        #[serde(default)]
        arguments: EmptyArguments,
    },
    Compile {
        credential: Credential,
        arguments: CompileArguments,
    },
    Explain {
        credential: Credential,
        arguments: ExplainArguments,
    },
    ReviewAction {
        credential: Credential,
        arguments: ActionArguments,
    },
    ProposeNote {
        credential: Credential,
        arguments: NoteArguments,
    },
    ProposalStatus {
        credential: Credential,
        arguments: ProposalArguments,
    },
    ForgetProposal {
        credential: Credential,
        arguments: ProposalArguments,
    },
    Close {
        credential: Credential,
    },
}
impl Input {
    pub(crate) fn uses_context(&self) -> bool {
        matches!(
            self,
            Self::Compile { .. }
                | Self::Explain { .. }
                | Self::ReviewAction { .. }
                | Self::ProposeNote { .. }
                | Self::ForgetProposal { .. }
        )
    }
}

struct Session {
    secret_hash: [u8; 32],
    scope_id: Option<String>,
    expires: Instant,
    snapshots: BTreeSet<String>,
}
#[derive(Default)]
pub(crate) struct Sessions {
    sessions: BTreeMap<String, Session>,
}

impl Sessions {
    pub(crate) fn sweep(&mut self, now: Instant) -> BTreeSet<String> {
        self.sessions.retain(|_, s| s.expires > now);
        self.sessions.keys().cloned().collect()
    }
    pub(crate) fn begin(&mut self, now: Instant) -> Result<Value, RuntimeError> {
        self.sessions.retain(|_, session| session.expires > now);
        if self.sessions.len() >= CAPACITY {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut secret = [0_u8; 32];
        let mut id = [0_u8; 16];
        getrandom::fill(&mut secret).map_err(|_| RuntimeError::ResourceLimit)?;
        getrandom::fill(&mut id).map_err(|_| RuntimeError::ResourceLimit)?;
        let credential = hex::encode(secret);
        secret.zeroize();
        let id = format!("agent:{}", hex::encode(id));
        self.sessions.insert(
            id.clone(),
            Session {
                secret_hash: Sha256::digest(credential.as_bytes()).into(),
                scope_id: None,
                expires: now + PENDING_TTL,
                snapshots: BTreeSet::new(),
            },
        );
        // This response is confined to authenticated native application IPC.
        // No HTTP route or MCP result exposes this credential.
        Ok(json!({"session_id":id, "credential":credential, "phase":"pending"}))
    }

    pub(crate) fn authenticate(
        &self,
        credential: &Credential,
        now: Instant,
    ) -> Result<(String, Option<String>), RuntimeError> {
        if credential.0.len() != 64
            || !credential
                .0
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let digest: [u8; 32] = Sha256::digest(credential.0.as_bytes()).into();
        self.sessions
            .iter()
            .find(|(_, session)| {
                session.expires > now && crate::constant_time_eq(&session.secret_hash, &digest)
            })
            .map(|(id, session)| (id.clone(), session.scope_id.clone()))
            .ok_or(RuntimeError::ScopeDenied)
    }

    #[cfg(test)]
    pub(crate) fn authorize(
        &mut self,
        id: &str,
        scope_id: &str,
        now: Instant,
    ) -> Result<(), RuntimeError> {
        self.authorize_mode(id, scope_id, now, false)
    }
    pub(crate) fn authorize_mode(
        &mut self,
        id: &str,
        scope_id: &str,
        now: Instant,
        shared: bool,
    ) -> Result<(), RuntimeError> {
        if !shared
            && self.sessions.values().any(|session| {
                session.expires > now && session.scope_id.as_deref() == Some(scope_id)
            })
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let session = self
            .sessions
            .get_mut(id)
            .filter(|session| session.expires > now && session.scope_id.is_none())
            .ok_or(RuntimeError::ScopeDenied)?;
        session.scope_id = Some(scope_id.into());
        session.expires = now + if shared { PENDING_TTL } else { ACTIVE_TTL };
        Ok(())
    }
    pub(crate) fn expires(&self, id: &str) -> Result<Instant, RuntimeError> {
        self.sessions
            .get(id)
            .filter(|s| s.expires > Instant::now())
            .map(|s| s.expires)
            .ok_or(RuntimeError::ScopeDenied)
    }
    pub(crate) fn revoke(&mut self, id: &str) -> Result<(), RuntimeError> {
        self.sessions
            .remove(id)
            .map(|_| ())
            .ok_or(RuntimeError::ScopeDenied)
    }
    pub(crate) fn retain_snapshot(
        &mut self,
        id: &str,
        snapshot: String,
    ) -> Result<(), RuntimeError> {
        let session = self.sessions.get_mut(id).ok_or(RuntimeError::ScopeDenied)?;
        if session.snapshots.len() >= 8 {
            session.snapshots.clear();
        }
        session.snapshots.insert(snapshot);
        Ok(())
    }
    pub(crate) fn require_snapshot(&self, id: &str, snapshot: &str) -> Result<(), RuntimeError> {
        if self
            .sessions
            .get(id)
            .is_some_and(|session| session.snapshots.contains(snapshot))
        {
            Ok(())
        } else {
            Err(RuntimeError::ScopeDenied)
        }
    }
    pub(crate) fn require_live(&self, id: &str, now: Instant) -> Result<(), RuntimeError> {
        if self
            .sessions
            .get(id)
            .is_some_and(|session| session.expires > now)
        {
            Ok(())
        } else {
            Err(RuntimeError::ScopeDenied)
        }
    }
    pub(crate) fn metadata(&self, now: Instant) -> Value {
        json!(self.sessions.iter().filter(|(_, session)| session.expires > now).map(|(id, session)|
            json!({"session_id":id,"scope_id":session.scope_id,"phase":if session.scope_id.is_some() {"authorized"} else {"pending"},
                "expires_in_seconds":session.expires.saturating_duration_since(now).as_secs()})).collect::<Vec<_>>())
    }
}

#[cfg(test)]
#[path = "context_assistance_agents_tests.rs"]
mod tests;
