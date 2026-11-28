//! Lease metadata stays separate from a resident secret value.

use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LeaseState {
    Active,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaseRecord {
    pub(crate) lease_digest: String,
    pub(crate) expires_at_ms: u64,
    pub(crate) renewable: bool,
    pub(crate) state: LeaseState,
}

impl LeaseRecord {
    pub(crate) fn state_at(&self, now_ms: u64) -> LeaseState {
        match self.state {
            LeaseState::Revoked => LeaseState::Revoked,
            LeaseState::Expired if now_ms >= self.expires_at_ms => LeaseState::Expired,
            _ if now_ms >= self.expires_at_ms => LeaseState::Expired,
            _ => LeaseState::Active,
        }
    }
}

#[derive(Default)]
pub(crate) struct LeaseCache {
    records: HashMap<String, LeaseRecord>,
}

impl LeaseCache {
    pub(crate) fn insert(&mut self, record: LeaseRecord) {
        self.records.insert(record.lease_digest.clone(), record);
    }

    pub(crate) fn state(&self, digest: &str, now_ms: u64) -> Option<LeaseState> {
        self.records
            .get(digest)
            .map(|record| record.state_at(now_ms))
    }

    pub(crate) fn revoke(&mut self, digest: &str) -> bool {
        let Some(record) = self.records.get_mut(digest) else {
            return false;
        };
        record.state = LeaseState::Revoked;
        true
    }

    pub(crate) fn invalidate(&mut self, digest: &str) {
        self.records.remove(digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_and_revocation_never_extend_validity() {
        let mut cache = LeaseCache::default();
        cache.insert(LeaseRecord {
            lease_digest: "a".repeat(64),
            expires_at_ms: 10,
            renewable: false,
            state: LeaseState::Active,
        });
        assert_eq!(cache.state(&"a".repeat(64), 9), Some(LeaseState::Active));
        assert_eq!(cache.state(&"a".repeat(64), 10), Some(LeaseState::Expired));
        assert!(cache.revoke(&"a".repeat(64)));
        assert_eq!(cache.state(&"a".repeat(64), 0), Some(LeaseState::Revoked));
    }
}
