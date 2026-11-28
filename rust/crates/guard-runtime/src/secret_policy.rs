//! Local secret policy composition. Provider evidence can tighten a result.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Decision {
    Allow,
    Review,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderEvidence {
    Available,
    Stale,
    Unavailable,
    Malformed,
    Revoked,
}

pub(crate) fn compose(local: Decision, evidence: ProviderEvidence) -> Decision {
    let provider_floor = match evidence {
        ProviderEvidence::Available => Decision::Allow,
        ProviderEvidence::Stale | ProviderEvidence::Unavailable => Decision::Review,
        ProviderEvidence::Malformed | ProviderEvidence::Revoked => Decision::Block,
    };
    local.max(provider_floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_evidence_never_lowers_a_local_floor() {
        for local in [Decision::Allow, Decision::Review, Decision::Block] {
            for evidence in [
                ProviderEvidence::Available,
                ProviderEvidence::Stale,
                ProviderEvidence::Unavailable,
                ProviderEvidence::Malformed,
                ProviderEvidence::Revoked,
            ] {
                assert!(compose(local, evidence) >= local);
            }
        }
    }
}
