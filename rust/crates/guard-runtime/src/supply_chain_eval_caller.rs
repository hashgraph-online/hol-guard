//! What a caller has to own for one package evaluation: the network policy the
//! exchanges happen under, the private directory a spooled body is written to,
//! and the egress the rounds loop performs its needs through.
//!
//! Port of the caller half of `native_supply_chain_eval_payload`
//! (native_supply_chain_eval.py:255) together with `private_spool_dir`
//! (native_supply_chain_egress.py:358) and `resolved_network_policy`
//! (mdm/network_transport.py:61). The rounds themselves live in
//! `supply_chain_eval_rounds`; this module only assembles what they need.
//!
//! The resident cannot reach the network, so the caller performs its exchanges
//! — under the machine's managed network policy, never under whatever the
//! answer asked for. A policy this caller cannot honour refuses every exchange
//! instead of exchanging under default trust or a direct connection; an
//! evaluation that needs no network still settles, exactly as it does for a
//! caller whose managed policy resolved.

// The MCP front end that assembles a caller lands with the native relay lane;
// until it does, only the tests below build one.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use guard_command::egress_caller::{EgressFulfilment, EgressPolicy};
use guard_command::egress_caller_policy::{ManagedEgressPolicy, ManagedNetworkPolicy};
use guard_command::restricted_archive::RestrictedArchiveDownload;
use guard_contracts::{EgressNeedV1, EgressSuppliedV1};
use serde_json::Value;

use crate::managed_policy_floor::effective_managed_policy;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource};
use crate::supply_chain_eval_rounds::CallerEgress;

/// `private_spool_dir`'s prefix, so a directory left behind by a killed caller
/// is recognisable as one.
const SPOOL_PREFIX: &str = "hol-guard-egress-";
/// Bytes of randomness in the spool directory's name. The directory is created
/// exclusively, so this only has to make a collision with a live caller's
/// directory improbable.
const SPOOL_NAME_BYTES: usize = 16;
/// The refusal a caller whose managed network policy cannot be honoured answers
/// every need with.
const POLICY_UNHONOURED: &str = "egress_managed_policy_unavailable";
/// The refusal of a caller that could not open its own spool directory.
const SPOOL_UNAVAILABLE: &str = "egress_spool_unavailable";

/// Stands in where a refusal has to answer `claim_archives` without a resolved
/// policy. It never reaches an exchange: the fulfilment it belongs to performed
/// no need.
static NO_EGRESS_POLICY: NoEgressPolicy = NoEgressPolicy;

/// `resolved_network_policy(None)` (mdm/network_transport.py:61): the machine's
/// network policy, or the unmanaged default where no machine policy applies.
///
/// A profile that is present but did not load is not an unmanaged machine. The
/// floor that stands in for it locks settings, and its network section is the
/// unmanaged default, so reading that section would exchange under no proxy,
/// CA, or registry rule the unreadable profile may have required. That load
/// refuses the network instead.
///
/// A machine whose authority this runtime cannot read at all refuses too.
/// Every Windows machine reports that status, because the registry is the
/// authority and this runtime does not read it yet, so an administrator's
/// proxy, CA, or `allowPublicRegistries: false` is invisible here while being
/// honoured on the Python path. Exchanging under the unmanaged default would
/// exchange outside every rule such a policy sets, so this caller performs no
/// exchange on a machine whose authority it cannot read: an evaluation the
/// resident answers from the cache still settles, and one that needs the
/// network has no verdict here and belongs on the Python path, which reads the
/// registry. Reading HKLM natively is what moves those machines onto this lane.
pub(crate) fn caller_network_policy(
    managed: &ManagedPolicySource,
) -> Result<ManagedNetworkPolicy, &'static str> {
    let state = load_managed_policy(managed);
    if state.status.fails_closed() {
        return Err(POLICY_UNHONOURED);
    }
    Ok(effective_managed_policy(&state)
        .map(|policy| policy.network)
        .unwrap_or_else(ManagedNetworkPolicy::unmanaged_default))
}

/// `private_spool_dir` (native_supply_chain_egress.py:358): an owner-only
/// directory for response bodies too big to inline, removed when the evaluation
/// that opened it is done with it.
#[derive(Debug)]
pub(crate) struct PrivateSpool {
    dir: PathBuf,
}

impl PrivateSpool {
    /// Create the directory, owner-only from the moment it exists.
    ///
    /// `None` is a caller that cannot spool, which fails the evaluation closed:
    /// a body the resident cannot read is not an answer it can be asked to
    /// decide without.
    pub(crate) fn open() -> Option<Self> {
        let mut name = [0u8; SPOOL_NAME_BYTES];
        getrandom::fill(&mut name).ok()?;
        let dir = std::env::temp_dir().join(format!("{SPOOL_PREFIX}{}", hex::encode(name)));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        // Not `create_dir_all`: the directory is this caller's, so a name that
        // already exists is somebody else's directory, not this one.
        builder.create(&dir).ok()?;
        Some(Self { dir })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for PrivateSpool {
    fn drop(&mut self) {
        // Python's exit stack removes the directory on every exit. A spooled
        // body is a response the resident has already read and decided on;
        // nothing outlives the evaluation.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The caller's egress for one evaluation.
///
/// The spool directory is opened on the first round that needs the network, as
/// Python's exit stack opens it: an evaluation answered from the cache leaves
/// nothing behind at all.
pub(crate) struct CallerEgressFulfilment<'a> {
    policy: Result<&'a dyn EgressPolicy, &'static str>,
    spool: Option<PrivateSpool>,
    fulfilment: Option<EgressFulfilment<'a>>,
}

impl<'a> CallerEgressFulfilment<'a> {
    /// Exchanges happen under `policy`.
    pub(crate) fn new(policy: &'a dyn EgressPolicy) -> Self {
        Self {
            policy: Ok(policy),
            spool: None,
            fulfilment: None,
        }
    }

    /// A caller whose managed network policy cannot be honoured. It refuses
    /// every need rather than exchanging outside the policy; an evaluation that
    /// asks for no exchange is unaffected.
    pub(crate) fn refusing(reason: &'static str) -> Self {
        Self {
            policy: Err(reason),
            spool: None,
            fulfilment: None,
        }
    }

    /// Resolve the machine's managed network policy into the egress policy the
    /// exchanges happen under. `Err` is a policy this caller cannot honour.
    pub(crate) fn resolve_policy(
        managed: &ManagedPolicySource,
    ) -> Result<ManagedEgressPolicy, &'static str> {
        ManagedEgressPolicy::resolve(&caller_network_policy(managed)?)
    }

    /// The refusal reason for a policy that did not resolve.
    pub(crate) fn policy_unhonoured() -> &'static str {
        POLICY_UNHONOURED
    }
}

impl CallerEgress for CallerEgressFulfilment<'_> {
    fn spool_dir(&self) -> &Path {
        // The rounds loop reads this only after a round's needs were
        // performed, which is the round that opened the spool.
        self.spool
            .as_ref()
            .map_or_else(|| Path::new(""), PrivateSpool::path)
    }

    fn fulfil(&mut self, needs: &[EgressNeedV1]) -> Result<(), &'static str> {
        let policy = self.policy?;
        if self.fulfilment.is_none() {
            // The first round that needs the network opens the spool, as
            // Python's exit stack does: an evaluation answered without one
            // creates no directory at all.
            let spool = PrivateSpool::open().ok_or(SPOOL_UNAVAILABLE)?;
            self.fulfilment = Some(EgressFulfilment::new(spool.path(), policy));
            self.spool = Some(spool);
        }
        let Some(fulfilment) = self.fulfilment.as_mut() else {
            return Err(SPOOL_UNAVAILABLE);
        };
        fulfilment.fulfil(needs)
    }

    fn supplied(&self) -> &[EgressSuppliedV1] {
        self.fulfilment
            .as_ref()
            .map_or(&[][..], EgressFulfilment::supplied)
    }

    fn claim_archives(
        &mut self,
        descriptors: Option<&Value>,
    ) -> Result<Vec<RestrictedArchiveDownload>, &'static str> {
        match self.fulfilment.as_mut() {
            Some(fulfilment) => fulfilment.claim_archives(descriptors),
            // No round needed the network, so this caller holds no archive. An
            // answer that names one names an archive nobody downloaded.
            None => {
                EgressFulfilment::new(Path::new(""), &NO_EGRESS_POLICY).claim_archives(descriptors)
            }
        }
    }
}

/// The policy of a caller that performed no exchange at all.
struct NoEgressPolicy;

impl EgressPolicy for NoEgressPolicy {
    fn validate(&self, _url: &str) -> Result<(), String> {
        Err(POLICY_UNHONOURED.to_owned())
    }
}

#[cfg(test)]
#[path = "supply_chain_eval_caller_tests.rs"]
mod tests;
