//! Cached provider answers on an MCP browser call (BP-T123, PRD 6.6).
//!
//! The MCP tool-call policy pass asks this module for the provider floor of a browser call that
//! names a target origin. It reads the provider signal cache in the Guard store and nothing else:
//! no lookup, no network and no wait on the worker (BP-T124). With no shipped provider it returns
//! the recommendation unchanged before it opens anything.
//!
//! The floor is applied to the current recommendation before saved authority is composed:
//! - A provider review raises the recommendation to `review`. A review still offers Allow once and
//!   Always allow, and a saved allow for the exact call keeps answering it, as the approval
//!   invariant requires (`docs/guard/approval-invariant.md`).
//! - An enforced provider block makes the recommendation `block`. A block is terminal, so it wins
//!   over a saved approval without deleting it.
//!
//! Provider evidence only tightens: the result is never less restrictive than the recommendation it
//! was given. Every failure to read the cache keeps the recommendation as it was.

use guard_command::effect_decision::GuardAction;
use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_contracts::{
    BrowserAutomationIntentV1, McpPolicyLookupInputV1, ProviderCapabilityV1,
    ProviderConnectionStateV1,
};
use guard_provider_integrations::noise::{BaselineDecision, NoiseLedger};
use rusqlite::Connection;

use crate::local_store_read::require_store_path;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource};
use crate::mcp_tool_policy_decision::Current;
use crate::policy_decision_lookup_op::open_lookup_connection;
use crate::provider_integration_decide::{decide, DecideProvider, DecideRequest};
use crate::provider_integration_managed::{managed_settings, ManagedProviderSettings};
use crate::provider_integration_purge::has_provider_tables;
use crate::provider_integration_routes::origin_subject;
use crate::provider_integration_shipped::shipped_providers;
use crate::provider_integration_store::provider_connection;

pub(crate) const PROVIDER_REVIEW_SOURCE: &str = "provider-integration-review";
pub(crate) const PROVIDER_BLOCK_SOURCE: &str = "provider-integration-block";
pub(crate) const PROVIDER_FRESH_CHECK_SOURCE: &str = "provider-integration-fresh-check-unavailable";
pub(crate) const PROVIDER_MANAGED_UNKNOWN_SOURCE: &str =
    "provider-integration-managed-policy-unknown";

/// The Guard store to read cached provider answers from for an in-process policy lookup, or `None`
/// when no provider ships or the lookup cannot read the store. The relay passes the connection it
/// already holds instead.
pub(crate) fn open_provider_store(lookup: Option<&McpPolicyLookupInputV1>) -> Option<Connection> {
    let lookup = lookup?;
    if shipped_providers().is_empty()
        || lookup.degraded_trust_status.is_some()
        || require_store_path(&lookup.store_path, &lookup.guard_home).is_err()
    {
        return None;
    }
    open_lookup_connection(&lookup.store_path).ok()
}

/// The current recommendation with the cached provider answers for the call's origin applied.
pub(crate) fn with_provider_floor(
    store: Option<&Connection>,
    intent: Option<&BrowserAutomationIntentV1>,
    current: Current,
) -> Current {
    let providers = shipped_providers();
    let origin = intent.and_then(|intent| intent.target_origin.as_deref());
    let (false, Some(connection), Some(origin)) = (providers.is_empty(), store, origin) else {
        return current;
    };
    // `None` when managed policy failed closed or its provider settings do not parse.
    let managed = managed_settings(&load_managed_policy(&managed_policy_source()));
    floor(&Floor {
        connection,
        providers,
        managed: managed.as_ref(),
        origin,
        now_ms: now_ms(),
        current,
    })
}

pub(crate) struct Floor<'a> {
    pub(crate) connection: &'a Connection,
    pub(crate) providers: &'a [CompiledProviderIntegrationV1],
    /// The managed provider settings, or `None` when they cannot be known.
    pub(crate) managed: Option<&'a ManagedProviderSettings>,
    pub(crate) origin: &'a str,
    pub(crate) now_ms: u64,
    pub(crate) current: Current,
}

/// Applies the cache in `connection` to `current`. Pure apart from the store read.
pub(crate) fn floor(input: &Floor<'_>) -> Current {
    let current = input.current.clone();
    if !has_provider_tables(input.connection).unwrap_or(false) {
        return current;
    }
    let Some((_, subject)) = origin_subject(input.origin) else {
        return current;
    };
    // One savepoint makes the connection and signal reads see one committed state, so a reconnect
    // under another manifest cannot pair the new connection with the old manifest's answers. A
    // savepoint nests inside a caller's transaction.
    if input
        .connection
        .execute_batch("savepoint provider_floor")
        .is_err()
    {
        return current;
    }
    let raised = raised_in_snapshot(input, &subject.digest, current.action);
    let _ = input
        .connection
        .execute_batch("rollback to provider_floor; release provider_floor");
    let Some(raised) = raised else {
        return current;
    };
    let action = crate::mcp_tool_policy_flow::most_restrictive(current.action, raised.action);
    let mut signals = current.signals.clone();
    signals.push(raised.signal);
    Current {
        action,
        source: raised.source.to_owned(),
        summary: raised.summary.to_owned(),
        signals,
        ..current
    }
}

struct Raised {
    action: GuardAction,
    source: &'static str,
    summary: &'static str,
    signal: String,
}

impl Raised {
    fn new(action: GuardAction, source: &'static str, summary: &'static str, detail: &str) -> Self {
        Self {
            action,
            source,
            summary,
            signal: format!("{source}:{detail}"),
        }
    }
}

/// The stronger recommendation the cached answers call for, or `None` to keep Guard's own.
fn raised_in_snapshot(
    input: &Floor<'_>,
    subject_digest: &str,
    action: GuardAction,
) -> Option<Raised> {
    let connected = connected_providers(input.connection, input.providers);
    if connected.is_empty() {
        return None;
    }
    let baseline = baseline(action);
    let Some(managed) = input.managed else {
        // Managed policy may set an enforced floor Guard cannot read now. Fail closed to a review
        // rather than decide from the local settings alone.
        return (baseline < BaselineDecision::Review).then(|| {
            Raised::new(
                GuardAction::Review,
                PROVIDER_MANAGED_UNKNOWN_SOURCE,
                "Managed security provider settings could not be read. Review this site before \
                 the agent opens it.",
                "managed-policy",
            )
        });
    };
    let request = DecideRequest {
        baseline,
        capability: ProviderCapabilityV1::OriginReputation,
        subject_digest,
        providers: &connected,
        now_ms: input.now_ms,
        managed,
    };
    // The noise caps count per session; this pass has no session ledger yet, so it admits every
    // signal. That can only add reviews, never remove one.
    let decided = decide(input.connection, &mut NoiseLedger::new(), &request).ok()?;
    if decided.decision <= baseline {
        return None;
    }
    let raised = match (decided.decision, decided.deciding_provider.as_deref()) {
        (BaselineDecision::Block, provider) => Raised::new(
            GuardAction::Block,
            PROVIDER_BLOCK_SOURCE,
            "A connected security provider reports this site as dangerous, and its blocks are \
             enforced.",
            provider.unwrap_or_default(),
        ),
        (_, Some(provider)) => Raised::new(
            GuardAction::Review,
            PROVIDER_REVIEW_SOURCE,
            "A connected security provider flagged this site. Review it before the agent opens it.",
            provider,
        ),
        (_, None) => Raised::new(
            GuardAction::Review,
            PROVIDER_FRESH_CHECK_SOURCE,
            "A security provider set to require a fresh check has no current answer for this \
             site. Review it before the agent opens it.",
            &decided.fresh_check_required.join(","),
        ),
    };
    Some(raised)
}

/// Shipped providers still connected to the manifest this build compiled. A connection made under
/// another manifest digest has no consent for this one, so its cached answers are not read.
fn connected_providers<'a>(
    connection: &Connection,
    providers: &'a [CompiledProviderIntegrationV1],
) -> Vec<DecideProvider<'a>> {
    providers
        .iter()
        .filter(|provider| {
            provider_connection(connection, &provider.id)
                .ok()
                .flatten()
                .is_some_and(|stored| {
                    stored.state == ProviderConnectionStateV1::Connected
                        && stored.manifest_digest == provider.manifest_digest
                })
        })
        .map(|provider| DecideProvider {
            provider_id: &provider.id,
            verified: provider.verified,
        })
        .collect()
}

fn baseline(action: GuardAction) -> BaselineDecision {
    match action {
        GuardAction::Allow | GuardAction::Warn => BaselineDecision::Allow,
        GuardAction::Block => BaselineDecision::Block,
        GuardAction::Review | GuardAction::RequireReapproval | GuardAction::SandboxRequired => {
            BaselineDecision::Review
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// This machine's managed policy. Tests read an unmanaged machine root, so the host's own policy
/// never changes their decisions.
#[cfg(not(test))]
fn managed_policy_source() -> ManagedPolicySource {
    ManagedPolicySource::native()
}

#[cfg(test)]
fn managed_policy_source() -> ManagedPolicySource {
    crate::codex_live_wait_build::managed_policy_source()
}

#[cfg(test)]
#[path = "mcp_tool_policy_provider_tests.rs"]
mod tests;
