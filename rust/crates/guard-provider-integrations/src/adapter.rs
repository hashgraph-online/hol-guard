//! Closed adapter ids for provider protocols that data cannot express.
//!
//! Almost every provider is a manifest: a pinned host, a literal path, a body of declared facts and
//! pointers into a JSON answer. A protocol that needs more (challenge-response, signed receipts,
//! device enrollment) gets a reviewed Rust module in this crate and one variant here. A manifest
//! names it with `"adapter": "<id>"`; an id this list does not hold refuses the manifest. Nothing is
//! loaded at run time, so the list is the whole set.
//!
//! The list is empty in this phase. Yanez Pulse is the precedent for the shape, and stays where it
//! is until a separate migration.
//!
//! # Review bar for a new adapter
//!
//! An adapter is Guard code that speaks for a vendor, so it is held to the bar of a decision path:
//!
//! 1. **Data first.** The pull request shows why the protocol cannot be a manifest: which step needs a
//!    computed value (a signature, a nonce, a token exchange) that no declared field or pointer can
//!    carry. A new manifest field that would cover it is preferred to an adapter.
//! 2. **Same transport.** Every exchange goes through `client::HttpProviderTransport`: pinned hosts,
//!    HTTPS only, no redirects, the manifest's byte cap and deadline, and the managed network policy.
//!    No other socket, process or file is opened.
//! 3. **Same custody.** The key is read from the resident's secret store as `Zeroizing` and never
//!    reaches a log, receipt, route response, panic message or `Debug` output. Derived secrets follow
//!    the same rule.
//! 4. **Same answer.** The adapter ends in `answer::map_answer` or an equivalent that yields only the
//!    closed verdicts, declared reason codes and a clamped lifetime. It cannot allow, grant or lower
//!    a floor; an `ok` never cancels another provider's `danger`.
//! 5. **Same shares.** It sends only the facts the manifest's `shares` list declares, rendered by
//!    `render::render_body` or checked against that list.
//! 6. **Tests.** Unit tests against `testkit::FakeProvider` for every exchange, a real-TLS test in the
//!    style of `tests/https_client.rs`, the secret-leak checks above, and a refusal test for each
//!    malformed step. The id, its manifest field and the contract docs change in the same pull
//!    request.
//! 7. **Synthetic names.** Fixtures use invented providers and hosts, never a vendor's real
//!    endpoints or keys.

/// A reviewed adapter. Empty in this phase: no manifest may name one yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProviderAdapterId {}

impl ProviderAdapterId {
    /// Every reviewed adapter.
    pub const ALL: &'static [Self] = &[];

    /// The adapter a manifest names, or `None` when the id is not on the closed list.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|adapter| adapter.id() == id)
    }

    /// The id a manifest uses for this adapter.
    pub fn id(self) -> &'static str {
        match self {}
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderAdapterId;

    #[test]
    fn the_registry_is_empty_and_refuses_every_id() {
        assert_eq!(ProviderAdapterId::ALL, &[] as &[ProviderAdapterId]);
        for id in ["exampleshield-signed-v1", "yanez-pulse", "", "*"] {
            assert_eq!(ProviderAdapterId::from_id(id), None, "{id}");
        }
    }
}
