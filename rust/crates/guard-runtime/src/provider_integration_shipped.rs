//! The provider manifests this build ships (BP-T130).
//!
//! Every manifest under `contributions/provider-integrations/` is embedded at build time and
//! compiled once per process, so the set a resident serves is exactly the reviewed set its source
//! carried; nothing on disk can add a provider or change one. A test checks that `SHIPPED` lists
//! every manifest in that directory and nothing else, and that the set compiles.
//!
//! The set fails closed: when it does not compile, the resident serves no provider at all rather
//! than part of the set, and every provider route answers for an empty catalog.
//!
//! To ship a provider, add a line to `SHIPPED` in the same pull request as its manifest:
//!
//! ```text
//! ("provider.<slug>.json", include_bytes!("../../../../contributions/provider-integrations/provider.<slug>.json")),
//! ```

use std::sync::OnceLock;

use guard_command::provider_integration_compile::{
    compile_contributed_provider_integration_set, CompiledProviderIntegrationV1,
    ProviderIntegrationCompileError,
};

/// The embedded manifests, by file name. No reviewed provider pack has been contributed yet.
pub(crate) const SHIPPED: &[(&str, &[u8])] = &[];

/// The maintainer-owned list of provider ids whose `publisher.verified` claim is honoured. A
/// manifest outside this list that claims `verified` does not compile.
pub(crate) const VERIFIED: &[&str] = &[];

/// Compiles a manifest set the way the shipped set is compiled.
pub(crate) fn compile_shipped(
    sources: &[(&str, &[u8])],
    verified: &[&str],
) -> Result<Vec<CompiledProviderIntegrationV1>, ProviderIntegrationCompileError> {
    let bytes: Vec<&[u8]> = sources.iter().map(|(_, bytes)| *bytes).collect();
    compile_contributed_provider_integration_set(&bytes, verified)
}

/// The providers this build ships, compiled once. Empty when the set does not compile.
pub fn shipped_providers() -> &'static [CompiledProviderIntegrationV1] {
    static PROVIDERS: OnceLock<Vec<CompiledProviderIntegrationV1>> = OnceLock::new();
    PROVIDERS.get_or_init(|| compile_shipped(SHIPPED, VERIFIED).unwrap_or_default())
}

#[cfg(test)]
#[path = "provider_integration_shipped_tests.rs"]
mod tests;
