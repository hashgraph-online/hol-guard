//! Machine network authority, never caller-supplied proxy/key material.
use super::*;
use guard_command::egress_caller_policy::{proxy_map, ManagedNetworkPolicy};

pub(super) fn direct_allowed() -> Result<bool, String> {
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.write_cache = false;
    let state = crate::managed_policy_load::load_managed_policy(&source);
    if state.status.fails_closed() || state.authority_unreadable() {
        return Err(error("policy_restricted"));
    }
    let network = state
        .policy
        .map(|policy| policy.network)
        .unwrap_or_else(ManagedNetworkPolicy::unmanaged_default);
    check(&network, !proxy_map(&network).map_err(error)?.is_empty())
}
fn check(network: &ManagedNetworkPolicy, has_proxy: bool) -> Result<bool, String> {
    // Do not silently bypass the OS/administrator's proxy or drop additive
    // trust roots. Direct pinned TLS is the only acquisition mode qualified
    // here. An explicit, hash-checked offline import remains available.
    if has_proxy {
        return Err(error("install_proxy_requires_offline_import"));
    }
    if network.ca_bundle_path.is_some() || network.trust_roots_path.is_some() {
        return Err(error("install_trust_requires_offline_import"));
    }
    Ok(network.allow_public_registries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_proxy_or_custom_ca_is_never_silently_bypassed() {
        let mut network = ManagedNetworkPolicy::unmanaged_default();
        assert!(check(&network, false).unwrap());
        assert_eq!(
            check(&network, true),
            Err(error("install_proxy_requires_offline_import"))
        );
        network.allow_public_registries = false;
        assert!(!check(&network, false).unwrap());
        network.ca_bundle_path = Some("/admin/ca.pem".into());
        assert_eq!(
            check(&network, false),
            Err(error("install_trust_requires_offline_import"))
        );
        network.ca_bundle_path = None;
        network.trust_roots_path = Some("/admin/roots.pem".into());
        assert!(check(&network, false).is_err());
    }
}
