#![forbid(unsafe_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const RULE_CONTRACT_SCHEMA: &str = "hol-guard-native-rule-contract.v2";
const RULE_CONTRACT_DOMAIN: &[u8] = b"hol-guard-native-rule-contract.v2\0";
const PROGRAM_COMPONENT: &str = "native-command-program-artifact";

// Component digests are computed by build.rs so the packaged runtime embeds
// hashes instead of a second copy of every component's source bytes.
include!(concat!(env!("OUT_DIR"), "/rule_components.rs"));

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleComponentDigest {
    pub name: &'static str,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleContract {
    pub schema: &'static str,
    pub components: Vec<RuleComponentDigest>,
    pub rule_digest: String,
}

pub fn rule_contract() -> RuleContract {
    static CONTRACT: OnceLock<RuleContract> = OnceLock::new();
    CONTRACT
        .get_or_init(|| {
            let components: Vec<RuleComponentDigest> = COMPONENT_DIGESTS
                .iter()
                .map(|&(name, sha256)| {
                    let sha256 = if name == PROGRAM_COMPONENT {
                        guard_command::native_command_program::PACKAGED_COMMAND_PROGRAM_SHA256
                    } else {
                        sha256
                    };
                    assert!(!sha256.is_empty(), "rule contract component bytes missing");
                    RuleComponentDigest {
                        name,
                        sha256: sha256.to_owned(),
                    }
                })
                .collect();

            let mut combined = Sha256::new();
            combined.update(RULE_CONTRACT_DOMAIN);
            for component in &components {
                combined.update(component.name.as_bytes());
                combined.update([0]);
                combined.update(component.sha256.as_bytes());
                combined.update([0]);
            }

            RuleContract {
                schema: RULE_CONTRACT_SCHEMA,
                components,
                rule_digest: hex::encode(combined.finalize()),
            }
        })
        .clone()
}

pub fn rule_digest() -> String {
    rule_contract().rule_digest
}

#[cfg(test)]
mod tests {
    use super::*;

    include!(concat!(env!("OUT_DIR"), "/rule_component_sources.rs"));

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn contract_is_stable_and_complete() {
        let first = rule_contract();
        let second = rule_contract();
        assert_eq!(first, second);
        assert_eq!(first.schema, RULE_CONTRACT_SCHEMA);
        assert_eq!(
            first
                .components
                .iter()
                .map(|component| component.name)
                .collect::<Vec<_>>(),
            vec![
                "guard-rules",
                "guard-scanner",
                "guard-secure-fs",
                "guard-hook-core",
                "guard-contracts",
                "guard-command-pretool",
                "guard-command-pretool-generic",
                "guard-command-pretool-result",
                "guard-command-pretool-extract",
                "guard-runtime-policy-enforcement",
                "guard-runtime-policy-enforcement-admission",
                "guard-runtime-policy-enforcement-facts",
                "guard-runtime-policy-enforcement-facts-tools",
                "guard-runtime-policy-enforcement-policy",
                "guard-policy-snapshot",
                "guard-policy-snapshot-canonical",
                "guard-policy-snapshot-crypto",
                "guard-command-command-argument-semantics",
                "guard-command-command-common-cli-matcher-values",
                "guard-command-command-common-cli-matchers",
                "guard-command-command-curl-operations",
                "guard-command-command-curl-targets",
                "guard-command-command-database-matchers",
                "guard-command-command-operand-matchers",
                "guard-command-command-option-parsing",
                "guard-command-command-option-unicode",
                "guard-command-command-option-unicode-ranges-a",
                "guard-command-command-option-unicode-ranges-b",
                "guard-command-command-reviewed-literal",
                "guard-command-command-specialized-matchers",
                "guard-command-command-structured-matchers-grammar",
                "guard-command-command-structured-matchers",
                "guard-command-executable-flag-contract",
                "guard-command-lib",
                "guard-command-native-command-controls",
                "guard-command-native-command-delegated",
                "guard-command-native-command-program",
                "guard-command-native-command-program-admission",
                "guard-command-native-command-program-compile",
                "guard-command-native-command-program-evaluation",
                "guard-command-native-command-program-observations",
                "guard-command-native-command-program-wire",
                "guard-command-pretool-search-glob-class",
                "guard-command-pretool-search-hint",
                "guard-command-pretool-search-options",
                "guard-command-pretool-search",
                "guard-contracts-native-command-controls",
                "guard-contracts-native-command-observations",
                "guard-contracts-native-hook-receipt",
                "guard-runtime-policy-store-command-floor",
                "native-command-program-artifact",
                "guard-command-command-ascii-comparison",
                "guard-command-command-compatibility-catalog",
                "guard-command-command-compatibility-domains",
                "guard-command-command-compatibility-git",
                "guard-command-command-compatibility-github",
                "guard-command-command-compatibility-github-api",
                "guard-command-command-compatibility-github-options",
                "guard-command-command-compatibility",
                "guard-runtime-policy-store",
                "guard-runtime-policy-store-command-authority",
                "guard-runtime-policy-store-approval",
                "guard-runtime-policy-store-authority",
                "guard-runtime-policy-store-migration",
                "guard-runtime-policy-store-request",
                "guard-runtime-policy-store-persistence",
                "guard-runtime-native-hook-receipt",
                "guard-runtime-edge",
            ]
        );
        assert!(first
            .components
            .iter()
            .all(|component| component.sha256.len() == 64));
        assert_eq!(first.rule_digest.len(), 64);
        let program = guard_command::native_command_program::packaged_command_program_bytes();
        assert!(!program.is_empty());
        let component = first
            .components
            .iter()
            .find(|entry| entry.name == PROGRAM_COMPONENT)
            .unwrap();
        assert_eq!(component.sha256, sha256_hex(program));
    }

    #[test]
    fn build_time_digests_match_component_sources() {
        let contract = rule_contract();
        assert_eq!(COMPONENT_SOURCES.len(), contract.components.len());
        for (index, &(name, bytes)) in COMPONENT_SOURCES.iter().enumerate() {
            let bytes = if name == PROGRAM_COMPONENT {
                guard_command::native_command_program::packaged_command_program_bytes()
            } else {
                bytes
            };
            assert!(!bytes.is_empty(), "component {name} bytes missing");
            assert_eq!(contract.components[index].name, name);
            assert_eq!(
                contract.components[index].sha256,
                sha256_hex(bytes),
                "component {name} digest mismatch"
            );
        }
        assert_eq!(
            guard_command::native_command_program::PACKAGED_COMMAND_PROGRAM_SHA256,
            sha256_hex(guard_command::native_command_program::packaged_command_program_bytes())
        );
    }
}
