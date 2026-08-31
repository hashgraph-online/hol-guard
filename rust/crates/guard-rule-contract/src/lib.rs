#![forbid(unsafe_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};

pub const RULE_CONTRACT_SCHEMA: &str = "hol-guard-native-rule-contract.v2";
const RULE_CONTRACT_DOMAIN: &[u8] = b"hol-guard-native-rule-contract.v2\0";

const COMPONENTS: [(&str, &[u8]); 15] = [
    (
        "guard-rules",
        include_bytes!("../../guard-rules/src/lib.rs"),
    ),
    (
        "guard-scanner",
        include_bytes!("../../guard-scanner/src/lib.rs"),
    ),
    (
        "guard-secure-fs",
        include_bytes!("../../guard-secure-fs/src/lib.rs"),
    ),
    (
        "guard-hook-core",
        include_bytes!("../../guard-hook-core/src/lib.rs"),
    ),
    (
        "guard-contracts",
        include_bytes!("../../guard-contracts/src/lib.rs"),
    ),
    (
        "guard-command-pretool",
        include_bytes!("../../guard-command/src/pretool.rs"),
    ),
    (
        "guard-command-pretool-generic",
        include_bytes!("../../guard-command/src/pretool/generic.rs"),
    ),
    (
        "guard-command-pretool-result",
        include_bytes!("../../guard-command/src/pretool/generic_result.rs"),
    ),
    (
        "guard-command-pretool-extract",
        include_bytes!("../../guard-command/src/pretool/generic_extract.rs"),
    ),
    (
        "guard-runtime-policy-enforcement",
        include_bytes!("../../guard-runtime/src/policy_enforcement.rs"),
    ),
    (
        "guard-runtime-policy-enforcement-facts",
        include_bytes!("../../guard-runtime/src/policy_enforcement_facts.rs"),
    ),
    (
        "guard-runtime-policy-enforcement-policy",
        include_bytes!("../../guard-runtime/src/policy_enforcement_policy.rs"),
    ),
    (
        "guard-policy-snapshot",
        include_bytes!("../../guard-policy-snapshot/src/lib.rs"),
    ),
    (
        "guard-policy-snapshot-canonical",
        include_bytes!("../../guard-policy-snapshot/src/policy_snapshot_canonical.rs"),
    ),
    (
        "guard-policy-snapshot-crypto",
        include_bytes!("../../guard-policy-snapshot/src/policy_snapshot_crypto.rs"),
    ),
];

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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn rule_contract() -> RuleContract {
    let components: Vec<RuleComponentDigest> = COMPONENTS
        .iter()
        .map(|(name, bytes)| RuleComponentDigest {
            name,
            sha256: sha256_hex(bytes),
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
}

pub fn rule_digest() -> String {
    rule_contract().rule_digest
}

#[cfg(test)]
mod tests {
    use super::*;

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
                "guard-runtime-policy-enforcement-facts",
                "guard-runtime-policy-enforcement-policy",
                "guard-policy-snapshot",
                "guard-policy-snapshot-canonical",
                "guard-policy-snapshot-crypto",
            ]
        );
        assert!(first
            .components
            .iter()
            .all(|component| component.sha256.len() == 64));
        assert_eq!(first.rule_digest.len(), 64);
    }
}
