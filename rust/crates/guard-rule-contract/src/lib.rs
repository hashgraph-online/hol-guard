#![forbid(unsafe_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};

pub const RULE_CONTRACT_SCHEMA: &str = "hol-guard-native-rule-contract.v2";
const RULE_CONTRACT_DOMAIN: &[u8] = b"hol-guard-native-rule-contract.v2\0";

const COMPONENTS: &[(&str, &[u8])] = &[
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
        "guard-runtime-policy-enforcement-admission",
        include_bytes!("../../guard-runtime/src/policy_enforcement_admission.rs"),
    ),
    (
        "guard-runtime-policy-enforcement-facts",
        include_bytes!("../../guard-runtime/src/policy_enforcement_facts.rs"),
    ),
    (
        "guard-runtime-policy-enforcement-facts-tools",
        include_bytes!("../../guard-runtime/src/policy_enforcement_facts_tools.rs"),
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
    (
        "guard-command-command-argument-semantics",
        include_bytes!("../../guard-command/src/command_argument_semantics.rs"),
    ),
    (
        "guard-command-command-common-cli-matcher-values",
        include_bytes!("../../guard-command/src/command_common_cli_matcher_values.rs"),
    ),
    (
        "guard-command-command-common-cli-matchers",
        include_bytes!("../../guard-command/src/command_common_cli_matchers.rs"),
    ),
    (
        "guard-command-command-curl-operations",
        include_bytes!("../../guard-command/src/command_curl_operations.rs"),
    ),
    (
        "guard-command-command-curl-targets",
        include_bytes!("../../guard-command/src/command_curl_targets.rs"),
    ),
    (
        "guard-command-command-database-matchers",
        include_bytes!("../../guard-command/src/command_database_matchers.rs"),
    ),
    (
        "guard-command-command-operand-matchers",
        include_bytes!("../../guard-command/src/command_operand_matchers.rs"),
    ),
    (
        "guard-command-command-option-parsing",
        include_bytes!("../../guard-command/src/command_option_parsing.rs"),
    ),
    (
        "guard-command-command-option-unicode",
        include_bytes!("../../guard-command/src/command_option_unicode.rs"),
    ),
    (
        "guard-command-command-option-unicode-ranges-a",
        include_bytes!("../../guard-command/src/command_option_unicode_ranges_a.rs"),
    ),
    (
        "guard-command-command-option-unicode-ranges-b",
        include_bytes!("../../guard-command/src/command_option_unicode_ranges_b.rs"),
    ),
    (
        "guard-command-command-reviewed-literal",
        include_bytes!("../../guard-command/src/command_reviewed_literal.rs"),
    ),
    (
        "guard-command-command-specialized-matchers",
        include_bytes!("../../guard-command/src/command_specialized_matchers.rs"),
    ),
    (
        "guard-command-command-structured-matchers-grammar",
        include_bytes!("../../guard-command/src/command_structured_matchers/grammar.rs"),
    ),
    (
        "guard-command-command-structured-matchers",
        include_bytes!("../../guard-command/src/command_structured_matchers.rs"),
    ),
    (
        "guard-command-executable-flag-contract",
        include_bytes!("../../guard-command/src/executable_flag_contract.rs"),
    ),
    (
        "guard-command-lib",
        include_bytes!("../../guard-command/src/lib.rs"),
    ),
    (
        "guard-command-native-command-controls",
        include_bytes!("../../guard-command/src/native_command_controls.rs"),
    ),
    (
        "guard-command-native-command-delegated",
        include_bytes!("../../guard-command/src/native_command_delegated.rs"),
    ),
    (
        "guard-command-native-command-program",
        include_bytes!("../../guard-command/src/native_command_program.rs"),
    ),
    (
        "guard-command-native-command-program-admission",
        include_bytes!("../../guard-command/src/native_command_program_admission.rs"),
    ),
    (
        "guard-command-native-command-program-compile",
        include_bytes!("../../guard-command/src/native_command_program_compile.rs"),
    ),
    (
        "guard-command-native-command-program-evaluation",
        include_bytes!("../../guard-command/src/native_command_program_evaluation.rs"),
    ),
    (
        "guard-command-native-command-program-observations",
        include_bytes!("../../guard-command/src/native_command_program_observations.rs"),
    ),
    (
        "guard-command-native-command-program-wire",
        include_bytes!("../../guard-command/src/native_command_program_wire.rs"),
    ),
    (
        "guard-command-pretool-search-glob-class",
        include_bytes!("../../guard-command/src/pretool/search/glob_class.rs"),
    ),
    (
        "guard-command-pretool-search-hint",
        include_bytes!("../../guard-command/src/pretool/search/hint.rs"),
    ),
    (
        "guard-command-pretool-search-options",
        include_bytes!("../../guard-command/src/pretool/search/options.rs"),
    ),
    (
        "guard-command-pretool-search",
        include_bytes!("../../guard-command/src/pretool/search.rs"),
    ),
    (
        "guard-contracts-native-command-controls",
        include_bytes!("../../guard-contracts/src/native_command_controls.rs"),
    ),
    (
        "guard-contracts-native-command-observations",
        include_bytes!("../../guard-contracts/src/native_command_observations.rs"),
    ),
    (
        "guard-contracts-native-hook-receipt",
        include_bytes!("../../guard-contracts/src/native_hook_receipt.rs"),
    ),
    (
        "guard-runtime-policy-store-command-floor",
        include_bytes!("../../guard-runtime/src/policy_store_command_floor.rs"),
    ),
    (
        "native-command-program-artifact",
        include_bytes!("../../../../contracts/extensions/native-command-program.v1.json"),
    ),
    (
        "guard-command-command-ascii-comparison",
        include_bytes!("../../guard-command/src/command_ascii_comparison.rs"),
    ),
    (
        "guard-command-command-compatibility-catalog",
        include_bytes!("../../guard-command/src/command_compatibility/catalog.rs"),
    ),
    (
        "guard-command-command-compatibility-domains",
        include_bytes!("../../guard-command/src/command_compatibility/domains.rs"),
    ),
    (
        "guard-command-command-compatibility-git",
        include_bytes!("../../guard-command/src/command_compatibility/git.rs"),
    ),
    (
        "guard-command-command-compatibility-github",
        include_bytes!("../../guard-command/src/command_compatibility/github.rs"),
    ),
    (
        "guard-command-command-compatibility-github-api",
        include_bytes!("../../guard-command/src/command_compatibility/github_api.rs"),
    ),
    (
        "guard-command-command-compatibility-github-options",
        include_bytes!("../../guard-command/src/command_compatibility/github_options.rs"),
    ),
    (
        "guard-command-command-compatibility",
        include_bytes!("../../guard-command/src/command_compatibility.rs"),
    ),
    (
        "guard-runtime-policy-store",
        include_bytes!("../../guard-runtime/src/policy_store.rs"),
    ),
    (
        "guard-runtime-policy-store-command-authority",
        include_bytes!("../../guard-runtime/src/policy_store_command_authority.rs"),
    ),
    (
        "guard-runtime-policy-store-approval",
        include_bytes!("../../guard-runtime/src/policy_store_approval.rs"),
    ),
    (
        "guard-runtime-policy-store-authority",
        include_bytes!("../../guard-runtime/src/policy_store_authority.rs"),
    ),
    (
        "guard-runtime-policy-store-migration",
        include_bytes!("../../guard-runtime/src/policy_store_migration.rs"),
    ),
    (
        "guard-runtime-policy-store-request",
        include_bytes!("../../guard-runtime/src/policy_store_request.rs"),
    ),
    (
        "guard-runtime-policy-store-persistence",
        include_bytes!("../../guard-runtime/src/policy_store_persistence.rs"),
    ),
    (
        "guard-runtime-native-hook-receipt",
        include_bytes!("../../guard-runtime/src/native_hook_receipt.rs"),
    ),
    (
        "guard-runtime-edge",
        include_bytes!("../../guard-runtime/src/edge.rs"),
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
    }
}
