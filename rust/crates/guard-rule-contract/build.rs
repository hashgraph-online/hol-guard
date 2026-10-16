//! Compute the rule-contract component digests at build time so the packaged
//! runtime embeds hashes instead of the component source bytes.
use sha2::{Digest, Sha256};
use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
const PROGRAM_COMPONENT: &str = "native-command-program-artifact";

const COMPONENTS: &[(&str, &str)] = &[
    ("guard-rules", "../guard-rules/src/lib.rs"),
    ("guard-scanner", "../guard-scanner/src/lib.rs"),
    ("guard-secure-fs", "../guard-secure-fs/src/lib.rs"),
    ("guard-hook-core", "../guard-hook-core/src/lib.rs"),
    ("guard-contracts", "../guard-contracts/src/lib.rs"),
    ("guard-command-pretool", "../guard-command/src/pretool.rs"),
    (
        "guard-command-pretool-generic",
        "../guard-command/src/pretool/generic.rs",
    ),
    (
        "guard-command-pretool-result",
        "../guard-command/src/pretool/generic_result.rs",
    ),
    (
        "guard-command-pretool-extract",
        "../guard-command/src/pretool/generic_extract.rs",
    ),
    (
        "guard-runtime-policy-enforcement",
        "../guard-runtime/src/policy_enforcement.rs",
    ),
    (
        "guard-runtime-policy-enforcement-admission",
        "../guard-runtime/src/policy_enforcement_admission.rs",
    ),
    (
        "guard-runtime-policy-enforcement-facts",
        "../guard-runtime/src/policy_enforcement_facts.rs",
    ),
    (
        "guard-runtime-policy-enforcement-facts-tools",
        "../guard-runtime/src/policy_enforcement_facts_tools.rs",
    ),
    (
        "guard-runtime-policy-enforcement-policy",
        "../guard-runtime/src/policy_enforcement_policy.rs",
    ),
    (
        "guard-policy-snapshot",
        "../guard-policy-snapshot/src/lib.rs",
    ),
    (
        "guard-policy-snapshot-canonical",
        "../guard-policy-snapshot/src/policy_snapshot_canonical.rs",
    ),
    (
        "guard-policy-snapshot-crypto",
        "../guard-policy-snapshot/src/policy_snapshot_crypto.rs",
    ),
    (
        "guard-command-command-argument-semantics",
        "../guard-command/src/command_argument_semantics.rs",
    ),
    (
        "guard-command-command-common-cli-matcher-values",
        "../guard-command/src/command_common_cli_matcher_values.rs",
    ),
    (
        "guard-command-command-common-cli-matchers",
        "../guard-command/src/command_common_cli_matchers.rs",
    ),
    (
        "guard-command-command-curl-operations",
        "../guard-command/src/command_curl_operations.rs",
    ),
    (
        "guard-command-command-curl-targets",
        "../guard-command/src/command_curl_targets.rs",
    ),
    (
        "guard-command-command-database-matchers",
        "../guard-command/src/command_database_matchers.rs",
    ),
    (
        "guard-command-command-operand-matchers",
        "../guard-command/src/command_operand_matchers.rs",
    ),
    (
        "guard-command-command-option-parsing",
        "../guard-command/src/command_option_parsing.rs",
    ),
    (
        "guard-command-command-option-unicode",
        "../guard-command/src/command_option_unicode.rs",
    ),
    (
        "guard-command-command-option-unicode-ranges-a",
        "../guard-command/src/command_option_unicode_ranges_a.rs",
    ),
    (
        "guard-command-command-option-unicode-ranges-b",
        "../guard-command/src/command_option_unicode_ranges_b.rs",
    ),
    (
        "guard-command-command-reviewed-literal",
        "../guard-command/src/command_reviewed_literal.rs",
    ),
    (
        "guard-command-command-specialized-matchers",
        "../guard-command/src/command_specialized_matchers.rs",
    ),
    (
        "guard-command-command-structured-matchers-grammar",
        "../guard-command/src/command_structured_matchers/grammar.rs",
    ),
    (
        "guard-command-command-structured-matchers",
        "../guard-command/src/command_structured_matchers.rs",
    ),
    (
        "guard-command-executable-flag-contract",
        "../guard-command/src/executable_flag_contract.rs",
    ),
    ("guard-command-lib", "../guard-command/src/lib.rs"),
    (
        "guard-command-native-command-controls",
        "../guard-command/src/native_command_controls.rs",
    ),
    (
        "guard-command-native-command-delegated",
        "../guard-command/src/native_command_delegated.rs",
    ),
    (
        "guard-command-native-command-program",
        "../guard-command/src/native_command_program.rs",
    ),
    (
        "guard-command-native-command-program-admission",
        "../guard-command/src/native_command_program_admission.rs",
    ),
    (
        "guard-command-native-command-program-compile",
        "../guard-command/src/native_command_program_compile.rs",
    ),
    (
        "guard-command-native-command-program-evaluation",
        "../guard-command/src/native_command_program_evaluation.rs",
    ),
    (
        "guard-command-native-command-program-observations",
        "../guard-command/src/native_command_program_observations.rs",
    ),
    (
        "guard-command-native-command-program-wire",
        "../guard-command/src/native_command_program_wire.rs",
    ),
    (
        "guard-command-pretool-search-glob-class",
        "../guard-command/src/pretool/search/glob_class.rs",
    ),
    (
        "guard-command-pretool-search-hint",
        "../guard-command/src/pretool/search/hint.rs",
    ),
    (
        "guard-command-pretool-search-options",
        "../guard-command/src/pretool/search/options.rs",
    ),
    (
        "guard-command-pretool-search",
        "../guard-command/src/pretool/search.rs",
    ),
    (
        "guard-contracts-native-command-controls",
        "../guard-contracts/src/native_command_controls.rs",
    ),
    (
        "guard-contracts-native-command-observations",
        "../guard-contracts/src/native_command_observations.rs",
    ),
    (
        "guard-contracts-native-hook-receipt",
        "../guard-contracts/src/native_hook_receipt.rs",
    ),
    (
        "guard-runtime-policy-store-command-floor",
        "../guard-runtime/src/policy_store_command_floor.rs",
    ),
    // Resolved from the packaged program artifact at runtime; the empty source
    // slot keeps the artifact position stable without duplicating the JSON.
    (PROGRAM_COMPONENT, ""),
    (
        "guard-command-command-ascii-comparison",
        "../guard-command/src/command_ascii_comparison.rs",
    ),
    (
        "guard-command-command-compatibility-catalog",
        "../guard-command/src/command_compatibility/catalog.rs",
    ),
    (
        "guard-command-command-compatibility-domains",
        "../guard-command/src/command_compatibility/domains.rs",
    ),
    (
        "guard-command-command-compatibility-git",
        "../guard-command/src/command_compatibility/git.rs",
    ),
    (
        "guard-command-command-compatibility-github",
        "../guard-command/src/command_compatibility/github.rs",
    ),
    (
        "guard-command-command-compatibility-github-api",
        "../guard-command/src/command_compatibility/github_api.rs",
    ),
    (
        "guard-command-command-compatibility-github-options",
        "../guard-command/src/command_compatibility/github_options.rs",
    ),
    (
        "guard-command-command-compatibility",
        "../guard-command/src/command_compatibility.rs",
    ),
    (
        "guard-runtime-policy-store",
        "../guard-runtime/src/policy_store.rs",
    ),
    (
        "guard-runtime-policy-store-command-authority",
        "../guard-runtime/src/policy_store_command_authority.rs",
    ),
    (
        "guard-runtime-policy-store-approval",
        "../guard-runtime/src/policy_store_approval.rs",
    ),
    (
        "guard-runtime-policy-store-authority",
        "../guard-runtime/src/policy_store_authority.rs",
    ),
    (
        "guard-runtime-policy-store-migration",
        "../guard-runtime/src/policy_store_migration.rs",
    ),
    (
        "guard-runtime-policy-store-request",
        "../guard-runtime/src/policy_store_request.rs",
    ),
    (
        "guard-runtime-policy-store-persistence",
        "../guard-runtime/src/policy_store_persistence.rs",
    ),
    (
        "guard-runtime-native-hook-receipt",
        "../guard-runtime/src/native_hook_receipt.rs",
    ),
    ("guard-runtime-edge", "../guard-runtime/src/edge.rs"),
];

fn component_bytes(root: &Path, path: &Path) -> Vec<u8> {
    let relative = path
        .strip_prefix(root)
        .expect("component inside source tree");
    let mut current = root.to_path_buf();
    for part in relative.components() {
        current.push(part);
        assert!(
            !fs::symlink_metadata(&current)
                .expect("component metadata")
                .file_type()
                .is_symlink(),
            "component must not traverse symlinks"
        );
    }
    let metadata = fs::metadata(path).expect("component metadata");
    assert!(
        metadata.is_file() && metadata.len() <= MAX_INPUT_BYTES,
        "component size/type invalid"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read(path).expect("component bytes")
}

fn main() {
    let package = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let root = package
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .expect("repository root");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    let mut digests = String::from("const COMPONENT_DIGESTS: &[(&str, &str)] = &[");
    let mut sources = String::from("const COMPONENT_SOURCES: &[(&str, &[u8])] = &[");
    for &(name, relative) in COMPONENTS {
        if name == PROGRAM_COMPONENT {
            write!(digests, "({name:?},{:?}),", "").unwrap();
            write!(sources, "({name:?},&[]),").unwrap();
            continue;
        }
        let path = package.join(relative);
        let bytes = component_bytes(root, &path);
        write!(
            digests,
            "({name:?},{:?}),",
            hex::encode(Sha256::digest(&bytes))
        )
        .unwrap();
        write!(
            sources,
            "({name:?},include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"),\"/{relative}\"))),"
        )
        .unwrap();
    }
    digests.push_str("];\n");
    sources.push_str("];\n");
    fs::write(out.join("rule_components.rs"), digests).expect("write rule components");
    fs::write(out.join("rule_component_sources.rs"), sources)
        .expect("write rule component sources");
}
