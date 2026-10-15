//! Every integration test file in this directory, compiled as one binary.
//!
//! Each file used to link its own executable, and linking a hundred of them
//! dominated the CI test job. nextest still runs every test in its own
//! process. A new test file must be declared here, or listed as its own
//! `[[test]]` target in Cargo.toml when it needs a separate process.
//!
//! The test modules stay public so a fixture declared in one file remains
//! reachable from the crate root. Each shared support file is loaded once.

#[path = "support/git_helper_fixture.rs"]
pub(crate) mod git_helper_fixture;

#[path = "support/business_properties.rs"]
pub(crate) mod business_properties;

pub mod business_command_properties;
pub mod business_gmail_plain;
pub mod business_gmail_transfer;
pub mod business_gmail_wire;
pub mod business_gws_command;
pub mod business_input_properties;
pub mod business_mime_properties;
pub mod business_transfer_properties;
pub mod command_compatibility;
pub mod command_compatibility_stderr_merge;
pub mod compatibility_safe_scope;
pub mod data_flow_rules_parity;
pub mod effect_decision_parity;
pub mod fd_execution_boundaries;
pub mod inline_expression_boundaries;
pub mod js_semver_vectors;
pub mod manifest_change_vectors;
pub mod mcp_package_sources;
pub mod package_context_vectors;
pub mod portable_command_source_fixtures;
pub mod pretool_agent_metadata;
pub mod pretool_brew_reads;
pub mod pretool_bun_eval;
pub mod pretool_chain_temporary_files;
pub mod pretool_contained_script_tests;
pub mod pretool_contained_tests;
pub mod pretool_contained_wrappers;
pub mod pretool_cwd_compounds;
pub mod pretool_docker_start;
pub mod pretool_doctl_reads;
pub mod pretool_du_sibling_reads;
pub mod pretool_env_prefix_controls;
pub mod pretool_file_copies;
pub mod pretool_file_mutations;
pub mod pretool_file_reads;
pub mod pretool_forged_worktree;
pub mod pretool_generic;
pub mod pretool_generic_powershell;
pub mod pretool_git_branch_listing;
pub mod pretool_git_branch_rename;
pub mod pretool_git_cd_reads;
pub mod pretool_git_context_boundaries;
pub mod pretool_git_execution_environment;
pub mod pretool_git_filter_batches;
pub mod pretool_git_filter_config;
pub mod pretool_git_global_config;
pub mod pretool_git_hash_object;
pub mod pretool_git_helper_config;
pub mod pretool_git_large_listing;
pub mod pretool_git_merge_integration;
pub mod pretool_git_mkdir_chain;
pub mod pretool_git_nested_repositories;
pub mod pretool_git_object_reads;
pub mod pretool_git_outside_cwd;
pub mod pretool_git_pager_config;
pub mod pretool_git_read_sequences;
pub mod pretool_git_redirect_commit_chain;
pub mod pretool_git_ref_listings;
pub mod pretool_git_ref_reads;
pub mod pretool_git_rev_list;
pub mod pretool_git_session_ops;
pub mod pretool_git_sibling_local_writes;
pub mod pretool_git_sibling_worktree_cleanup;
pub mod pretool_git_sibling_worktree_ops;
pub mod pretool_git_submodules;
pub mod pretool_git_temp_repository;
pub mod pretool_git_textconv_config;
pub mod pretool_git_worktree;
pub mod pretool_git_worktree_chain;
pub mod pretool_git_worktree_session;
pub mod pretool_git_worktree_siblings;
pub mod pretool_github_conversation;
pub mod pretool_github_reads;
pub mod pretool_grep_repository_metadata;
pub mod pretool_guard_diagnostics;
pub mod pretool_home_aliases;
pub mod pretool_home_cd;
pub mod pretool_home_dotdir_listing;
pub mod pretool_home_layout_reads;
pub mod pretool_hooks_path_writes;
pub mod pretool_installed_package_source;
pub mod pretool_jq_sibling_filters;
pub mod pretool_linked_writes;
pub mod pretool_links_removals;
pub mod pretool_literal_route_writes;
pub mod pretool_lockfile_install;
pub mod pretool_lockfile_install_forms;
pub mod pretool_lookup_reads;
pub mod pretool_metadata_reads;
pub mod pretool_native_home_writes;
pub mod pretool_network_reads;
pub mod pretool_npm_reads;
pub mod pretool_omp_agent_listing;
pub mod pretool_omp_artifact_search;
pub mod pretool_omp_bash_cwd;
pub mod pretool_omp_eval_contained_bash;
pub mod pretool_omp_eval_read_helpers;
pub mod pretool_omp_fp_proofs;
pub mod pretool_omp_hashline_edits;
pub mod pretool_omp_home_documents;
pub mod pretool_omp_project_dotfiles;
pub mod pretool_omp_tools;
pub mod pretool_omp_workspace_search;
pub mod pretool_omp_yield_reports;
pub mod pretool_outside_workspace_files;
pub mod pretool_package_directory_flags;
pub mod pretool_parent_relative_writes;
pub mod pretool_pi_tools;
pub mod pretool_private_temporary_workspace;
pub mod pretool_process_probe_chains;
pub mod pretool_prompt_negation_scope;
pub mod pretool_prompt_secret_requests;
pub mod pretool_pytest_contained_route;
pub mod pretool_read_output_scratch;
pub mod pretool_recursive_copies;
pub mod pretool_recursive_file_search;
pub mod pretool_ripgrep_config;
pub mod pretool_rust_version_probe;
pub mod pretool_scratch_checkout_copies;
pub mod pretool_search_data;
pub mod pretool_sibling_glob_reads;
pub mod pretool_sibling_glob_search;
pub mod pretool_sibling_ignore_negations;
pub mod pretool_sibling_read_filters;
pub mod pretool_sibling_sequence_reads;
pub mod pretool_skill_listings;
pub mod pretool_skill_roots;
pub mod pretool_stdin_filters;
pub mod pretool_temp_checkout_search;
pub mod pretool_temporary_writes;
pub mod pretool_temporary_writes_windows;
pub mod pretool_version_printenv;
pub mod pretool_windows_agent_root_listing;
pub mod pretool_windows_drive_cwd;
pub mod pretool_windows_home_writes;
pub mod pretool_word_count;
pub mod pretool_workspace_harness_config_writes;
pub mod pretool_wrangler_reads;
pub mod pretool_zcode_dual_input;
pub mod pretool_zcode_dx_paths;
pub mod privileged_wrapper_floor;
pub mod reapproval_copy;
pub mod sed_workflow_boundaries;
pub mod sfrs_conformance;
pub mod workspace_write_boundaries;

#[test]
fn every_test_file_is_compiled() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let declared = include_str!("integration.rs");
    let cargo = std::fs::read_to_string(manifest.join("Cargo.toml")).unwrap();
    let mut missing = Vec::new();
    for entry in std::fs::read_dir(manifest.join("tests")).unwrap() {
        let path = entry.unwrap().path();
        let (Some(stem), Some("rs")) = (
            path.file_stem().and_then(|stem| stem.to_str()),
            path.extension().and_then(|extension| extension.to_str()),
        ) else {
            continue;
        };
        let target = format!("path = \"tests/{stem}.rs\"");
        // lines() drops CR, so a Windows autocrlf checkout still matches.
        let module = format!("pub mod {stem};");
        if stem != "integration"
            && !declared.lines().any(|line| line.trim() == module)
            && !cargo.contains(&target)
        {
            missing.push(stem.to_owned());
        }
    }
    assert!(
        missing.is_empty(),
        "declare these test files in tests/integration.rs: {missing:?}"
    );
}
