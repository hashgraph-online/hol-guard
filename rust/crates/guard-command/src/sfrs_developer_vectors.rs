//! Parity of the developer inspection argument checks against recorded
//! Python output.

use serde_json::{json, Value};

use crate::codex_output_env::Ctx;
use crate::sfrs_developer_inspection::{
    fd_exec_sed_read_only_args_are_safe, find_args_use_write_or_unsafe_exec_action,
    find_exec_ls_args_are_read_only, find_exec_sed_args_are_read_only,
    read_only_lookup_date_args_are_safe, read_only_lookup_fd_args_are_safe,
    read_only_lookup_find_args_are_safe, read_only_lookup_plain_targets_are_safe,
    read_only_lookup_primary_segment_is_safe, read_only_lookup_search_args_are_safe,
    read_only_lookup_search_uses_file_input, ripgrep_config_is_disabled,
    static_shell_segment_is_safe,
};
use crate::sfrs_shell_tokens::{iter_shell_command_segments, split_shell_parts};
use crate::sfrs_token_vectors::{records, NoEnvHost};

fn segment_record(segment: &[String], ctx: &Ctx) -> Value {
    let (name, args) = (segment[0].as_str(), &segment[1..]);
    let plain = [false, true].map(|dirs| read_only_lookup_plain_targets_are_safe(args, dirs, None));
    let search = ["grep", "egrep", "rg"]
        .map(|command| read_only_lookup_search_args_are_safe(command, args, None, ctx));
    let file_input = ["grep", "egrep", "rg", "fd"]
        .map(|command| read_only_lookup_search_uses_file_input(command, args));
    json!({
        "primary": read_only_lookup_primary_segment_is_safe(name, args, None, ctx),
        "static": static_shell_segment_is_safe(args),
        "date": read_only_lookup_date_args_are_safe(args),
        "plain": plain,
        "search": search,
        "file_input": file_input,
        "rg_config": ripgrep_config_is_disabled(args),
        "fd": read_only_lookup_fd_args_are_safe(args, None),
        "fd_exec": fd_exec_sed_read_only_args_are_safe(args, None),
        "find": read_only_lookup_find_args_are_safe(args, None),
        "find_write": find_args_use_write_or_unsafe_exec_action(args),
        "find_sed": find_exec_sed_args_are_read_only(args),
        "find_ls": find_exec_ls_args_are_read_only(args),
    })
}

#[test]
fn developer_inspection_arguments_match_recorded_python() {
    let host = NoEnvHost;
    let ctx = Ctx::new(&host, "/", "/");
    let mut failures = Vec::new();
    let mut compared = 0usize;
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let expected = record["developer"].as_array().expect("developer");
        let parts = split_shell_parts(text);
        let segments = iter_shell_command_segments(&parts);
        assert_eq!(segments.len(), expected.len(), "{text:?}");
        for (segment, want) in segments.iter().zip(expected) {
            compared += 1;
            let actual = segment_record(segment, &ctx);
            for (label, value) in want.as_object().expect("object") {
                if &actual[label] != value {
                    failures.push(format!("{segment:?} {label}: {} vs {value}", actual[label]));
                }
            }
        }
    }
    assert!(compared > 4000, "too few segments: {compared}");
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}
