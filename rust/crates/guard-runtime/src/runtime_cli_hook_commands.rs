//! One-shot hook commands that do not need an existing resident.

use std::io;

use crate::hook_render_op::unavailable_event;
use crate::{
    codex_hook_trust, hook_launch_scan, hook_payload_facts_op, read_stdin_bounded,
    write_bytes_response, write_json,
};

pub(super) fn route(args: &[String]) -> Option<Result<(), String>> {
    let [command, flag] = args else {
        return None;
    };
    if flag != "--stdin" {
        return None;
    }
    if command == hook_payload_facts_op::CLI_ADMISSION_COMMAND {
        return Some(
            read_stdin_bounded()
                .and_then(|bytes| write_json(&hook_payload_facts_op::cli_admission(&bytes)?)),
        );
    }
    if command == hook_payload_facts_op::CLI_AVAILABILITY_COMMAND {
        return Some(
            read_stdin_bounded()
                .and_then(|bytes| write_json(&hook_payload_facts_op::cli_availability(&bytes)?)),
        );
    }
    if command == unavailable_event::CLI_COMMAND {
        return Some(
            read_stdin_bounded().and_then(|bytes| write_json(&unavailable_event::cli(&bytes)?)),
        );
    }
    let response = if codex_hook_trust::is_command(command) {
        codex_hook_trust::run_command(io::stdin().lock())
    } else if hook_launch_scan::is_command(command) {
        hook_launch_scan::run_command(io::stdin().lock())
    } else {
        return None;
    };
    Some(response.and_then(|bytes| write_bytes_response(&bytes)))
}
