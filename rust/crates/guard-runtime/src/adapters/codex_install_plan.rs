//! `runner_authority` kind `codex_install_plan`: what Codex install and
//! uninstall remove from files Guard does not own.
//!
//! Python reads and writes the files. Each op is lexical over the values it is
//! given:
//! - `shell_blocks` names the byte ranges Guard's legacy shell marker blocks
//!   occupy in one shell startup file. The file travels as Latin-1 text, so
//!   every byte survives the JSON request and every offset is a byte offset.
//! - `guard_proxies` names the MCP servers whose launch is a Guard proxy, the
//!   test that decides which entries install refreshes and which alternate
//!   config entries uninstall removes.

use serde_json::{json, Value};

use super::cursor_editor_plan::is_guard_proxy;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// `_SHELL_GUARD_BEGIN` and `_SHELL_GUARD_END` in `adapters/codex.py`.
const SHELL_BEGIN: &[u8] = b"# >>> HOL Guard Codex shell guard >>>";
const SHELL_END: &[u8] = b"# <<< HOL Guard Codex shell guard <<<";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let op = map.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let key = match op {
        "shell_blocks" => "content",
        "guard_proxies" => "servers",
        _ => return Err(ERR_INVALID),
    };
    if map.len() != 2 || !map.contains_key(key) {
        return Err(ERR_INVALID);
    }
    if op == "shell_blocks" {
        let content = latin1(map[key].as_str().ok_or(ERR_INVALID)?)?;
        return Ok(json!({ "ranges": shell_block_ranges(&content) }));
    }
    guard_proxies(&map[key])
}

/// The bytes a Latin-1 decode of them produced.
fn latin1(text: &str) -> Result<Vec<u8>, &'static str> {
    text.chars()
        .map(|character| u8::try_from(u32::from(character)).map_err(|_| ERR_INVALID))
        .collect()
}

/// `bytes.find(marker, start)`.
fn find_from(content: &[u8], marker: &[u8], start: usize) -> Option<usize> {
    if start > content.len() {
        return None;
    }
    content[start..]
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|position| position + start)
}

/// `_line_marker_at`: the marker fills a whole line.
fn line_marker_at(content: &[u8], index: usize, marker: &[u8]) -> bool {
    let after = index + marker.len();
    (index == 0 || content[index - 1] == b'\n')
        && (after == content.len() || matches!(content[after], b'\r' | b'\n'))
}

/// `_find_line_marker`.
fn find_line_marker(content: &[u8], marker: &[u8], start: usize) -> Option<usize> {
    let mut from = start;
    loop {
        let index = find_from(content, marker, from)?;
        if line_marker_at(content, index, marker) {
            return Some(index);
        }
        from = index + marker.len();
    }
}

/// `_trailing_line_break_length`.
fn trailing_line_break(content: &[u8]) -> usize {
    if content.ends_with(b"\r\n") {
        2
    } else if content.ends_with(b"\n") {
        1
    } else {
        0
    }
}

/// `_remove_managed_shell_guard_blocks`, answered as the ranges of the
/// original bytes it removed, in order and never overlapping.
///
/// The removal runs over the shrinking content exactly as Python ran it, so a
/// separator that only touches a block after an earlier removal is judged the
/// same way; each remaining byte keeps its original offset.
pub(crate) fn shell_block_ranges(original: &[u8]) -> Vec<[usize; 2]> {
    let mut content = original.to_vec();
    let mut origin: Vec<usize> = (0..original.len()).collect();
    let mut removed = vec![false; original.len()];
    let mut search_from = 0;
    while let Some(block_start) = find_line_marker(&content, SHELL_BEGIN, search_from) {
        let Some(end_start) =
            find_line_marker(&content, SHELL_END, block_start + SHELL_BEGIN.len())
        else {
            break;
        };
        let mut removal_start = block_start;
        let prefix = &content[..block_start];
        let last_break = trailing_line_break(prefix);
        if last_break > 0 && trailing_line_break(&prefix[..prefix.len() - last_break]) > 0 {
            // Legacy installation inserted one blank separator before its block.
            removal_start -= last_break;
        }
        let mut removal_end = end_start + SHELL_END.len();
        if content[removal_end..].starts_with(b"\r\n") {
            removal_end += 2;
        } else if content[removal_end..].starts_with(b"\n") {
            removal_end += 1;
        }
        for &offset in &origin[removal_start..removal_end] {
            removed[offset] = true;
        }
        content.drain(removal_start..removal_end);
        origin.drain(removal_start..removal_end);
        search_from = removal_start;
    }
    let mut ranges: Vec<[usize; 2]> = Vec::new();
    for (offset, gone) in removed.iter().enumerate() {
        if !gone {
            continue;
        }
        match ranges.last_mut() {
            Some(range) if range[1] == offset => range[1] = offset + 1,
            _ => ranges.push([offset, offset + 1]),
        }
    }
    ranges
}

/// The names of `servers` (`{name: {"command": text | null, "args": [text]}}`)
/// whose launch `is_guard_proxy_command` recognizes.
fn guard_proxies(servers: &Value) -> KindResult {
    let servers = servers.as_object().ok_or(ERR_INVALID)?;
    let mut names = Vec::new();
    for (name, launch) in servers {
        let launch = launch.as_object().ok_or(ERR_INVALID)?;
        if launch.len() != 2 {
            return Err(ERR_INVALID);
        }
        let command = match launch.get("command").ok_or(ERR_INVALID)? {
            Value::Null => None,
            Value::String(command) => Some(command.as_str()),
            _ => return Err(ERR_INVALID),
        };
        let args = launch
            .get("args")
            .and_then(Value::as_array)
            .ok_or(ERR_INVALID)?
            .iter()
            .map(|arg| arg.as_str().map(str::to_owned).ok_or(ERR_INVALID))
            .collect::<Result<Vec<_>, _>>()?;
        if is_guard_proxy(command, &args) {
            names.push(name.clone());
        }
    }
    Ok(json!({ "names": names }))
}

#[cfg(test)]
#[path = "codex_install_plan_tests.rs"]
mod tests;
