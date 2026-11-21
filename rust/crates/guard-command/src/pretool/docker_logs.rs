//! `docker logs <container>` of one named container, bounded by time or line
//! limits.
//!
//! It prints what a workload already wrote and changes nothing: no container
//! starts, no image is pulled, no project file is resolved. That is the same
//! read `kubectl logs` is proven as, and the output stays in the session,
//! which any later step that sends it elsewhere still has to pass on its own.
//!
//! `docker compose logs` is not this read. Compose resolves the project first
//! — `compose.yaml`, its `.env`, `COMPOSE_FILE`, `COMPOSE_PROFILES` and every
//! `include` source, which may be a remote git or OCI reference — so it keeps
//! the review `compose ps` keeps.
//!
//! `--follow` never ends and stays out. `--details` prints the extra
//! attributes a driver was given, so it stays reviewed too, and so does every
//! option outside the lists below.

/// `docker logs` options that take no value.
const CONTAINER_FLAGS: [&str; 2] = ["-t", "--timestamps"];

/// Options whose value only bounds the printed output.
const CONTAINER_VALUES: [&str; 4] = ["-n", "--tail", "--since", "--until"];

/// `docker logs <container>` prints one container's output.
pub(super) fn safe_container_logs(words: &[&str]) -> bool {
    options_safe(words, &CONTAINER_FLAGS, &CONTAINER_VALUES)
}

fn options_safe(words: &[&str], flags: &[&str], values: &[&str]) -> bool {
    let mut positionals = 0usize;
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        index += 1;
        if !word.starts_with('-') {
            positionals += 1;
            if !target_name(word) {
                return false;
            }
            continue;
        }
        if flags.contains(&word) {
            continue;
        }
        let (name, inline) = match word.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (word, None),
        };
        if !values.contains(&name) {
            return false;
        }
        let value = match inline {
            Some(value) => value,
            None => match words.get(index) {
                Some(value) => {
                    index += 1;
                    *value
                }
                None => return false,
            },
        };
        if !value_safe(name, value) {
            return false;
        }
    }
    positionals == 1
}

fn value_safe(name: &str, value: &str) -> bool {
    match name {
        "-n" | "--tail" => {
            value == "all" || (value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit()))
        }
        // A time bound is a duration, a UNIX timestamp or an RFC 3339 time.
        "--since" | "--until" => {
            !value.is_empty()
                && value.len() <= 64
                && !value.starts_with('-')
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-' | b'+')
                })
        }
        _ => false,
    }
}

/// A container name.
fn target_name(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 128
        && word
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
