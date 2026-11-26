//! Resource limits a shell sets on itself.
//!
//! A test or build prelude often raises the descriptor limit before it starts
//! -- `ulimit -n 10240` ahead of a watcher that opens a file per module -- and
//! the limit it sets reaches no further than the shell that ran it and the
//! children that shell goes on to start. Nothing outside the process tree
//! observes it, nothing on disk records it, and the next shell starts from the
//! inherited limit again.
//!
//! `host_facts.rs` proves the reading spelling of `ulimit`, where a flag alone
//! prints the limit in effect. This module proves the setting spelling, which
//! is a different claim: not that the command changes nothing, but that what it
//! changes is a resource bound on the calling shell's own process tree and
//! nothing else.
//!
//! The bare spelling writes both limits. `ulimit -n 10240` with neither `-H`
//! nor `-S` is `ulimit -Hn 10240; ulimit -Sn 10240`, so a prelude that means to
//! raise its soft limit also caps the hard limit at the value it asked for, and
//! an unprivileged shell cannot raise a hard limit back afterwards. That write
//! is irreversible, but it is irreversible only inside the tree that made it:
//! the next shell inherits the limit its own parent holds, nothing on disk
//! records the change, and no process outside the tree can observe it. The
//! worst outcome is the shell capping its own work, which fails closed. The
//! proof therefore covers both the bare and the explicit `-S` spelling, because
//! those are the spellings a prelude asking for its own headroom actually uses.
//!
//! Two spellings stay out. `-H` writes the hard limit alone and raises no soft
//! limit, so it does nothing for a prelude that wants headroom for its own
//! work; keeping it out holds this prover to the shapes real preludes use.
//! `-c` sizes core dumps, and raising it makes the kernel write process memory
//! -- environment variables and whatever the process had read -- into a file on
//! the next crash, which is a disclosure a read-only prelude should not be able
//! to arrange without review.

/// The resource limits whose value is the calling shell's own.
///
/// Each of these bounds something the shell and its children may consume:
/// descriptors, processes, memory, CPU time, file size. Setting one can only
/// make the shell's own work fail earlier or later; it writes nothing and it
/// cannot reach another process tree.
const SOFT_RESOURCES: &[char] = &['d', 'f', 'l', 'm', 'n', 's', 't', 'u', 'v'];

/// Whether `basename` with `arguments` sets a resource limit on the calling
/// shell's own process tree and does nothing else.
pub(super) fn safe_shell_limit(basename: &str, arguments: &[String]) -> bool {
    if basename != "ulimit" {
        return false;
    }
    let (flag, value) = match arguments {
        [flag, value] => (flag.as_str(), value.as_str()),
        _ => return false,
    };
    limit_flag(flag) && limit_value(value)
}

/// Whether `flag` selects one of these resources, either bare -- which bash
/// applies to both the soft and the hard limit -- or with the `-S` that names
/// the soft limit alone (`-Sn`, or `-S` folded into `-n`).
fn limit_flag(flag: &str) -> bool {
    let Some(letters) = flag.strip_prefix('-') else {
        return false;
    };
    let mut resources = 0usize;
    for letter in letters.chars() {
        if letter == 'S' {
            continue;
        }
        if !SOFT_RESOURCES.contains(&letter) {
            return false;
        }
        resources += 1;
    }
    resources == 1
}

/// Whether `value` is a limit the shell can set: a plain decimal count or
/// `unlimited`. Anything else -- a substitution, an arithmetic expression, a
/// path -- is not read here.
fn limit_value(value: &str) -> bool {
    if value == "unlimited" {
        return true;
    }
    !value.is_empty() && value.len() <= 20 && value.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
#[path = "shell_limits_tests.rs"]
mod shell_limits_tests;
