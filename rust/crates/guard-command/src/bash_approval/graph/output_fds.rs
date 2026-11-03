//! Native descriptor layouts for the one-frame and acknowledged launch owners.

use super::*;

/// Output descriptors start at fd6 in the original source-delivery protocol.
pub fn build_with_outputs(
    entry: Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    deadline: Instant,
    output_fds: &BTreeMap<String, u32>,
) -> Result<Graph> {
    build(entry, argv, environment, resolver, deadline, output_fds, 6)
}

/// The acknowledged protocol reserves fd6 for its native-owned socket.
pub fn build_with_acknowledged_outputs(
    entry: Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    deadline: Instant,
    output_fds: &BTreeMap<String, u32>,
) -> Result<Graph> {
    build(entry, argv, environment, resolver, deadline, output_fds, 7)
}

/// The acknowledged protocol reserves fd6 and the compiled-image broker uses
/// fd7, so held output descriptors begin at fd8.
pub fn build_with_acknowledged_broker_outputs(
    entry: Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    deadline: Instant,
    output_fds: &BTreeMap<String, u32>,
) -> Result<Graph> {
    build(entry, argv, environment, resolver, deadline, output_fds, 8)
}

fn build(
    entry: Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    deadline: Instant,
    output_fds: &BTreeMap<String, u32>,
    first_fd: u32,
) -> Result<Graph> {
    let unique = output_fds.values().copied().collect::<BTreeSet<_>>();
    if output_fds.len() > 64
        || unique.len() != output_fds.len()
        || unique
            .iter()
            .enumerate()
            .any(|(index, fd)| *fd != first_fd + index as u32)
    {
        return Err(Uncertainty {
            reason: "bash_output_descriptor_bounds",
            line: 1,
        });
    }
    build_inner(
        entry,
        argv,
        environment,
        resolver,
        deadline,
        Some(output_fds),
    )
}
