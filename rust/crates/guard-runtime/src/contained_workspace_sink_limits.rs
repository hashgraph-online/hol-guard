//! The resource limits the launcher applies before it starts a sandboxed
//! command.
//!
//! A Node run on Linux keeps the same 4 GiB cap on the memory it can write
//! but not on its address space: V8 and WebAssembly reserve inaccessible
//! cages far larger than their working heap. `RLIMIT_DATA` bounds the heap
//! and private writable maps on the kernels Guard runs on; it is not an
//! aggregate RSS limit, so the wider address space is never granted without
//! it.

use nix::sys::resource::Resource;

const CPU_SECONDS: u64 = 1200;
const ADDRESS_SPACE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const NODE_ADDRESS_SPACE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FILE_SIZE_BYTES: u64 = 256 * 1024 * 1024;
const OPEN_FILES: u64 = 256;

/// Lower this process's limits for the sandboxed command, with `ceiling`
/// processes and, when `node`, a Node run's memory bounds on Linux. `false`
/// when the Node bounds could not be enforced.
pub(super) fn apply(ceiling: u64, node: bool) -> bool {
    lower(Resource::RLIMIT_CPU, CPU_SECONDS);
    if node && cfg!(target_os = "linux") {
        if !(enforce(Resource::RLIMIT_DATA, ADDRESS_SPACE_BYTES)
            && enforce(Resource::RLIMIT_AS, NODE_ADDRESS_SPACE_BYTES))
        {
            return false;
        }
    } else {
        lower(Resource::RLIMIT_AS, ADDRESS_SPACE_BYTES);
    }
    lower(Resource::RLIMIT_FSIZE, FILE_SIZE_BYTES);
    lower(Resource::RLIMIT_NOFILE, OPEN_FILES);
    #[cfg(not(target_vendor = "apple"))]
    lower(Resource::RLIMIT_NPROC, ceiling);
    #[cfg(target_vendor = "apple")]
    let _ = ceiling;
    true
}

/// Lower `resource` to `requested` without raising either limit; a limit
/// the platform refuses is left as it is.
fn lower(resource: Resource, requested: u64) {
    let Ok((soft, hard)) = nix::sys::resource::getrlimit(resource) else {
        return;
    };
    let (soft, hard) = lowered(soft, hard, requested);
    let _ = nix::sys::resource::setrlimit(resource, soft, hard);
}

/// Lower `resource` to `requested`, and whether both limits now hold at or
/// below it.
fn enforce(resource: Resource, requested: u64) -> bool {
    lower(resource, requested);
    nix::sys::resource::getrlimit(resource)
        .is_ok_and(|(soft, hard)| soft <= requested && hard <= requested)
}

fn lowered(soft: u64, hard: u64, requested: u64) -> (u64, u64) {
    let infinite = libc::RLIM_INFINITY;
    let hard = if hard == infinite {
        requested
    } else {
        requested.min(hard)
    };
    let soft = if soft == infinite {
        hard
    } else {
        requested.min(soft).min(hard)
    };
    (soft, hard)
}

#[cfg(test)]
#[path = "contained_workspace_sink_limits_tests.rs"]
mod tests;
