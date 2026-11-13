//! Local agent inventory and managed harness lifecycle for the Swarm workspace.
//! Observed processes are never control handles. Only a service-owned run may
//! accept instructions or cancellation.

mod adapter;
mod discovery;
mod history;
#[cfg(all(test, unix))]
mod lifecycle_tests;
mod model;
mod process;
mod service;
mod worker;

pub use discovery::{discover, installed_adapters};
pub use model::*;
pub use service::Service;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
