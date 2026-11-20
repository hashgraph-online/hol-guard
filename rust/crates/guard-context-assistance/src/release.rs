//! The engine release compiled into Guard; never a browser-selected path.

#[derive(Clone)]
pub(crate) struct RuntimeRelease {
    pub sdk_version: String,
    pub core_version: String,
    pub worker_protocol: String,
    pub broker_protocol: String,
    pub adapter_id: String,
    pub adapter_revision: u32,
}
impl RuntimeRelease {
    /// The CIGAR engine compiled into this Guard executable.
    pub fn builtin() -> Self {
        Self {
            sdk_version: guard_cigar_native::CORE_VERSION.into(),
            core_version: guard_cigar_native::CORE_VERSION.into(),
            worker_protocol: guard_cigar_native::WORKER_PROTOCOL.into(),
            broker_protocol: guard_cigar_native::BROKER_PROTOCOL.into(),
            adapter_id: crate::runtime::BUILTIN_ADAPTER.into(),
            adapter_revision: 1,
        }
    }
    pub(crate) fn is_builtin(&self) -> bool {
        self.adapter_id == crate::runtime::BUILTIN_ADAPTER
    }
}
