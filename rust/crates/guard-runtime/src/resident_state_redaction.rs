#![forbid(unsafe_code)]

use super::ResidentState;

/// The published state carries the resident's authentication token, so the
/// derived `Debug` would put the key into any message that formats a state.
/// This rendering keeps every field a diagnostic needs and names the token
/// without disclosing it.
impl std::fmt::Debug for ResidentState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentState")
            .field("schema", &self.schema)
            .field("generation", &self.generation)
            .field("process_id", &self.process_id)
            .field("process_start_marker", &self.process_start_marker)
            .field("owner_process_id", &self.owner_process_id)
            .field(
                "owner_process_start_marker",
                &self.owner_process_start_marker,
            )
            .field("runtime_sha256", &self.runtime_sha256)
            .field("transport", &self.transport)
            .field("endpoint", &self.endpoint)
            .field("unix_endpoint_identity", &self.unix_endpoint_identity)
            .field("token_hex", &"<redacted>")
            .field("created_ms", &self.created_ms)
            .field("state_mac", &self.state_mac)
            .finish()
    }
}
