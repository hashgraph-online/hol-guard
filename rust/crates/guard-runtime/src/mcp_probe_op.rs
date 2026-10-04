//! `McpStdioProbe` resident op — leave full protocol negotiation and catalog
//! discovery to Python until the Rust path supports the same catalog contract.
//! `result: None` asks the caller to fall back to that implementation.

use guard_contracts::{
    McpStdioProbeRequestV1, McpStdioProbeResultV1, MCP_STDIO_PROBE_REQUEST_SCHEMA,
    MCP_STDIO_PROBE_RESULT_SCHEMA,
};

pub(crate) fn evaluate_mcp_stdio_probe(
    request: &McpStdioProbeRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != MCP_STDIO_PROBE_REQUEST_SCHEMA {
        return Err(format!("schema_mismatch:{}", request.schema));
    }
    // Catalog negotiation, pagination, and skills discovery remain Python-owned.
    // Returning None asks the caller to use that complete negotiation path.
    crate::encode_response(&McpStdioProbeResultV1 {
        schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
        result: None,
    })
}
