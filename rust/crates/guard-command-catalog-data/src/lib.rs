//! Build-time packaged command artifacts for `guard-command`.
//!
//! The zstd-19 catalog compilation, trust-map projection, and embedded blob
//! digests live behind this leaf crate so an unrelated `guard-command` source
//! edit no longer reruns catalog generation. Constants mirror the build
//! outputs byte-for-byte; consumers keep their existing fail-closed decode.

/// Authored trust-class projection (`contracts/extensions/trust/` core set).
pub const TRUST_MAP_JSON: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/trust-class-map.v1.json"));

/// Compiled native command program, zstd-19 compressed.
pub const PROGRAM_JSON_ZST: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/native-command-program.v1.json.zst"
));

/// Catalog metadata projection, canonical JSON (uncompressed).
pub const CATALOG_JSON: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/command-catalog.v1.json"));

/// Catalog metadata projection, zstd-19 compressed.
pub const CATALOG_JSON_ZST: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/command-catalog.v1.json.zst"));

/// Export-envelope build record, zstd-19 compressed.
pub const BUILD_JSON_ZST: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/native-command-build.v1.json.zst"
));

/// SHA-256 hex of the uncompressed program JSON (with trailing newline).
pub const PROGRAM_JSON_SHA256: &str = env!("GUARD_PACKAGED_PROGRAM_SHA256");
/// Byte length of the uncompressed program JSON.
pub const PROGRAM_JSON_LEN: &str = env!("GUARD_PACKAGED_PROGRAM_LEN");
/// `program_digest` identity without decoding the embedded artifact.
pub const PROGRAM_ID: &str = env!("GUARD_PACKAGED_PROGRAM_ID");
/// Comma-joined default (required/non-external) command pack identities.
pub const DEFAULT_COMMAND_PACK_IDS: &str = env!("GUARD_DEFAULT_COMMAND_PACK_IDS");

/// SHA-256 hex of the uncompressed catalog JSON.
pub const CATALOG_JSON_SHA256: &str = env!("GUARD_PACKAGED_CATALOG_SHA256");
/// Byte length of the uncompressed catalog JSON.
pub const CATALOG_JSON_LEN: &str = env!("GUARD_PACKAGED_CATALOG_LEN");

/// SHA-256 hex of the uncompressed build-envelope JSON.
pub const BUILD_JSON_SHA256: &str = env!("GUARD_PACKAGED_BUILD_SHA256");
/// Byte length of the uncompressed build-envelope JSON.
pub const BUILD_JSON_LEN: &str = env!("GUARD_PACKAGED_BUILD_LEN");

/// Host/target command-source implementation identity bound into the artifacts.
pub const IMPLEMENTATION_DIGEST: &str = env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION");
