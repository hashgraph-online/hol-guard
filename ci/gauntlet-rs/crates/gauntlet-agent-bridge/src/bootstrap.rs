//! Private, bounded bootstrap for the two authenticated frame dialects.
//! The caller must authenticate the inherited management pipe and kernel
//! boot ID before supplying them here. Key bytes never enter an error.

use crate::{nonblocking, read_exact, validate_management_fd, write_all, BridgeIoError, Result};
use gauntlet_contracts::canonicalize;
use gauntlet_evidence::FrameCodec;
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use uuid::Uuid;

const BOOTSTRAP_LIMIT: usize = 4096;
const VM_SCHEMA: &str = "gauntlet-vm-bridge-private-bootstrap.v1";
const CELL_SCHEMA: &str = "product-cell-private-bootstrap.v1";
const VM_HASH_FILES: [&str; 5] = [
    "json_data.py",
    "vm_bridge_frames.py",
    "vm_bridge_io.py",
    "vm_bridge_rpc.py",
    "vm_bridge_control.py",
];
const FINGERPRINT_DOMAIN: &[u8] = b"vm-bridge-control-auth.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapKind {
    VmController,
    VmProductCollector,
    ProductCellSupervisor,
    ProductCellActor,
}

pub struct Bootstrap {
    kind: BootstrapKind,
    key: [u8; 32],
    session: String,
    local_boot: String,
    peer_boot: String,
}

/// One-use outbound bootstrap. A failed or partial write consumes the object.
pub struct OutboundBootstrap {
    bootstrap: Bootstrap,
    body: Vec<u8>,
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)))
}

fn canonical_uuid(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    Uuid::parse_str(text)
        .ok()
        .filter(|parsed| parsed.to_string() == text)
        .map(|_| text)
}

fn lower_sha(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn decode_key(value: &Value) -> Option<[u8; 32]> {
    if !lower_sha(value) {
        return None;
    }
    let hex = value.as_str()?.as_bytes();
    let mut key = [0_u8; 32];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        key[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(key)
}

/// Read one length-prefixed private bootstrap before constructing a codec.
/// The caller owns the descriptor and must close it after any failed read.
pub fn read_private_bootstrap(
    reader: &OwnedFd,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    validate_management_fd(reader.as_raw_fd())?;
    nonblocking(reader.as_raw_fd())?;
    let mut header = [0_u8; 4];
    read_exact(reader.as_raw_fd(), &mut header, deadline, cancelled)?;
    let length = u32::from_be_bytes(header) as usize;
    if !(1..=BOOTSTRAP_LIMIT).contains(&length) {
        return Err(BridgeIoError::Invalid("private bootstrap byte budget"));
    }
    let mut body = vec![0_u8; length];
    read_exact(reader.as_raw_fd(), &mut body, deadline, cancelled)?;
    Ok(body)
}

impl Bootstrap {
    /// `local_boot` and `expected_vm_hashes` must come from outside the
    /// bootstrap. Cell bootstraps have no embedded source-hash manifest.
    pub fn parse(
        raw: &[u8],
        kind: BootstrapKind,
        local_boot: &str,
        expected_vm_hashes: Option<&Value>,
    ) -> Result<Self> {
        if raw.is_empty() || raw.len() > BOOTSTRAP_LIMIT {
            return Err(BridgeIoError::Invalid("private bootstrap byte budget"));
        }
        let canonical = canonicalize(raw)
            .map_err(|_| BridgeIoError::Invalid("private bootstrap JSON invalid"))?;
        let value: Value = serde_json::from_slice(&canonical)
            .map_err(|_| BridgeIoError::Invalid("private bootstrap JSON invalid"))?;
        let vm = matches!(
            kind,
            BootstrapKind::VmController | BootstrapKind::VmProductCollector
        );
        let identity_error = if vm {
            "private bootstrap identity mismatch"
        } else {
            "private cell bootstrap mismatch"
        };
        let keys: &[&str] = if vm {
            &[
                "schema",
                "session",
                "key_hex",
                "controller_boot",
                "product_boot",
                "hashes",
            ]
        } else {
            &["schema", "session", "key_hex", "boot_id"]
        };
        if !exact_keys(&value, keys)
            || value["schema"] != if vm { VM_SCHEMA } else { CELL_SCHEMA }
            || canonical_uuid(&value["session"]).is_none()
        {
            return Err(BridgeIoError::Invalid(identity_error));
        }
        let key = decode_key(&value["key_hex"]).ok_or(BridgeIoError::Invalid(identity_error))?;
        let (local, peer) = if vm {
            let expected = expected_vm_hashes.ok_or(BridgeIoError::Invalid(identity_error))?;
            if !exact_keys(expected, &VM_HASH_FILES)
                || !VM_HASH_FILES.iter().all(|file| lower_sha(&expected[*file]))
                || value["hashes"] != *expected
            {
                return Err(BridgeIoError::Invalid(identity_error));
            }
            let controller = canonical_uuid(&value["controller_boot"])
                .ok_or(BridgeIoError::Invalid(identity_error))?;
            let product = canonical_uuid(&value["product_boot"])
                .ok_or(BridgeIoError::Invalid(identity_error))?;
            match kind {
                BootstrapKind::VmController => (controller, product),
                BootstrapKind::VmProductCollector => (product, controller),
                _ => unreachable!(),
            }
        } else {
            if expected_vm_hashes.is_some() {
                return Err(BridgeIoError::Invalid(identity_error));
            }
            let boot =
                canonical_uuid(&value["boot_id"]).ok_or(BridgeIoError::Invalid(identity_error))?;
            (boot, boot)
        };
        if local != local_boot || canonical_uuid(&Value::String(local_boot.to_owned())).is_none() {
            return Err(BridgeIoError::Invalid(identity_error));
        }
        Ok(Self {
            kind,
            key,
            session: value["session"].as_str().unwrap().to_owned(),
            local_boot: local.to_owned(),
            peer_boot: peer.to_owned(),
        })
    }

    pub fn vm_auth_fingerprint(&self) -> Option<String> {
        if matches!(
            self.kind,
            BootstrapKind::ProductCellSupervisor | BootstrapKind::ProductCellActor
        ) {
            return None;
        }
        let mut data = Vec::with_capacity(FINGERPRINT_DOMAIN.len() + self.key.len());
        data.extend_from_slice(FINGERPRINT_DOMAIN);
        data.extend_from_slice(&self.key);
        Some(
            digest(&SHA256, &data)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )
    }

    pub fn into_codec(self, max_frames: u64, max_bytes: usize) -> Result<FrameCodec> {
        let role = match self.kind {
            BootstrapKind::VmController => "controller",
            BootstrapKind::VmProductCollector => "product-collector",
            BootstrapKind::ProductCellSupervisor => "cell-supervisor",
            BootstrapKind::ProductCellActor => "cell-actor",
        };
        let result = if matches!(
            self.kind,
            BootstrapKind::VmController | BootstrapKind::VmProductCollector
        ) {
            FrameCodec::new(
                &self.key,
                &self.session,
                role,
                &self.local_boot,
                &self.peer_boot,
                max_frames,
                max_bytes,
            )
        } else {
            FrameCodec::new_product_cell(
                &self.key,
                &self.session,
                role,
                &self.local_boot,
                &self.peer_boot,
                max_frames,
                max_bytes,
            )
        };
        result.map_err(|error| BridgeIoError::Frame(error.to_string()))
    }
}

impl OutboundBootstrap {
    /// The boot IDs and VM source map must be reviewed outside the child.
    /// The key and session are freshly generated here, never selected by a
    /// candidate payload or serialized anywhere except the private pipe.
    pub fn generate(
        kind: BootstrapKind,
        local_boot: &str,
        peer_boot: &str,
        expected_vm_hashes: Option<&Value>,
    ) -> Result<Self> {
        let mut key = [0_u8; 32];
        let mut session_bytes = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| BridgeIoError::Invalid("private bootstrap randomness unavailable"))?;
        SystemRandom::new()
            .fill(&mut session_bytes)
            .map_err(|_| BridgeIoError::Invalid("private bootstrap randomness unavailable"))?;
        session_bytes[6] = (session_bytes[6] & 0x0f) | 0x40;
        session_bytes[8] = (session_bytes[8] & 0x3f) | 0x80;
        let session = Uuid::from_bytes(session_bytes).to_string();
        Self::assemble(
            kind,
            local_boot,
            peer_boot,
            expected_vm_hashes,
            &key,
            &session,
        )
    }

    fn assemble(
        kind: BootstrapKind,
        local_boot: &str,
        peer_boot: &str,
        expected_vm_hashes: Option<&Value>,
        key: &[u8; 32],
        session: &str,
    ) -> Result<Self> {
        let key_hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        let vm = matches!(
            kind,
            BootstrapKind::VmController | BootstrapKind::VmProductCollector
        );
        let value = if vm {
            let hashes = expected_vm_hashes
                .ok_or(BridgeIoError::Invalid("outside VM source hashes required"))?;
            let (controller, product) = if kind == BootstrapKind::VmController {
                (local_boot, peer_boot)
            } else {
                (peer_boot, local_boot)
            };
            json!({
                "schema": VM_SCHEMA,
                "session": session,
                "key_hex": key_hex,
                "controller_boot": controller,
                "product_boot": product,
                "hashes": hashes,
            })
        } else {
            if local_boot != peer_boot || expected_vm_hashes.is_some() {
                return Err(BridgeIoError::Invalid("private cell bootstrap mismatch"));
            }
            json!({
                "schema": CELL_SCHEMA,
                "session": session,
                "key_hex": key_hex,
                "boot_id": local_boot,
            })
        };
        let body = canonicalize(
            &serde_json::to_vec(&value)
                .map_err(|_| BridgeIoError::Invalid("private bootstrap JSON invalid"))?,
        )
        .map_err(|_| BridgeIoError::Invalid("private bootstrap JSON invalid"))?;
        let bootstrap = Bootstrap::parse(&body, kind, local_boot, expected_vm_hashes)?;
        Ok(Self { bootstrap, body })
    }

    pub fn vm_auth_fingerprint(&self) -> Option<String> {
        self.bootstrap.vm_auth_fingerprint()
    }

    pub fn deliver(
        self,
        writer: &OwnedFd,
        deadline: Instant,
        cancelled: &AtomicBool,
        max_frames: u64,
        max_bytes: usize,
    ) -> Result<FrameCodec> {
        let codec = self.bootstrap.into_codec(max_frames, max_bytes)?;
        validate_management_fd(writer.as_raw_fd())?;
        nonblocking(writer.as_raw_fd())?;
        let length: u32 = self
            .body
            .len()
            .try_into()
            .map_err(|_| BridgeIoError::Invalid("private bootstrap byte budget"))?;
        write_all(
            writer.as_raw_fd(),
            &length.to_be_bytes(),
            deadline,
            cancelled,
        )?;
        write_all(writer.as_raw_fd(), &self.body, deadline, cancelled)?;
        Ok(codec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn supplied_synthetic_material_matches_pinned_python_bootstrap_bytes() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/python_bootstrap_v1.json"))
                .unwrap();
        let vm = OutboundBootstrap::assemble(
            BootstrapKind::VmController,
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            Some(&fixture["vm"]["body"]["hashes"]),
            &[b'B'; 32],
            "11111111-1111-1111-1111-111111111111",
        )
        .unwrap();
        assert_eq!(vm.body, bytes(fixture["vm"]["bytes_hex"].as_str().unwrap()));
        let cell = OutboundBootstrap::assemble(
            BootstrapKind::ProductCellSupervisor,
            "22222222-2222-2222-2222-222222222222",
            "22222222-2222-2222-2222-222222222222",
            None,
            &[b'C'; 32],
            "11111111-1111-1111-1111-111111111111",
        )
        .unwrap();
        assert_eq!(
            cell.body,
            bytes(fixture["cell"]["bytes_hex"].as_str().unwrap())
        );
    }
}
