//! Separate local evidence role; these keys cannot sign catalogs/installations.
use super::*;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use std::io::{Read, Write};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    payload: String,
    mac: String,
}
pub(super) struct Authority {
    directory: Directory,
    file: File,
    key_sha256: String,
    key: hmac::Key,
    home_sha256: String,
}
impl Authority {
    pub(super) fn open(
        directory: &Directory,
        home: &Path,
        provision: bool,
    ) -> Result<Self, RuntimeError> {
        let names = directory.names(MAX_GENERATIONS + 2)?;
        let exists = names.iter().any(|n| n == "authority.key");
        if !exists {
            if !provision || names.iter().any(|n| n != "store.lock") {
                return Err(RuntimeError::StorageRepairRequired);
            }
            let mut bytes = [0u8; 32];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| RuntimeError::ArtifactUnreadable)?;
            let mut file = directory.open_file("authority.key", Access::CreateNew, 32)?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| RuntimeError::StorageOutcomeUnknown)?;
            directory.sync()?;
            directory.check_file("authority.key", &file, 32)?;
        }
        let file = directory.open_file("authority.key", Access::Read, 32)?;
        let mut bytes = Vec::new();
        (&file)
            .take(33)
            .read_to_end(&mut bytes)
            .map_err(|_| RuntimeError::ArtifactUnreadable)?;
        directory.check_file("authority.key", &file, 32)?;
        if bytes.len() != 32 {
            return Err(RuntimeError::StorageRepairRequired);
        }
        Ok(Self {
            directory: Directory::inspect(&directory.path)?,
            file,
            key_sha256: format!("{:x}", Sha256::digest(&bytes)),
            key: hmac::Key::new(hmac::HMAC_SHA256, &bytes),
            home_sha256: format!("{:x}", Sha256::digest(home.as_os_str().as_encoded_bytes())),
        })
    }
    pub(super) fn check(&self) -> Result<(), RuntimeError> {
        self.directory.check_file("authority.key", &self.file, 32)?;
        let bytes = self.directory.read_limit("authority.key", 32)?;
        if bytes.len() != 32 || format!("{:x}", Sha256::digest(bytes)) != self.key_sha256 {
            return Err(RuntimeError::StorageRepairRequired);
        }
        Ok(())
    }
    fn message(&self, id: &str, payload: &str) -> Result<Vec<u8>, RuntimeError> {
        let bytes = serde_json::to_vec(&(
            "hol-guard-cigar-evidence-generation.v1",
            &self.home_sha256,
            id,
            payload,
        ))
        .map_err(|_| RuntimeError::StorageRepairRequired)?;
        Ok(bytes)
    }
    pub(super) fn seal(&self, record: &Record) -> Result<Vec<u8>, RuntimeError> {
        self.check()?;
        record.validate()?;
        let payload =
            serde_json::to_string(record).map_err(|_| RuntimeError::StorageRepairRequired)?;
        if payload.len() > PAYLOAD_BYTES {
            return Err(RuntimeError::ResourceLimit);
        }
        let mac = hmac::sign(&self.key, &self.message(&record.generation_id, &payload)?);
        let mac = mac.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        let bytes = serde_json::to_vec(&Envelope {
            schema: "guard-cigar-sealed-evidence-generation.v1".into(),
            payload,
            mac,
        })
        .map_err(|_| RuntimeError::StorageRepairRequired)?;
        if bytes.len() as u64 > RECORD_BYTES {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
    pub(super) fn read(&self, directory: &Directory, id: &str) -> Result<Record, RuntimeError> {
        self.check()?;
        let bytes = directory.read_limit("state.json", RECORD_BYTES)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| RuntimeError::StorageRepairRequired)?;
        if envelope.schema != "guard-cigar-sealed-evidence-generation.v1"
            || envelope.payload.len() > PAYLOAD_BYTES
            || !valid_key(&envelope.mac)
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let mac: Vec<_> = envelope
            .mac
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(
                    std::str::from_utf8(pair).map_err(|_| RuntimeError::StorageRepairRequired)?,
                    16,
                )
                .map_err(|_| RuntimeError::StorageRepairRequired)
            })
            .collect::<Result<_, _>>()?;
        hmac::verify(&self.key, &self.message(id, &envelope.payload)?, &mac)
            .map_err(|_| RuntimeError::StorageRepairRequired)?;
        let record: Record = serde_json::from_str(&envelope.payload)
            .map_err(|_| RuntimeError::StorageRepairRequired)?;
        record.validate()?;
        if record.generation_id != id {
            return Err(RuntimeError::StorageRepairRequired);
        }
        Ok(record)
    }
}
