use super::{PolicySnapshotV3, SnapshotError, POLICY_SNAPSHOT_MAX_BYTES};
use serde_json::Value;

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, SnapshotError> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output).map_err(|_| SnapshotError::Serialization)?;
    Ok(output)
}

pub fn snapshot_bytes(snapshot: &PolicySnapshotV3) -> Result<Vec<u8>, SnapshotError> {
    let value = serde_json::to_value(snapshot).map_err(|_| SnapshotError::Serialization)?;
    let bytes = canonical_json_bytes(&value)?;
    if bytes.len() > POLICY_SNAPSHOT_MAX_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    Ok(bytes)
}

pub fn snapshot_signing_bytes(snapshot: &PolicySnapshotV3) -> Result<Vec<u8>, SnapshotError> {
    let mut value = serde_json::to_value(snapshot).map_err(|_| SnapshotError::Serialization)?;
    let object = value.as_object_mut().ok_or(SnapshotError::Serialization)?;
    object.remove("integrity");
    canonical_json_bytes(&value)
}
pub fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), std::fmt::Error> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            let encoded = serde_json::to_string(value).map_err(|_| std::fmt::Error)?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                let encoded = serde_json::to_string(key).map_err(|_| std::fmt::Error)?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_json(values.get(*key).ok_or(std::fmt::Error)?, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}
