//! Opaque Linux filesystem-object identity, interpreted only with a separately
//! observed filesystem device. A handle is not a pathname or a writer identity.

use serde_json::{json, Value};

pub const MAX_EFFECT_HANDLE_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectFileHandle {
    kind: i32,
    bytes: String,
}

impl EffectFileHandle {
    pub fn from_kernel(kind: i32, bytes: &[u8]) -> Option<Self> {
        if kind < 0 || bytes.is_empty() || bytes.len() > MAX_EFFECT_HANDLE_BYTES {
            return None;
        }
        Some(Self {
            kind,
            bytes: bytes.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }

    pub fn from_json(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if object.len() != 2 {
            return None;
        }
        let kind = i32::try_from(object.get("kind")?.as_u64()?).ok()?;
        let bytes = object.get("bytes")?.as_str()?;
        if bytes.is_empty()
            || bytes.len() > MAX_EFFECT_HANDLE_BYTES * 2
            || bytes.len() % 2 != 0
            || !bytes
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        Some(Self {
            kind,
            bytes: bytes.to_owned(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({"kind":self.kind,"bytes":self.bytes})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_bounded_opaque_and_strictly_typed() {
        let handle = EffectFileHandle::from_kernel(1, &[1, 0, 255, 128]).unwrap();
        assert_eq!(handle.to_json(), json!({"kind":1,"bytes":"0100ff80"}));
        assert_eq!(EffectFileHandle::from_json(&handle.to_json()), Some(handle));
        for value in [
            json!({"kind":-1,"bytes":"ab"}),
            json!({"kind":true,"bytes":"ab"}),
            json!({"kind":1.0,"bytes":"ab"}),
            json!({"kind":2147483648u64,"bytes":"ab"}),
            json!({"kind":1,"bytes":"AB"}),
            json!({"kind":1,"bytes":"a"}),
            json!({"kind":1,"bytes":""}),
            json!({"kind":1,"bytes":"aa".repeat(MAX_EFFECT_HANDLE_BYTES + 1)}),
            json!({"kind":1,"bytes":"ab","extra":true}),
            Value::Null,
        ] {
            assert!(EffectFileHandle::from_json(&value).is_none());
        }
        assert!(EffectFileHandle::from_kernel(1, &[]).is_none());
        assert!(EffectFileHandle::from_kernel(-1, &[1]).is_none());
    }
}
