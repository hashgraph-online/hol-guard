//! Borrowed canonical JSON and a bounded, non-buffering serialized-size check.
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use std::io::{self, Write};

pub(super) struct Canonical<'a>(pub &'a Value);

impl Serialize for Canonical<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&Canonical(value))?;
                }
                sequence.end()
            }
            Value::Object(values) => canonical_map(values, &[], serializer),
            value => value.serialize(serializer),
        }
    }
}

pub(super) fn canonical_map<S: Serializer>(
    values: &Map<String, Value>,
    omitted: &[&str],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // Explicit sorting preserves the existing canonical contract even if a
    // future dependency enables serde_json's insertion-order map feature.
    let mut entries: Vec<_> = values
        .iter()
        .filter(|(key, _)| !omitted.contains(&key.as_str()))
        .collect();
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let mut map = serializer.serialize_map(Some(entries.len()))?;
    for (key, value) in entries {
        map.serialize_entry(key, &Canonical(value))?;
    }
    map.end()
}

struct BoundedCount {
    bytes: usize,
    maximum: usize,
}

impl Write for BoundedCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn serialized_size_within<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<usize, serde_json::Error> {
    let mut count = BoundedCount { bytes: 0, maximum };
    serde_json::to_writer(&mut count, value)?;
    Ok(count.bytes)
}

#[cfg(test)]
#[path = "edge_serialization_tests.rs"]
mod tests;
