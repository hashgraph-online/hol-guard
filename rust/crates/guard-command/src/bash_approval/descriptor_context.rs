//! A descriptor in the host shell is not the resident's descriptor.

use std::path::{Component, Path};

pub fn is_descriptor_reference(value: &str) -> bool {
    let parts: Vec<_> = Path::new(value)
        .components()
        .filter_map(|part| match part {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect();
    parts
        .windows(2)
        .any(|parts| parts[0] == "dev" && matches!(parts[1], "fd" | "stdin" | "stdout" | "stderr"))
        || parts.windows(3).any(|parts| {
            parts[0] == "proc" && matches!(parts[1], "self" | "thread-self") && parts[2] == "fd"
        })
}
