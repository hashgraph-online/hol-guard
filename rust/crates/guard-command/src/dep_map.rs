//! Insertion-ordered dependency map.
//!
//! Python manifest parsers return `dict[str, str]`, whose iteration order is
//! insertion order and whose re-assignment keeps the original slot. Workspace
//! inventory and the package-intent target order are observable through that
//! order, so the manifest parsers build this map instead of a sorted one.

use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DepMap {
    keys: Vec<String>,
    values: HashMap<String, String>,
}

impl DepMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// `dict[key] = value`: a repeated key keeps its first position.
    pub fn insert(&mut self, key: String, value: String) -> Option<String> {
        let previous = self.values.insert(key.clone(), value);
        if previous.is_none() {
            self.keys.push(key);
        }
        previous
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.values.get(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.keys.iter()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.keys
            .iter()
            .filter_map(|key| self.values.get_key_value(key))
    }

    pub fn into_sorted(self) -> BTreeMap<String, String> {
        self.values.into_iter().collect()
    }
}
