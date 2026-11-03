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
    /// Distinct values a key held before its current one. One lockfile can
    /// resolve a package to several versions, and each one is installed.
    earlier: HashMap<String, Vec<String>>,
}

impl DepMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// `dict[key] = value`: a repeated key keeps its first position.
    pub fn insert(&mut self, key: String, value: String) -> Option<String> {
        let previous = self.values.insert(key.clone(), value.clone());
        match &previous {
            None => self.keys.push(key),
            Some(old) if *old != value => {
                let earlier = self.earlier.entry(key).or_default();
                earlier.retain(|seen| *seen != value);
                if !earlier.contains(old) {
                    earlier.push(old.clone());
                }
            }
            Some(_) => {}
        }
        previous
    }

    /// Distinct values `key` held before its current one, oldest first.
    pub fn earlier(&self, key: &str) -> &[String] {
        self.earlier.get(key).map_or(&[], Vec::as_slice)
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

    /// Every distinct `(key, value)` inserted, sorted by key. A key's earlier
    /// values come first and its current value last, so collecting the
    /// result into a map gives `into_sorted`.
    pub fn into_sorted_versions(mut self) -> Vec<(String, String)> {
        self.keys.sort();
        let mut entries = Vec::with_capacity(self.keys.len());
        for key in self.keys {
            for value in self.earlier.remove(&key).unwrap_or_default() {
                entries.push((key.clone(), value));
            }
            if let Some(value) = self.values.remove(&key) {
                entries.push((key, value));
            }
        }
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_version_a_key_held_is_kept_with_the_current_one_last() {
        let mut map = DepMap::new();
        for (key, value) in [
            ("lodash", "4.17.21"),
            ("debug", "4.3.4"),
            ("lodash", "3.10.1"),
            ("lodash", "4.17.21"),
            ("lodash", "4.17.21"),
            ("lodash", "2.4.2"),
        ] {
            map.insert(key.to_owned(), value.to_owned());
        }
        let current = map.clone().into_sorted();

        let versions = map.into_sorted_versions();

        let pairs: Vec<(&str, &str)> = versions
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("debug", "4.3.4"),
                ("lodash", "3.10.1"),
                ("lodash", "4.17.21"),
                ("lodash", "2.4.2"),
            ]
        );
        assert_eq!(versions.into_iter().collect::<BTreeMap<_, _>>(), current);
    }
}
