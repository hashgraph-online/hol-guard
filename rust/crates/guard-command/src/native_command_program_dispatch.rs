//! Candidate sets contain applicable active rules, never catalog-sized flags.
use super::*;

#[derive(Debug)]
pub(crate) struct CommandCandidateIndex {
    executables: BTreeMap<String, Vec<usize>>,
    keywords: BTreeMap<String, Vec<usize>>,
    unindexed: Vec<usize>,
    extension_indices: Vec<usize>,
    pub(super) memo_layout: Arc<MemoLayout>,
}

pub(super) fn admission_indexes(
    extensions: &[ProgramExtension],
    rules: &[ProgramRule],
) -> (Vec<Vec<usize>>, BTreeSet<String>) {
    let mut owned = vec![Vec::new(); extensions.len()];
    for (index, rule) in rules.iter().enumerate() {
        owned[rule.extension_index].push(index);
    }
    let allows = extensions
        .iter()
        .flat_map(|extension| &extension.permissions)
        .filter(|permission| permission.default_enabled && permission.baseline_floor == "allow")
        .map(|permission| permission.permission_id.clone())
        .collect();
    (owned, allows)
}

impl CommandCandidateIndex {
    pub(crate) fn for_active(program: &NativeCommandProgram, active: &BTreeSet<String>) -> Self {
        let selected = |index: &usize| {
            active.contains(&program.extensions[program.rules[*index].extension_index].extension_id)
        };
        let filter = |map: &BTreeMap<String, Vec<usize>>| {
            map.iter()
                .filter_map(|(key, indices)| {
                    let values: Vec<_> = indices
                        .iter()
                        .filter(|index| selected(index))
                        .copied()
                        .collect();
                    (!values.is_empty()).then(|| (key.clone(), values))
                })
                .collect()
        };
        Self {
            memo_layout: MemoLayout::for_active(program, active),
            extension_indices: program
                .extensions
                .iter()
                .enumerate()
                .filter_map(|(index, extension)| {
                    active.contains(&extension.extension_id).then_some(index)
                })
                .collect(),
            executables: filter(&program.executable_index),
            keywords: filter(&program.keyword_index),
            unindexed: program
                .unindexed
                .iter()
                .filter(|index| selected(index))
                .copied()
                .collect(),
        }
    }

    pub(crate) fn candidates(&self, command: &CanonicalCommandV1) -> Vec<usize> {
        candidates(command, &self.executables, &self.keywords, &self.unindexed)
    }

    pub(crate) fn extension_indices(&self) -> &[usize] {
        &self.extension_indices
    }
}

pub(super) fn candidates(
    command: &CanonicalCommandV1,
    executables: &BTreeMap<String, Vec<usize>>,
    keywords: &BTreeMap<String, Vec<usize>>,
    unindexed: &[usize],
) -> Vec<usize> {
    let mut selected: BTreeSet<usize> = unindexed.iter().copied().collect();
    for segment in &command.segments {
        if let Some(executable) = segment.executable.as_deref() {
            if let Some(indices) =
                executables.get(&lowercase_for_ascii_comparison(basename(executable)))
            {
                selected.extend(indices.iter().copied());
            }
        }
        for token in &segment.tokens {
            if let Some(indices) = keywords.get(&lowercase_for_ascii_comparison(token)) {
                selected.extend(indices.iter().copied());
            }
        }
    }
    selected.into_iter().collect()
}

#[cfg(test)]
#[path = "native_command_program_dispatch_tests.rs"]
mod tests;
