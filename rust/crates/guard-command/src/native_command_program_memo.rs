//! Active-layout memo leases. Retained storage is bounded per thread; decisions
//! clear only touched slots and never scan unrelated catalog nodes.
use super::*;
use std::cell::RefCell;

const CACHED_LAYOUTS: usize = 2;

#[derive(Debug)]
pub(super) struct MemoLayout {
    slots: Vec<usize>,
    active_nodes: usize,
}

impl MemoLayout {
    #[cfg(test)]
    pub(super) fn active_node_count(&self) -> usize {
        self.active_nodes
    }
    pub(super) fn for_active(
        program: &NativeCommandProgram,
        active: &BTreeSet<String>,
    ) -> Arc<Self> {
        let mut slots = vec![usize::MAX; program.nodes.len()];
        let mut pending = Vec::new();
        for rule in &program.rules {
            if active.contains(&program.extensions[rule.extension_index].extension_id) {
                pending.extend(rule.matcher);
                pending.extend(rule.variants.iter().map(|(_, index)| *index));
            }
        }
        let mut active_nodes = 0;
        while let Some(index) = pending.pop() {
            if slots[index] != usize::MAX {
                continue;
            }
            slots[index] = active_nodes;
            active_nodes += 1;
            match &program.nodes[index].matcher {
                Matcher::Any(children) | Matcher::All(children) => pending.extend(children),
                Matcher::Pipeline(producer, consumer) => pending.extend([producer, consumer]),
                _ => {}
            }
        }
        Arc::new(Self {
            slots,
            active_nodes,
        })
    }
}

struct Entry {
    generation: u64,
    value: Option<MatchResult>,
}
struct Cache {
    layout: Arc<MemoLayout>,
    generation: u64,
    entries: Vec<Entry>,
    touched: Vec<usize>,
}

thread_local! {
    static POOL: RefCell<Vec<Cache>> = const { RefCell::new(Vec::new()) };
}

pub(super) struct MemoLease {
    cache: Option<Cache>,
}

impl MemoLease {
    fn new(layout: Arc<MemoLayout>) -> Self {
        // Remove the lease from the pool before evaluation. Reentrant calls and
        // other threads cannot borrow or see this decision's partial results.
        let cached = POOL
            .try_with(|pool| {
                let mut pool = pool.try_borrow_mut().ok()?;
                let index = pool
                    .iter()
                    .position(|cache| Arc::ptr_eq(&cache.layout, &layout))?;
                Some(pool.swap_remove(index))
            })
            .ok()
            .flatten();
        let mut cache = cached.unwrap_or_else(|| Cache {
            entries: (0..layout.active_nodes)
                .map(|_| Entry {
                    generation: 0,
                    value: None,
                })
                .collect(),
            layout,
            generation: 0,
            touched: Vec::new(),
        });
        // Values are cleared on return even when evaluation exits with an error.
        // The generation check separately prevents reuse across command models.
        cache.generation = if let Some(next) = cache.generation.checked_add(1) {
            next
        } else {
            for entry in &mut cache.entries {
                entry.generation = 0;
                entry.value = None;
            }
            1
        };
        Self { cache: Some(cache) }
    }

    fn get(&self, index: usize) -> Option<&MatchResult> {
        let cache = self.cache.as_ref()?;
        let slot = *cache.layout.slots.get(index)?;
        let entry = cache.entries.get(slot)?;
        (entry.generation == cache.generation)
            .then_some(entry.value.as_ref())
            .flatten()
    }

    fn insert(&mut self, index: usize, value: MatchResult) -> Result<(), &'static str> {
        let cache = self
            .cache
            .as_mut()
            .ok_or("native_command_memo_unavailable")?;
        let slot = *cache
            .layout
            .slots
            .get(index)
            .ok_or("native_command_memo_node_invalid")?;
        let entry = cache
            .entries
            .get_mut(slot)
            .ok_or("native_command_inactive_memo_node")?;
        if entry.generation != cache.generation {
            cache.touched.push(slot);
            entry.generation = cache.generation;
        }
        entry.value = Some(value);
        Ok(())
    }
}

impl Drop for MemoLease {
    fn drop(&mut self) {
        let Some(mut cache) = self.cache.take() else {
            return;
        };
        for slot in cache.touched.drain(..) {
            cache.entries[slot].value = None;
        }
        // During thread-local destruction or a nested borrow, discard storage.
        // Neither case is allowed to affect a decision or retain its evidence.
        let _ = POOL.try_with(|pool| {
            if let Ok(mut pool) = pool.try_borrow_mut() {
                if pool.len() >= CACHED_LAYOUTS {
                    pool.remove(0);
                }
                pool.push(cache);
            }
        });
    }
}

pub(super) enum NodeMemo {
    Sparse(HashMap<usize, MatchResult>),
    Active(MemoLease),
}

impl NodeMemo {
    pub(super) fn new(layout: Option<Arc<MemoLayout>>) -> Self {
        layout
            .map(|layout| Self::Active(MemoLease::new(layout)))
            .unwrap_or_else(|| Self::Sparse(HashMap::new()))
    }

    pub(super) fn get(&self, index: usize) -> Option<&MatchResult> {
        match self {
            Self::Sparse(values) => values.get(&index),
            Self::Active(lease) => lease.get(index),
        }
    }

    pub(super) fn insert(&mut self, index: usize, value: MatchResult) -> Result<(), &'static str> {
        match self {
            Self::Sparse(values) => {
                values.insert(index, value);
                Ok(())
            }
            Self::Active(lease) => lease.insert(index, value),
        }
    }
}

#[cfg(test)]
#[path = "native_command_program_memo_tests.rs"]
mod tests;
