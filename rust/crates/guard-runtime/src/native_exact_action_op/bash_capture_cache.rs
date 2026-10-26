//! Bounded analysis reuse for local Bash builtins and literal sources.
//!
//! No handles, policy decisions, helper images or network peers are cached.
//! Every hit rereads bytes and source lookup order, then the caller reacquires
//! output/interpreter handles and evaluates current policy before admission.

use std::sync::{Mutex, OnceLock};

use super::*;

pub(super) const MAX_ENTRIES: usize = 16;
pub(super) const MAX_FROZEN_BYTES: usize = 8 * MAX_SOURCE_BYTES;

#[derive(Clone)]
pub(super) struct CachedAnalysis {
    graph: Arc<graph::Graph>,
    last_used: u64,
    #[cfg(test)]
    lookup_hits: u64,
}

#[derive(Default)]
struct AnalysisCache {
    entries: BTreeMap<[u8; 32], CachedAnalysis>,
    frozen_bytes: usize,
    clock: u64,
}

impl AnalysisCache {
    fn remove(&mut self, key: &[u8; 32]) {
        if let Some(entry) = self.entries.remove(key) {
            self.frozen_bytes = self
                .frozen_bytes
                .saturating_sub(entry.graph.frozen_source_bytes());
        }
    }

    fn insert(&mut self, key: [u8; 32], graph: graph::Graph) {
        self.remove(&key);
        self.clock = self.clock.wrapping_add(1);
        self.frozen_bytes += graph.frozen_source_bytes();
        self.entries.insert(
            key,
            CachedAnalysis {
                graph: Arc::new(graph),
                last_used: self.clock,
                #[cfg(test)]
                lookup_hits: 0,
            },
        );
        while self.entries.len() > MAX_ENTRIES || self.frozen_bytes > MAX_FROZEN_BYTES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.remove(&oldest);
        }
    }
}

fn cache() -> &'static Mutex<AnalysisCache> {
    static CACHE: OnceLock<Mutex<AnalysisCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(AnalysisCache::default()))
}

pub(super) fn key(request: &NativeBashCaptureV1) -> Option<[u8; 32]> {
    let encoded = serde_json::to_vec(request).ok()?;
    let mut digest = Sha256::new();
    digest.update(b"guard-native-bash-local-analysis-cache-v1\0");
    digest.update(encoded);
    Some(digest.finalize().into())
}

pub(super) fn get(key: &[u8; 32]) -> Option<CachedAnalysis> {
    // Cache contention must not add an unbounded wait to an admission.
    let mut cache = cache().try_lock().ok()?;
    cache.clock = cache.clock.wrapping_add(1);
    let clock = cache.clock;
    let entry = cache.entries.get_mut(key)?;
    entry.last_used = clock;
    #[cfg(test)]
    {
        entry.lookup_hits = entry.lookup_hits.saturating_add(1);
    }
    Some(entry.clone())
}

pub(super) fn discard(key: &[u8; 32]) {
    if let Ok(mut cache) = cache().try_lock() {
        cache.remove(key);
    }
}

fn eligible(graph: &graph::Graph) -> bool {
    graph.code.len() == 1
        && graph.startup.is_empty()
        && graph.native_images.is_empty()
        && graph.brokered_images.is_empty()
        && graph.invocations.iter().all(|call| {
            call.broker_id.is_none()
                && match call.operation.argv.first().map(String::as_str) {
                    Some("source" | ".") => {
                        call.operation.argv.len() == 2 && call.resolved_path.is_some()
                    }
                    Some(
                        ":" | "printf" | "echo" | "set" | "test" | "[" | "exit" | "true" | "false",
                    ) => call.resolved_path.is_none(),
                    _ => false,
                }
        })
}

pub(super) fn insert(key: [u8; 32], graph: &graph::Graph) {
    if eligible(graph) && graph.frozen_source_bytes() <= MAX_FROZEN_BYTES {
        if let Ok(mut cache) = cache().try_lock() {
            cache.insert(key, graph.clone());
        }
    }
}

#[cfg(test)]
pub(super) fn lookup_hits(request: &NativeBashCaptureV1) -> Option<u64> {
    let key = key(request)?;
    cache()
        .lock()
        .ok()?
        .entries
        .get(&key)
        .map(|entry| entry.lookup_hits)
}

#[cfg(test)]
pub(super) fn bounds() -> Option<(usize, usize)> {
    let cache = cache().lock().ok()?;
    Some((cache.entries.len(), cache.frozen_bytes))
}

fn digest_matches(code: &graph::Code, expected: &graph::CodeIdentity) -> Result<()> {
    if code.original_path != expected.original_path
        || code.resolved_path != expected.resolved_path
        || hex::encode(Sha256::digest(code.source.as_bytes())) != expected.content_sha256
    {
        return Err("bash_cached_code_changed");
    }
    Ok(())
}

pub(super) fn reuse(
    key: &[u8; 32],
    resolver: &Resolver<'_>,
    argv: &[String],
) -> Option<graph::Graph> {
    let cached = get(key)?;
    match revalidate(resolver, argv, &cached.graph) {
        Ok(()) => Some(cached.graph.as_ref().clone()),
        Err(_) => {
            discard(key);
            None
        }
    }
}

fn revalidate(resolver: &Resolver<'_>, argv: &[String], graph: &graph::Graph) -> Result<()> {
    let entry = &graph.code[0];
    let resolved = canonical(&text(&resolver.cwd.join(&argv[0]))?)?;
    digest_matches(&resolver.code(&argv[0], &resolved)?, entry)?;
    let mut checked_sources = BTreeSet::new();
    for call in &graph.invocations {
        resolver.check()?;
        resolver.reject_function(&call.operation.argv[0])?;
        if matches!(call.operation.argv[0].as_str(), "source" | ".") {
            // Resolve the original invocation again: an earlier PATH candidate
            // may have appeared since the graph was first captured.
            let code = graph::Resolver::resolve_source(resolver, &call.operation.argv[1])?;
            if call.resolved_path.as_deref() != Some(code.resolved_path.as_str()) {
                return Err("bash_cached_resolution_changed");
            }
            let expected = graph
                .sources
                .iter()
                .find(|expected| expected.original_path == code.original_path)
                .ok_or("bash_cached_resolution_changed")?;
            digest_matches(&code, expected)?;
            checked_sources.insert(code.original_path);
        }
    }
    if checked_sources.len() != graph.sources.len() {
        return Err("bash_cached_source_unchecked");
    }
    resolver.check()
}
