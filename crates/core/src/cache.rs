use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use crate::engine::EngineArtifact;
use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::ArtifactKey;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheStats {
    pub entries: usize,
    pub accounted_bytes: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub oversized_bypasses: u64,
    pub builds: u64,
    pub joined_builds: u64,
}

struct CacheEntry {
    artifact: Arc<EngineArtifact>,
    accounted_bytes: usize,
    last_used: u64,
}

#[derive(Default)]
struct CacheState {
    entries: BTreeMap<ArtifactKey, CacheEntry>,
    accounted_bytes: usize,
    clock: u64,
    stats: CacheStats,
}

type SharedResult = Result<Arc<EngineArtifact>, GateError>;

struct BuildCell {
    result: Mutex<Option<SharedResult>>,
    ready: Condvar,
}

impl BuildCell {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }
}

pub struct ArtifactCache {
    state: Mutex<CacheState>,
    inflight: Mutex<HashMap<ArtifactKey, Arc<BuildCell>>>,
    max_entries: usize,
    max_accounted_bytes: usize,
    max_concurrent_builds: usize,
}

impl ArtifactCache {
    #[must_use]
    pub fn new(
        max_entries: usize,
        max_accounted_bytes: usize,
        max_concurrent_builds: usize,
    ) -> Self {
        Self {
            state: Mutex::new(CacheState::default()),
            inflight: Mutex::new(HashMap::new()),
            max_entries,
            max_accounted_bytes,
            max_concurrent_builds,
        }
    }

    pub fn get_or_build(
        &self,
        key: ArtifactKey,
        accounted_bytes: usize,
        build: impl FnOnce() -> GateResult<Arc<EngineArtifact>>,
    ) -> GateResult<Arc<EngineArtifact>> {
        if let Some(artifact) = self.lookup(&key)? {
            return Ok(artifact);
        }
        let (cell, builder) = {
            let mut inflight = lock(&self.inflight, "artifact in-flight lock poisoned")?;
            if let Some(cell) = inflight.get(&key) {
                self.increment_joined()?;
                (Arc::clone(cell), false)
            } else {
                if inflight.len() >= self.max_concurrent_builds {
                    return Err(GateError::new(
                        ErrorCode::CatalogTooLarge,
                        "concurrent artifact build limit reached",
                    ));
                }
                let cell = Arc::new(BuildCell::new());
                inflight.insert(key.clone(), Arc::clone(&cell));
                self.increment_miss_and_build()?;
                (cell, true)
            }
        };
        if !builder {
            return wait_for_build(&cell);
        }

        let mut cleanup = BuildCleanup {
            cache: self,
            key: key.clone(),
            cell: Arc::clone(&cell),
            published: false,
        };
        let result = build();
        if let Ok(artifact) = &result {
            self.insert(key.clone(), Arc::clone(artifact), accounted_bytes)?;
        }
        cleanup.publish(result.clone())?;
        result
    }

    pub fn stats(&self) -> GateResult<CacheStats> {
        let state = lock(&self.state, "artifact cache lock poisoned")?;
        let mut stats = state.stats;
        stats.entries = state.entries.len();
        stats.accounted_bytes = state.accounted_bytes;
        Ok(stats)
    }

    fn lookup(&self, key: &ArtifactKey) -> GateResult<Option<Arc<EngineArtifact>>> {
        let mut state = lock(&self.state, "artifact cache lock poisoned")?;
        state.clock = state.clock.checked_add(1).ok_or_else(counter_error)?;
        let clock = state.clock;
        let artifact = state.entries.get_mut(key).map(|entry| {
            entry.last_used = clock;
            Arc::clone(&entry.artifact)
        });
        if artifact.is_some() {
            state.stats.hits = state.stats.hits.checked_add(1).ok_or_else(counter_error)?;
        }
        Ok(artifact)
    }

    fn insert(
        &self,
        key: ArtifactKey,
        artifact: Arc<EngineArtifact>,
        accounted_bytes: usize,
    ) -> GateResult<()> {
        let mut state = lock(&self.state, "artifact cache lock poisoned")?;
        if self.max_entries == 0 || accounted_bytes > self.max_accounted_bytes {
            state.stats.oversized_bypasses = state
                .stats
                .oversized_bypasses
                .checked_add(1)
                .ok_or_else(counter_error)?;
            return Ok(());
        }
        while state.entries.len() >= self.max_entries
            || state
                .accounted_bytes
                .checked_add(accounted_bytes)
                .is_none_or(|bytes| bytes > self.max_accounted_bytes)
        {
            let victim = state
                .entries
                .iter()
                .min_by_key(|(key, entry)| (entry.last_used, (*key).clone()))
                .map(|(key, _)| key.clone())
                .ok_or_else(|| {
                    GateError::new(
                        ErrorCode::InternalInvariant,
                        "cache eviction found no victim",
                    )
                })?;
            let removed = state.entries.remove(&victim).ok_or_else(|| {
                GateError::new(ErrorCode::InternalInvariant, "cache victim disappeared")
            })?;
            state.accounted_bytes = state
                .accounted_bytes
                .checked_sub(removed.accounted_bytes)
                .ok_or_else(|| {
                    GateError::new(ErrorCode::InternalInvariant, "cache accounting underflow")
                })?;
            state.stats.evictions = state
                .stats
                .evictions
                .checked_add(1)
                .ok_or_else(counter_error)?;
        }
        state.clock = state.clock.checked_add(1).ok_or_else(counter_error)?;
        let last_used = state.clock;
        state.accounted_bytes = state
            .accounted_bytes
            .checked_add(accounted_bytes)
            .ok_or_else(|| GateError::new(ErrorCode::CatalogTooLarge, "cache bytes overflow"))?;
        state.entries.insert(
            key,
            CacheEntry {
                artifact,
                accounted_bytes,
                last_used,
            },
        );
        Ok(())
    }

    fn increment_miss_and_build(&self) -> GateResult<()> {
        let mut state = lock(&self.state, "artifact cache lock poisoned")?;
        state.stats.misses = state
            .stats
            .misses
            .checked_add(1)
            .ok_or_else(counter_error)?;
        state.stats.builds = state
            .stats
            .builds
            .checked_add(1)
            .ok_or_else(counter_error)?;
        Ok(())
    }

    fn increment_joined(&self) -> GateResult<()> {
        let mut state = lock(&self.state, "artifact cache lock poisoned")?;
        state.stats.joined_builds = state
            .stats
            .joined_builds
            .checked_add(1)
            .ok_or_else(counter_error)?;
        Ok(())
    }
}

struct BuildCleanup<'a> {
    cache: &'a ArtifactCache,
    key: ArtifactKey,
    cell: Arc<BuildCell>,
    published: bool,
}

impl BuildCleanup<'_> {
    fn publish(&mut self, result: SharedResult) -> GateResult<()> {
        {
            let mut slot = lock(&self.cell.result, "artifact build cell lock poisoned")?;
            *slot = Some(result);
            self.cell.ready.notify_all();
        }
        lock(&self.cache.inflight, "artifact in-flight lock poisoned")?.remove(&self.key);
        self.published = true;
        Ok(())
    }
}

impl Drop for BuildCleanup<'_> {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        if let Ok(mut slot) = self.cell.result.lock() {
            *slot = Some(Err(GateError::new(
                ErrorCode::InternalInvariant,
                "artifact builder exited before publishing",
            )));
            self.cell.ready.notify_all();
        }
        if let Ok(mut inflight) = self.cache.inflight.lock() {
            inflight.remove(&self.key);
        }
    }
}

fn wait_for_build(cell: &BuildCell) -> GateResult<Arc<EngineArtifact>> {
    let mut slot = lock(&cell.result, "artifact build cell lock poisoned")?;
    while slot.is_none() {
        slot = cell.ready.wait(slot).map_err(|_| {
            GateError::new(
                ErrorCode::InternalInvariant,
                "artifact build wait lock poisoned",
            )
        })?;
    }
    slot.as_ref().cloned().ok_or_else(|| {
        GateError::new(
            ErrorCode::InternalInvariant,
            "artifact build result missing",
        )
    })?
}

fn counter_error() -> GateError {
    GateError::new(
        ErrorCode::InternalInvariant,
        "artifact cache counter overflow",
    )
}

fn lock<'a, T>(mutex: &'a Mutex<T>, message: &'static str) -> GateResult<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| GateError::new(ErrorCode::InternalInvariant, message))
}
