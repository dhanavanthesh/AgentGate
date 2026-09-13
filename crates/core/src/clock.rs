use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::error::{ErrorCode, GateError, GateResult};

pub trait Clock: Send + Sync {
    fn wall_time_ms(&self) -> GateResult<u64>;
    fn monotonic_ns(&self) -> GateResult<u64>;
}

pub struct SystemClock {
    started: Instant,
}

impl SystemClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn wall_time_ms(&self) -> GateResult<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GateError::new(ErrorCode::InternalInvariant, "system clock is invalid"))
            .and_then(|duration| {
                u64::try_from(duration.as_millis()).map_err(|_| {
                    GateError::new(ErrorCode::InternalInvariant, "system time overflow")
                })
            })
    }

    fn monotonic_ns(&self) -> GateResult<u64> {
        u64::try_from(self.started.elapsed().as_nanos())
            .map_err(|_| GateError::new(ErrorCode::InternalInvariant, "monotonic time overflow"))
    }
}

pub struct ManualClock {
    wall_ms: AtomicU64,
    monotonic_ns: AtomicU64,
}

impl ManualClock {
    #[must_use]
    pub fn new(wall_ms: u64, monotonic_ns: u64) -> Self {
        Self {
            wall_ms: AtomicU64::new(wall_ms),
            monotonic_ns: AtomicU64::new(monotonic_ns),
        }
    }

    pub fn advance_ms(&self, delta_ms: u64) -> GateResult<()> {
        let delta_ns = delta_ms.checked_mul(1_000_000).ok_or_else(|| {
            GateError::new(ErrorCode::InternalInvariant, "manual clock delta overflow")
        })?;
        checked_add(&self.wall_ms, delta_ms)?;
        checked_add(&self.monotonic_ns, delta_ns)
    }

    pub fn set_wall_time_ms(&self, wall_ms: u64) {
        self.wall_ms.store(wall_ms, Ordering::Release);
    }

    pub fn set_monotonic_ns(&self, monotonic_ns: u64) {
        self.monotonic_ns.store(monotonic_ns, Ordering::Release);
    }
}

impl Clock for ManualClock {
    fn wall_time_ms(&self) -> GateResult<u64> {
        Ok(self.wall_ms.load(Ordering::Acquire))
    }

    fn monotonic_ns(&self) -> GateResult<u64> {
        Ok(self.monotonic_ns.load(Ordering::Acquire))
    }
}

fn checked_add(value: &AtomicU64, delta: u64) -> GateResult<()> {
    value
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(delta)
        })
        .map(|_| ())
        .map_err(|_| GateError::new(ErrorCode::InternalInvariant, "manual clock overflow"))
}
