use crate::clock::Clock;
use crate::error::{ErrorCode, GateError, GateResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline {
    monotonic_ns: u64,
}

impl Deadline {
    pub fn after_ms(clock: &dyn Clock, timeout_ms: u64) -> GateResult<Self> {
        let delta = timeout_ms.checked_mul(1_000_000).ok_or_else(|| {
            GateError::new(ErrorCode::InternalInvariant, "deadline duration overflow")
        })?;
        let monotonic_ns = clock.monotonic_ns()?.checked_add(delta).ok_or_else(|| {
            GateError::new(ErrorCode::InternalInvariant, "deadline timestamp overflow")
        })?;
        Ok(Self { monotonic_ns })
    }

    #[must_use]
    pub fn monotonic_ns(self) -> u64 {
        self.monotonic_ns
    }

    pub fn is_expired(self, clock: &dyn Clock) -> GateResult<bool> {
        Ok(clock.monotonic_ns()? >= self.monotonic_ns)
    }

    pub fn check(self, clock: &dyn Clock) -> GateResult<()> {
        if self.is_expired(clock)? {
            return Err(GateError::new(
                ErrorCode::ToolTimeout,
                "operation deadline expired",
            ));
        }
        Ok(())
    }
}
