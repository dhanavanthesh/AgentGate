use std::time::Instant;

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Distribution {
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub samples: usize,
}

impl Distribution {
    pub fn from_samples(mut values: Vec<u64>) -> Self {
        values.sort_unstable();
        Self {
            p50_ns: percentile(&values, 50),
            p95_ns: percentile(&values, 95),
            p99_ns: percentile(&values, 99),
            max_ns: values.last().copied().unwrap_or(0),
            samples: values.len(),
        }
    }
}

pub fn measure<T>(operation: impl FnOnce() -> T) -> (T, u64) {
    let started = Instant::now();
    let result = operation();
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    (result, elapsed)
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let index = values
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(values.len() - 1);
    values[index]
}
