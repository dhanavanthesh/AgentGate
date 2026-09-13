use std::time::Instant;

use serde_json::{Map, Value};

use crate::error::{ErrorCode, GateError, GateResult};

#[derive(Clone, Debug)]
pub struct OutputLimits {
    pub max_serialized_bytes: usize,
    pub max_object_members: usize,
    pub max_array_values: usize,
    pub max_depth: usize,
    pub max_string_bytes: usize,
    pub max_records: usize,
    pub max_normalization_ns: u64,
}

impl Default for OutputLimits {
    fn default() -> Self {
        Self {
            max_serialized_bytes: 128 * 1024,
            max_object_members: 2048,
            max_array_values: 1024,
            max_depth: 8,
            max_string_bytes: 4096,
            max_records: 1024,
            max_normalization_ns: 100_000_000,
        }
    }
}

#[derive(Default)]
struct Counts {
    members: usize,
    values: usize,
    strings: usize,
}

pub fn parse_and_bound(raw: &[u8], limits: &OutputLimits) -> GateResult<Value> {
    if raw.len() > limits.max_serialized_bytes {
        return Err(output_error("adapter result exceeds byte limit"));
    }
    let started = Instant::now();
    let value: Value = serde_json::from_slice(raw)
        .map_err(|_| output_error("adapter result is malformed UTF-8 or JSON"))?;
    let mut counts = Counts::default();
    check_value(&value, 1, limits, &mut counts)?;
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    if elapsed > limits.max_normalization_ns {
        return Err(GateError::new(
            ErrorCode::ToolTimeout,
            "adapter result normalization exceeded its time limit",
        ));
    }
    Ok(value)
}

pub fn extract_declared_object(value: &Value, fields: &[&str]) -> GateResult<Value> {
    let object = value
        .as_object()
        .ok_or_else(|| output_error("adapter result must be an object"))?;
    let mut normalized = Map::new();
    for field in fields {
        let value = object
            .get(*field)
            .ok_or_else(|| output_error("adapter result lacks a declared field"))?;
        normalized.insert((*field).to_owned(), value.clone());
    }
    Ok(Value::Object(normalized))
}

fn check_value(
    value: &Value,
    depth: usize,
    limits: &OutputLimits,
    counts: &mut Counts,
) -> GateResult<()> {
    if depth > limits.max_depth {
        return Err(output_error("adapter result exceeds nesting limit"));
    }
    match value {
        Value::String(value) => {
            if value.len() > limits.max_string_bytes {
                return Err(output_error("adapter result string exceeds limit"));
            }
            counts.strings = counts.strings.checked_add(1).ok_or_else(accounting_error)?;
        }
        Value::Array(values) => {
            counts.values = counts
                .values
                .checked_add(values.len())
                .ok_or_else(accounting_error)?;
            if counts.values > limits.max_array_values || values.len() > limits.max_records {
                return Err(output_error("adapter result contains too many values"));
            }
            for value in values {
                check_value(value, depth + 1, limits, counts)?;
            }
        }
        Value::Object(values) => {
            counts.members = counts
                .members
                .checked_add(values.len())
                .ok_or_else(accounting_error)?;
            if counts.members > limits.max_object_members {
                return Err(output_error("adapter result contains too many members"));
            }
            for (key, value) in values {
                if key.len() > limits.max_string_bytes {
                    return Err(output_error("adapter result key exceeds string limit"));
                }
                check_value(value, depth + 1, limits, counts)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn output_error(message: &'static str) -> GateError {
    GateError::new(ErrorCode::ToolFailed, message)
}

fn accounting_error() -> GateError {
    GateError::new(ErrorCode::InternalInvariant, "output accounting overflow")
}
