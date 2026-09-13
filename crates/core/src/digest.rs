use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{ErrorCode, GateError, GateResult};

pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn canonical_json(value: &Value) -> GateResult<String> {
    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output)
}

fn write_value(value: &Value, output: &mut String) -> GateResult<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(&encode_string(value)?),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_value(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&encode_string(key)?);
                output.push(':');
                let member = values.get(key).ok_or_else(|| {
                    GateError::new(
                        ErrorCode::InternalInvariant,
                        "canonical object key disappeared",
                    )
                })?;
                write_value(member, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn encode_string(value: &str) -> GateResult<String> {
    serde_json::to_string(value)
        .map_err(|_| GateError::new(ErrorCode::InternalInvariant, "string serialization failed"))
}
