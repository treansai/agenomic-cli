use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub const MAX_JSON_DEPTH: usize = 64;

pub const FLOAT_NOT_ALLOWED: &str = "float_not_allowed";
pub const INTEGER_OUT_OF_RANGE: &str = "integer_out_of_range";
pub const INVALID_UNICODE: &str = "invalid_unicode";
pub const NUL_CHARACTER: &str = "nul_character";
pub const JSON_TOO_DEEP: &str = "json_too_deep";

const TWO_POW_53: f64 = 9_007_199_254_740_992.0;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("value outside the Agenomic JSON Subset: {reason} at {value_path:?}")]
pub struct AjsError {
    pub reason: &'static str,
    pub value_path: String,
}

impl AjsError {
    fn new(reason: &'static str, value_path: &str) -> Self {
        Self {
            reason,
            value_path: value_path.to_string(),
        }
    }
}

pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => write_number(out, number),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, key) in sorted_keys(map).into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[key]);
            }
            out.push('}');
        }
    }
}

fn write_number(out: &mut String, number: &Number) {
    if let Some(integer) = number.as_i64() {
        out.push_str(&integer.to_string());
    } else if let Some(integer) = number.as_u64() {
        out.push_str(&integer.to_string());
    } else if let Some(float) = number.as_f64() {
        if float.is_finite() && float.trunc() == float && float.abs() < TWO_POW_53 {
            out.push_str(&(float as i64).to_string());
        } else {
            out.push_str(&number.to_string());
        }
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

pub fn ensure_ajs(value: &Value) -> Result<(), AjsError> {
    ensure_ajs_at(value, "")
}

pub fn ensure_ajs_at(value: &Value, path: &str) -> Result<(), AjsError> {
    check_value(value, path, 0)
}

pub fn prompt_digest(value: &Value) -> Result<String, AjsError> {
    ensure_ajs(value)?;
    Ok(sha256_prefixed(canonical_json(value).as_bytes()))
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn ajs_integer(number: &Number) -> Result<i64, &'static str> {
    if let Some(integer) = number.as_i64() {
        return if integer.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() {
            Ok(integer)
        } else {
            Err(INTEGER_OUT_OF_RANGE)
        };
    }
    if number.as_u64().is_some() {
        return Err(INTEGER_OUT_OF_RANGE);
    }
    match number.as_f64() {
        Some(float) if float.is_finite() && float.trunc() == float => {
            if float.abs() <= MAX_SAFE_INTEGER as f64 {
                Ok(float as i64)
            } else {
                Err(INTEGER_OUT_OF_RANGE)
            }
        }
        _ => Err(FLOAT_NOT_ALLOWED),
    }
}

pub fn check_ajs_string(value: &str, path: &str) -> Result<(), AjsError> {
    if value.contains('\0') {
        return Err(AjsError::new(NUL_CHARACTER, path));
    }
    Ok(())
}

fn check_value(value: &Value, path: &str, depth: usize) -> Result<(), AjsError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => ajs_integer(number)
            .map(|_| ())
            .map_err(|reason| AjsError::new(reason, path)),
        Value::String(text) => check_ajs_string(text, path),
        Value::Array(items) => {
            if depth + 1 > MAX_JSON_DEPTH {
                return Err(AjsError::new(JSON_TOO_DEEP, path));
            }
            for (index, item) in items.iter().enumerate() {
                check_value(item, &pointer(path, &index.to_string()), depth + 1)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            if depth + 1 > MAX_JSON_DEPTH {
                return Err(AjsError::new(JSON_TOO_DEEP, path));
            }
            for key in sorted_keys(map) {
                let member = pointer(path, key);
                check_ajs_string(key, &member)?;
                check_value(&map[key], &member, depth + 1)?;
            }
            Ok(())
        }
    }
}

pub fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

pub fn sorted_keys(map: &Map<String, Value>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| utf16_cmp(a, b));
    keys
}

pub fn sort_utf16(names: &mut [String]) {
    names.sort_by(|a, b| utf16_cmp(a, b));
}

pub fn pointer(base: &str, key: &str) -> String {
    format!("{base}/{}", key.replace('~', "~0").replace('/', "~1"))
}

pub fn code_points(text: &str) -> usize {
    text.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nested(depth: usize) -> Value {
        let mut value = json!(0);
        for _ in 0..depth {
            value = json!([value]);
        }
        value
    }

    #[test]
    fn depth_64_is_accepted_and_65_is_refused() {
        assert!(ensure_ajs(&nested(MAX_JSON_DEPTH)).is_ok());
        let error = ensure_ajs(&nested(MAX_JSON_DEPTH + 1)).unwrap_err();
        assert_eq!(error.reason, JSON_TOO_DEEP);
        assert_eq!(error.value_path, "/0".repeat(MAX_JSON_DEPTH));
    }

    #[test]
    fn integers_are_bounded_on_every_number_path() {
        assert!(ensure_ajs(&json!(MAX_SAFE_INTEGER)).is_ok());
        assert!(ensure_ajs(&json!(-MAX_SAFE_INTEGER)).is_ok());
        for value in [
            json!(MAX_SAFE_INTEGER + 1),
            json!(-MAX_SAFE_INTEGER - 1),
            json!(u64::MAX),
            json!(1e300),
        ] {
            assert_eq!(ensure_ajs(&value).unwrap_err().reason, INTEGER_OUT_OF_RANGE);
        }
        assert_eq!(
            ensure_ajs(&json!(0.5)).unwrap_err().reason,
            FLOAT_NOT_ALLOWED
        );
        assert!(ensure_ajs(&json!(3.0)).is_ok());
        assert_eq!(canonical_json(&json!([3.0, -0.0])), "[3,0]");
    }

    #[test]
    fn strings_use_the_ncf_escape_table() {
        let text = "\"\\\u{8}\t\n\u{c}\r\u{1}\u{1f}\u{7f}\u{2028}/\u{e9}";
        assert_eq!(
            canonical_json(&json!(text)),
            "\"\\\"\\\\\\b\\t\\n\\f\\r\\u0001\\u001f\u{7f}\u{2028}/\u{e9}\""
        );
        assert_eq!(
            canonical_json(&json!(text)),
            serde_json::to_string(text).unwrap()
        );
    }

    #[test]
    fn nul_in_keys_and_values_is_refused_with_its_pointer() {
        let error = ensure_ajs(&json!({ "a/b": { "c\u{0}": 1 } })).unwrap_err();
        assert_eq!(error.reason, NUL_CHARACTER);
        assert_eq!(error.value_path, "/a~1b/c\u{0}");
        let error = ensure_ajs(&json!({ "a": ["ok", "x\u{0}"] })).unwrap_err();
        assert_eq!(error.value_path, "/a/1");
    }

    #[test]
    fn keys_sort_by_utf16_code_units() {
        let value = json!({ "\u{ffff}": 1, "\u{1f600}": 2, "\u{e000}": 3, "a": 4 });
        assert_eq!(
            canonical_json(&value),
            "{\"a\":4,\"\u{1f600}\":2,\"\u{e000}\":3,\"\u{ffff}\":1}"
        );
    }
}
