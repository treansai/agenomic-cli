use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};
use std::sync::LazyLock;

pub const SECRET_PATTERN_SET: &str = "agenomic-secrets/1";
pub const SECRET_KEY_RULE: &str = "agenomic-secret-keys/1";
pub const REDACTED: &str = "[REDACTED]";

const PATTERNS: [(&str, &str); 11] = [
    (
        "bearer_token",
        r"(?-u:\b)(?i-u:bearer)[\t\n\x0B\x0C\r ]+[A-Za-z0-9\-_.=+/]{20,}",
    ),
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("openai_key", r"(?-u:\b)sk-[A-Za-z0-9\-_]{20,}"),
    (
        "stripe_key",
        r"(?-u:\b)[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
    ),
    ("aws_access_key", r"(?-u:\b)AKIA[0-9A-Z]{16}(?-u:\b)"),
    ("github_token", r"(?-u:\b)gh[pousr]_[A-Za-z0-9]{36,}"),
    ("huggingface_token", r"(?-u:\b)hf_[A-Za-z0-9]{20,}"),
    ("slack_token", r"(?-u:\b)xox[baprs]-[A-Za-z0-9\-]{10,}"),
    ("google_api_key", r"(?-u:\b)AIza[0-9A-Za-z\-_]{35}"),
    (
        "jwt",
        r"(?-u:\b)eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    ),
    ("agenomic_api_key", r"(?-u:\b)agm_[A-Za-z0-9]{24,}"),
];

static COMPILED: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .filter_map(|(id, pattern)| Regex::new(pattern).ok().map(|regex| (*id, regex)))
        .collect()
});

pub fn pattern_ids() -> impl Iterator<Item = &'static str> {
    PATTERNS.iter().map(|(id, _)| *id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretFinding {
    pub pattern: &'static str,
    pub offset: usize,
    pub length: usize,
}

pub fn scan(text: &str) -> Vec<SecretFinding> {
    let mut found: Vec<(usize, SecretFinding)> = Vec::new();
    for (order, (id, regex)) in COMPILED.iter().enumerate() {
        let (mut byte, mut chars) = (0, 0);
        for hit in regex.find_iter(text) {
            chars += text[byte..hit.start()].chars().count();
            byte = hit.start();
            found.push((
                order,
                SecretFinding {
                    pattern: id,
                    offset: chars,
                    length: hit.as_str().chars().count(),
                },
            ));
        }
    }
    found.sort_by_key(|(order, finding)| (finding.offset, *order));
    found.into_iter().map(|(_, finding)| finding).collect()
}

pub fn contains_secret(text: &str) -> bool {
    COMPILED.iter().any(|(_, regex)| regex.is_match(text))
}

pub fn scrub(text: &str) -> String {
    let found = scan(text);
    if found.is_empty() {
        return text.to_string();
    }
    let mut spans: Vec<(usize, usize, &'static str)> = Vec::new();
    for finding in &found {
        let end = finding.offset + finding.length;
        match spans.last_mut() {
            Some(last) if finding.offset <= last.1 => last.1 = last.1.max(end),
            _ => spans.push((finding.offset, end, finding.pattern)),
        }
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut position = 0;
    for (start, end, pattern) in spans {
        out.extend(&chars[position..start]);
        out.push_str("[REDACTED:");
        out.push_str(pattern);
        out.push(']');
        position = end;
    }
    out.extend(&chars[position..]);
    out
}

pub fn scrub_json(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(scrub(text)),
        Value::Array(items) => Value::Array(items.iter().map(scrub_json).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, member)| {
                    let scrubbed = if secret_shaped_key(key) {
                        Value::String(REDACTED.to_string())
                    } else {
                        scrub_json(member)
                    };
                    (key.clone(), scrubbed)
                })
                .collect::<Map<String, Value>>(),
        ),
        other => other.clone(),
    }
}

const SECRET_TOKENS: [&str; 8] = [
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "credentials",
    "authorization",
    "cookie",
];

const SECRET_SUFFIXES: [&str; 12] = [
    "apikey",
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "credentials",
    "authorization",
    "cookie",
    "privatekey",
    "accesskey",
    "clientsecret",
];

const SECRET_KEY_ENDINGS: [&str; 4] = ["_api_key", "_private_key", "_access_key", "_client_secret"];

pub fn secret_shaped_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    let tokens: Vec<&str> = normalized
        .split('_')
        .filter(|token| !token.is_empty())
        .collect();
    let collapsed = tokens.concat();
    tokens.iter().any(|token| SECRET_TOKENS.contains(token))
        || SECRET_SUFFIXES
            .iter()
            .any(|suffix| collapsed.ends_with(suffix))
        || normalized == "apikey"
        || SECRET_KEY_ENDINGS
            .iter()
            .any(|ending| normalized.ends_with(ending))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        assert_eq!(COMPILED.len(), PATTERNS.len());
        assert_eq!(pattern_ids().count(), 11);
    }

    #[test]
    fn boundary_is_ascii_and_whitespace_is_ascii() {
        let token = "a1B2".repeat(6);
        assert_eq!(
            scan(&format!("\u{e9}sk-{token}")),
            vec![SecretFinding {
                pattern: "openai_key",
                offset: 1,
                length: 27
            }]
        );
        assert!(scan(&format!("bearer\u{a0}{token}")).is_empty());
        assert!(scan(&format!("xsk-{token}")).is_empty());
        assert_eq!(scan(&format!("BeArEr\t{token}"))[0].pattern, "bearer_token");
    }

    #[test]
    fn many_findings_keep_exact_offsets_in_linear_time() {
        let key = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        let count = 60_000;
        let text = vec![format!("\u{1F600}{key}"); count].join(" ");
        let started = std::time::Instant::now();
        let found = scan(&text);
        assert_eq!(found.len(), count);
        assert_eq!(
            found[count - 1],
            SecretFinding {
                pattern: "aws_access_key",
                offset: (count - 1) * 22 + 1,
                length: 20
            }
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn touching_spans_merge_under_the_earliest_pattern() {
        let token = "a1B2".repeat(6);
        assert_eq!(
            scrub(&format!("x Bearer sk-{token} y")),
            "x [REDACTED:bearer_token] y"
        );
        assert!(!contains_secret("plain text"));
    }
}
