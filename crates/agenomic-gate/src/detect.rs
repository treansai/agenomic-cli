//! Deterministic, dependency-free detectors over tool-call arguments.
//!
//! None of these call an LLM or use randomness or wall-clock time: the same
//! JSON in produces the same finding out, every time. They deliberately lean
//! **safe** (a false positive blocks; a false negative is the dangerous one).

/// A class of sensitive data found in an argument value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiKind {
    Email,
    CreditCard,
    Ssn,
    Secret,
}

impl PiiKind {
    pub fn label(self) -> &'static str {
        match self {
            PiiKind::Email => "email",
            PiiKind::CreditCard => "credit_card",
            PiiKind::Ssn => "ssn",
            PiiKind::Secret => "secret",
        }
    }
}

/// Scan every string leaf of `value` and return the first PII class found, in a
/// deterministic traversal order (object keys are visited in sorted order).
pub fn scan_pii(value: &serde_json::Value) -> Option<PiiKind> {
    let mut leaves = Vec::new();
    string_leaves(value, &mut leaves);
    for s in &leaves {
        if let Some(kind) = classify(s) {
            return Some(kind);
        }
    }
    None
}

/// Classify a single string for the strongest PII signal it carries.
fn classify(s: &str) -> Option<PiiKind> {
    if has_secret(s) {
        return Some(PiiKind::Secret);
    }
    if has_credit_card(s) {
        return Some(PiiKind::CreditCard);
    }
    if has_ssn(s) {
        return Some(PiiKind::Ssn);
    }
    if has_email(s) {
        return Some(PiiKind::Email);
    }
    None
}

/// Collect every string leaf of a JSON value.
pub fn string_leaves(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(items) => {
            for v in items {
                string_leaves(v, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                string_leaves(v, out);
            }
        }
        _ => {}
    }
}

/// `true` if any whitespace-delimited token looks like an email address.
fn has_email(s: &str) -> bool {
    s.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '<' || c == '>')
        .any(token_is_email)
}

fn token_is_email(token: &str) -> bool {
    let bytes = token.as_bytes();
    let at = match token.find('@') {
        Some(i) => i,
        None => return false,
    };
    // Exactly one '@', non-empty local part, domain with a dot and a 2+ char TLD.
    if token[at + 1..].contains('@') {
        return false;
    }
    let local = &token[..at];
    let domain = &token[at + 1..];
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    let dot = match domain.rfind('.') {
        Some(i) => i,
        None => return false,
    };
    let tld = &domain[dot + 1..];
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let ok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-');
    bytes.iter().take(at).all(|&c| ok(c))
        && domain.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
}

/// `true` if any token matches the US SSN shape `ddd-dd-dddd`.
fn has_ssn(s: &str) -> bool {
    s.split(|c: char| !(c.is_ascii_digit() || c == '-'))
        .any(token_is_ssn)
}

fn token_is_ssn(token: &str) -> bool {
    let b = token.as_bytes();
    b.len() == 11
        && b[3] == b'-'
        && b[6] == b'-'
        && b[..3].iter().all(u8::is_ascii_digit)
        && b[4..6].iter().all(u8::is_ascii_digit)
        && b[7..].iter().all(u8::is_ascii_digit)
}

/// `true` if any maximal run of digits and separators (spaces / dashes), once
/// the separators are stripped, is a 13–19 digit number passing the Luhn
/// checksum — a payment card number, even when embedded in prose like
/// `"card 4111 1111 1111 1111"`.
fn has_credit_card(s: &str) -> bool {
    let mut run: Vec<u8> = Vec::new();
    for &b in s.as_bytes() {
        if b.is_ascii_digit() || b == b' ' || b == b'-' {
            run.push(b);
        } else {
            if run_is_card(&run) {
                return true;
            }
            run.clear();
        }
    }
    run_is_card(&run)
}

fn run_is_card(run: &[u8]) -> bool {
    let digits: Vec<u8> = run.iter().copied().filter(u8::is_ascii_digit).collect();
    digits.len() >= 13 && digits.len() <= 19 && luhn_ok(&digits)
}

fn luhn_ok(ascii_digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for &c in ascii_digits.iter().rev() {
        let mut v = (c - b'0') as u32;
        if alt {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        alt = !alt;
    }
    sum % 10 == 0
}

/// Known credential prefixes / markers. Kept explicit (no entropy heuristics)
/// so detection is predictable.
const SECRET_PREFIXES: &[&str] = &[
    "sk-", "sk_live_", "sk_test_", "rk_live_", "AKIA", "ASIA", "ghp_", "gho_", "ghs_", "github_pat_",
    "xoxb-", "xoxp-", "xoxa-", "AIza", "ya29.", "glpat-", "AGENOMIC_SECRET",
];

fn has_secret(s: &str) -> bool {
    if s.contains("-----BEGIN") && s.contains("PRIVATE KEY") {
        return true;
    }
    s.split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .any(|t| SECRET_PREFIXES.iter().any(|p| t.starts_with(p) && t.len() > p.len() + 8))
}

// ---- path checks -------------------------------------------------------------

/// `true` if a path string contains a `..` traversal component.
pub fn has_traversal(path: &str) -> bool {
    path.split(['/', '\\']).any(|seg| seg == "..")
}

/// Return the first protected fragment that `path` contains, if any.
pub fn matches_protected<'a>(path: &str, fragments: &'a [String]) -> Option<&'a str> {
    fragments
        .iter()
        .find(|f| !f.is_empty() && path.contains(f.as_str()))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_email() {
        assert_eq!(scan_pii(&serde_json::json!("reach me at a@b.com ok")), Some(PiiKind::Email));
        assert_eq!(scan_pii(&serde_json::json!("no address here")), None);
        assert_eq!(scan_pii(&serde_json::json!("a@b")), None); // no TLD
    }

    #[test]
    fn detects_ssn() {
        assert_eq!(scan_pii(&serde_json::json!("ssn 123-45-6789")), Some(PiiKind::Ssn));
    }

    #[test]
    fn detects_credit_card_luhn() {
        // 4111 1111 1111 1111 is the classic Luhn-valid test PAN.
        assert_eq!(scan_pii(&serde_json::json!("4111 1111 1111 1111")), Some(PiiKind::CreditCard));
        // Embedded in prose is still detected.
        assert_eq!(scan_pii(&serde_json::json!("card 4111 1111 1111 1111")), Some(PiiKind::CreditCard));
        assert_eq!(scan_pii(&serde_json::json!("4111111111111112")), None); // bad checksum
        assert_eq!(scan_pii(&serde_json::json!("call 555 0100 today")), None); // short run
    }

    #[test]
    fn detects_secret_prefix() {
        assert_eq!(scan_pii(&serde_json::json!("token sk-ABCDEFGHIJKLMNOP")), Some(PiiKind::Secret));
        assert_eq!(
            scan_pii(&serde_json::json!("-----BEGIN OPENSSH PRIVATE KEY-----")),
            Some(PiiKind::Secret)
        );
    }

    #[test]
    fn nested_leaves_are_scanned() {
        let v = serde_json::json!({ "outer": { "inner": ["x", "victim@evil.com"] } });
        assert_eq!(scan_pii(&v), Some(PiiKind::Email));
    }

    #[test]
    fn traversal_detection() {
        assert!(has_traversal("../../etc/passwd"));
        assert!(has_traversal("a/../b"));
        assert!(!has_traversal("reports/summary.txt"));
        assert!(!has_traversal("file..name")); // not a path component
    }
}
