//! `agent://` URI parsing.
//!
//! Grammar (see `docs/agent-uri.md`):
//!
//! ```text
//! agent://<org>/<slug>[@<qualifier>][?<query>]
//! ```
//!
//! - `<org>` and `<slug>`: lowercase ASCII letters, digits, and `-`. May not
//!   start or end with `-`, contain `..`, or be empty.
//! - `<qualifier>`: a semver-like version, a channel name, or
//!   `sha256:<hex>`.
//! - `<query>`: `&`-separated `key=value` pairs. Recognized keys are
//!   `profile` and `runtime`; unknown keys are preserved on the
//!   [`Query::extra`] map.
//!
//! Parsing is total: every input either yields an [`AgentReference`] or
//! returns [`OsError::UriInvalid`] with a human-readable reason.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::error::{OsError, OsResult};

/// A parsed `agent://` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentReference {
    pub org: String,
    pub slug: String,
    pub qualifier: Option<Qualifier>,
    pub query: Query,
}

/// The optional pinning suffix after `@`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qualifier {
    /// A semver-like version string, e.g. `1.2.0`, `1.2.0-rc.1`.
    Version(String),
    /// A channel name, e.g. `prod`, `staging`, `dev`.
    Channel(String),
    /// A content digest in the form `sha256:<hex>`.
    Digest { algorithm: String, hex: String },
}

impl Qualifier {
    /// Render in the canonical suffix form used after `@`.
    pub fn as_suffix(&self) -> String {
        match self {
            Qualifier::Version(v) => v.clone(),
            Qualifier::Channel(c) => c.clone(),
            Qualifier::Digest { algorithm, hex } => format!("{algorithm}:{hex}"),
        }
    }

    /// A filesystem-safe directory segment for cache layouts.
    pub fn cache_segment(&self) -> String {
        match self {
            Qualifier::Version(v) => format!("v-{v}"),
            Qualifier::Channel(c) => format!("ch-{c}"),
            Qualifier::Digest { algorithm, hex } => format!("d-{algorithm}-{hex}"),
        }
    }
}

/// Parsed query string. Unknown keys are preserved in [`Query::extra`] so the
/// resolver can decide whether to reject or pass them through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub profile: Option<String>,
    pub runtime: Option<String>,
    pub extra: BTreeMap<String, String>,
}

impl Query {
    pub fn is_empty(&self) -> bool {
        self.profile.is_none() && self.runtime.is_none() && self.extra.is_empty()
    }
}

impl AgentReference {
    /// Canonical string form, suitable for diagnostics and lockfile fields.
    pub fn canonical(&self) -> String {
        let mut s = format!("agent://{}/{}", self.org, self.slug);
        if let Some(q) = &self.qualifier {
            s.push('@');
            s.push_str(&q.as_suffix());
        }
        if !self.query.is_empty() {
            s.push('?');
            let mut parts: Vec<String> = Vec::new();
            if let Some(p) = &self.query.profile {
                parts.push(format!("profile={p}"));
            }
            if let Some(r) = &self.query.runtime {
                parts.push(format!("runtime={r}"));
            }
            for (k, v) in &self.query.extra {
                parts.push(format!("{k}={v}"));
            }
            s.push_str(&parts.join("&"));
        }
        s
    }
}

impl fmt::Display for AgentReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

impl FromStr for AgentReference {
    type Err = OsError;

    fn from_str(s: &str) -> OsResult<Self> {
        parse(s)
    }
}

const SCHEME: &str = "agent://";

fn invalid<S: Into<String>>(reason: S) -> OsError {
    OsError::UriInvalid {
        reason: reason.into(),
    }
}

fn parse(input: &str) -> OsResult<AgentReference> {
    let rest = input
        .strip_prefix(SCHEME)
        .ok_or_else(|| invalid(format!("missing `agent://` scheme in {input:?}")))?;

    if rest.is_empty() {
        return Err(invalid("empty authority"));
    }

    // Split off the query string first so '?' inside qualifiers never confuses
    // the path parser. Empty queries are tolerated for parser symmetry but the
    // canonical form drops them.
    let (path_and_qualifier, query_str) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };

    // Split off the qualifier. Multiple '@' is unambiguous corruption.
    let (path, qualifier_str) = match path_and_qualifier.split_once('@') {
        Some((p, q)) => {
            if q.contains('@') {
                return Err(invalid("multiple '@' qualifiers not allowed"));
            }
            (p, Some(q))
        }
        None => (path_and_qualifier, None),
    };

    let (org, slug) = path
        .split_once('/')
        .ok_or_else(|| invalid("missing '/' between <org> and <slug>"))?;

    validate_segment(org, "org")?;
    validate_segment(slug, "slug")?;

    let qualifier = match qualifier_str {
        None => None,
        Some("") => return Err(invalid("empty qualifier after '@'")),
        Some(q) => Some(parse_qualifier(q)?),
    };

    let query = match query_str {
        None => Query::default(),
        Some(q) => parse_query(q)?,
    };

    Ok(AgentReference {
        org: org.to_string(),
        slug: slug.to_string(),
        qualifier,
        query,
    })
}

fn validate_segment(seg: &str, label: &str) -> OsResult<()> {
    if seg.is_empty() {
        return Err(invalid(format!("empty <{label}> segment")));
    }
    if seg == "." || seg == ".." {
        return Err(invalid(format!("<{label}> may not be '.' or '..'")));
    }
    if seg.contains('/') {
        return Err(invalid(format!("<{label}> may not contain '/'")));
    }
    if seg.starts_with('-') || seg.ends_with('-') {
        return Err(invalid(format!(
            "<{label}> may not start or end with '-'"
        )));
    }
    if !seg
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(invalid(format!(
            "<{label}> must be lowercase ASCII letters, digits, or '-' (got {seg:?})"
        )));
    }
    Ok(())
}

fn parse_qualifier(q: &str) -> OsResult<Qualifier> {
    if let Some(rest) = q.strip_prefix("sha256:") {
        if rest.is_empty() {
            return Err(invalid("empty sha256 digest"));
        }
        if !rest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid("sha256 digest must be hex"));
        }
        return Ok(Qualifier::Digest {
            algorithm: "sha256".to_string(),
            hex: rest.to_ascii_lowercase(),
        });
    }
    // Heuristic: a leading digit looks like semver; anything else is a channel.
    // Both branches share the same character-set restriction.
    if !q
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
    {
        return Err(invalid(format!(
            "qualifier contains unsupported character (got {q:?})"
        )));
    }
    let starts_numeric = q.chars().next().is_some_and(|c| c.is_ascii_digit());
    if starts_numeric {
        Ok(Qualifier::Version(q.to_string()))
    } else {
        // Channels are lowercase by convention, but we accept any case for now
        // and let the resolver normalize.
        Ok(Qualifier::Channel(q.to_string()))
    }
}

fn parse_query(q: &str) -> OsResult<Query> {
    let mut out = Query::default();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    if q.is_empty() {
        return Ok(out);
    }
    for pair in q.split('&') {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| invalid(format!("query pair {pair:?} missing '='")))?;
        if k.is_empty() {
            return Err(invalid("query key may not be empty"));
        }
        if seen.insert(k.to_string(), ()).is_some() {
            return Err(invalid(format!("duplicate query key {k:?}")));
        }
        match k {
            "profile" => out.profile = Some(v.to_string()),
            "runtime" => out.runtime = Some(v.to_string()),
            other => {
                out.extra.insert(other.to_string(), v.to_string());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_reference() {
        let r: AgentReference = "agent://treansai/agenomic-codedrift".parse().unwrap();
        assert_eq!(r.org, "treansai");
        assert_eq!(r.slug, "agenomic-codedrift");
        assert!(r.qualifier.is_none());
        assert!(r.query.is_empty());
        assert_eq!(r.canonical(), "agent://treansai/agenomic-codedrift");
    }

    #[test]
    fn versioned() {
        let r: AgentReference = "agent://treansai/foo@1.2.0".parse().unwrap();
        assert_eq!(r.qualifier, Some(Qualifier::Version("1.2.0".into())));
    }

    #[test]
    fn channel() {
        let r: AgentReference = "agent://treansai/foo@prod".parse().unwrap();
        assert_eq!(r.qualifier, Some(Qualifier::Channel("prod".into())));
    }

    #[test]
    fn digest_lowercased() {
        let r: AgentReference = "agent://treansai/foo@sha256:ABC123".parse().unwrap();
        match r.qualifier.unwrap() {
            Qualifier::Digest { algorithm, hex } => {
                assert_eq!(algorithm, "sha256");
                assert_eq!(hex, "abc123");
            }
            _ => panic!("expected digest"),
        }
    }

    #[test]
    fn query_known_keys() {
        let r: AgentReference = "agent://treansai/foo?profile=local&runtime=python"
            .parse()
            .unwrap();
        assert_eq!(r.query.profile.as_deref(), Some("local"));
        assert_eq!(r.query.runtime.as_deref(), Some("python"));
    }

    #[test]
    fn query_extra_preserved() {
        let r: AgentReference = "agent://t/f?weird=ok".parse().unwrap();
        assert_eq!(r.query.extra.get("weird").map(String::as_str), Some("ok"));
    }

    #[test]
    fn rejects_missing_scheme() {
        let e = "treansai/foo".parse::<AgentReference>().unwrap_err();
        assert!(matches!(e, OsError::UriInvalid { .. }));
    }

    #[test]
    fn rejects_uppercase_org() {
        assert!("agent://Treansai/foo".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_empty_slug() {
        assert!("agent://treansai/".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_empty_org() {
        assert!("agent:///foo".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_leading_dash() {
        assert!("agent://-org/foo".parse::<AgentReference>().is_err());
        assert!("agent://org/-foo".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_trailing_dash() {
        assert!("agent://org-/foo".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_dot_segments() {
        assert!("agent://./foo".parse::<AgentReference>().is_err());
        assert!("agent://../foo".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_multiple_at() {
        assert!("agent://o/s@1@2".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_empty_qualifier() {
        assert!("agent://o/s@".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_duplicate_query_key() {
        assert!("agent://o/s?profile=a&profile=b"
            .parse::<AgentReference>()
            .is_err());
    }

    #[test]
    fn rejects_query_pair_without_equals() {
        assert!("agent://o/s?profile".parse::<AgentReference>().is_err());
    }

    #[test]
    fn rejects_bad_hex_digest() {
        assert!("agent://o/s@sha256:zzz".parse::<AgentReference>().is_err());
    }

    #[test]
    fn canonical_roundtrip_full() {
        let raw = "agent://treansai/foo@1.2.0?profile=local&runtime=python";
        let r: AgentReference = raw.parse().unwrap();
        let again: AgentReference = r.canonical().parse().unwrap();
        assert_eq!(r, again);
    }

    #[test]
    fn cache_segment_distinguishes_qualifier_kinds() {
        let v = Qualifier::Version("1.0.0".into()).cache_segment();
        let c = Qualifier::Channel("prod".into()).cache_segment();
        let d = Qualifier::Digest {
            algorithm: "sha256".into(),
            hex: "abc".into(),
        }
        .cache_segment();
        assert_ne!(v, c);
        assert_ne!(v, d);
        assert_ne!(c, d);
    }
}
