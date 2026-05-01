//! String-newtype identifiers used across `agentlock-cli`.
//!
//! Each newtype is `serde(transparent)` so it serializes as a plain string in
//! JSON and YAML.

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id!(AgentId, "Canonical agent identifier (e.g. `agent://org/name`).");
string_id!(BundleHash, "Hex-encoded bundle hash (BLAKE3 root).");
string_id!(ReleaseId, "Cloud release identifier.");
string_id!(TraceId, "Identifier of a single trace.");
string_id!(RunId, "Identifier of a single replay run.");
string_id!(SchemaId, "Identifier of an embedded JSON schema.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_from_str() {
        let id: AgentId = "agent://acme/foo".into();
        assert_eq!(id.to_string(), "agent://acme/foo");
        assert_eq!(id.as_ref(), "agent://acme/foo");
    }

    #[test]
    fn json_transparent() {
        let id = AgentId("agent://acme/foo".into());
        let s = serde_json::to_string(&id).unwrap();
        assert_eq!(s, "\"agent://acme/foo\"");
        let back: AgentId = serde_json::from_str(&s).unwrap();
        assert_eq!(back, id);
    }
}
