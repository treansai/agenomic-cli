use crate::error::{
    PromptError, PROMPT_REF_CROSS_WORKSPACE, PROMPT_REF_INVALID, PROMPT_REF_UNVERSIONED,
};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

pub const MAX_PROMPT_ID_LEN: usize = 64;
pub const MAX_REF_LEN: usize = 256;
pub const MAX_VERSION: u32 = 2_147_483_647;

pub fn is_prompt_id(text: &str) -> bool {
    if text.len() > MAX_PROMPT_ID_LEN {
        return false;
    }
    let Some(rest) = text.strip_prefix("prm_") else {
        return false;
    };
    !rest.is_empty()
        && rest.split(['_', '-']).all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

pub fn is_alias(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
}

pub fn is_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

pub fn is_uuid_lower(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
}

pub fn is_sha256_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub fn is_channel_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

pub fn is_slot_path(text: &str) -> bool {
    text.len() <= 128
        && text.split('.').count() >= 2
        && text.split('.').all(|segment| {
            let bytes = segment.as_bytes();
            !bytes.is_empty()
                && bytes[0].is_ascii_lowercase()
                && bytes[1..]
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        })
}

pub fn parse_version(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    if !(1..=10).contains(&bytes.len()) || bytes[0] == b'0' || !bytes.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value <= u64::from(MAX_VERSION))
        .and_then(|value| u32::try_from(value).ok())
}

pub fn version_key(prompt_id: &str, version: impl fmt::Display) -> String {
    format!("{prompt_id}:{version}")
}

pub fn canonical_uri(workspace_id: Uuid, prompt_id: &str, version: u32) -> String {
    format!("agenomic://{workspace_id}/prompts/{prompt_id}/versions/{version}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct PromptRefError {
    pub code: &'static str,
    pub reason: Option<&'static str>,
}

impl PromptRefError {
    fn invalid(reason: &'static str) -> Self {
        Self {
            code: PROMPT_REF_INVALID,
            reason: Some(reason),
        }
    }
}

impl From<PromptRefError> for PromptError {
    fn from(error: PromptRefError) -> Self {
        match (error.code, error.reason) {
            (PROMPT_REF_CROSS_WORKSPACE, _) => PromptError::new(
                PROMPT_REF_CROSS_WORKSPACE,
                "the prompt reference names another workspace",
            ),
            (PROMPT_REF_UNVERSIONED, _) => PromptError::new(
                PROMPT_REF_UNVERSIONED,
                "a version or an alias is required in this context",
            ),
            (code, Some(reason)) => {
                PromptError::new(code, format!("invalid prompt reference ({reason})"))
                    .with_reason(reason)
            }
            (code, None) => PromptError::new(code, "invalid prompt reference"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefContext {
    Management,
    Execution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptRef {
    PromptId {
        prompt_id: String,
    },
    Version {
        prompt_id: String,
        version: u32,
    },
    Alias {
        prompt_id: String,
        alias: String,
    },
    Uri {
        workspace_id: Uuid,
        prompt_id: String,
        version: u32,
    },
}

fn prompt_id_of(text: &str) -> Result<String, PromptRefError> {
    if is_prompt_id(text) {
        Ok(text.to_string())
    } else {
        Err(PromptRefError::invalid("invalid_prompt_id"))
    }
}

impl PromptRef {
    pub fn parse(text: &str) -> Result<Self, PromptRefError> {
        if text.is_empty() {
            return Err(PromptRefError::invalid("empty_segment"));
        }
        if text.chars().count() > MAX_REF_LEN {
            return Err(PromptRefError::invalid("too_long"));
        }
        if let Some(ch) = text.chars().find(|ch| !('\u{21}'..='\u{7e}').contains(ch)) {
            let reason = if ('\u{9}'..='\u{d}').contains(&ch) || ch == ' ' {
                "whitespace"
            } else {
                "invalid_character"
            };
            return Err(PromptRefError::invalid(reason));
        }
        if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(PromptRefError::invalid("uppercase"));
        }
        if text.contains('%') {
            return Err(PromptRefError::invalid("percent_encoded_separator"));
        }
        if let Some((scheme, rest)) = text.split_once("://") {
            return parse_uri(scheme, rest);
        }
        match (text.split_once(':'), text.split_once('@')) {
            (Some(_), Some(_)) => Err(PromptRefError::invalid("mixed_form")),
            (Some((id, version)), None) => {
                if id.is_empty() || version.is_empty() {
                    return Err(PromptRefError::invalid("empty_segment"));
                }
                let prompt_id = prompt_id_of(id)?;
                let version =
                    parse_version(version).ok_or(PromptRefError::invalid("invalid_version"))?;
                Ok(Self::Version { prompt_id, version })
            }
            (None, Some((id, alias))) => {
                if id.is_empty() || alias.is_empty() {
                    return Err(PromptRefError::invalid("empty_segment"));
                }
                let prompt_id = prompt_id_of(id)?;
                if !is_alias(alias) {
                    return Err(PromptRefError::invalid("invalid_alias"));
                }
                Ok(Self::Alias {
                    prompt_id,
                    alias: alias.to_string(),
                })
            }
            (None, None) => Ok(Self::PromptId {
                prompt_id: prompt_id_of(text)?,
            }),
        }
    }

    pub fn form(&self) -> &'static str {
        match self {
            Self::PromptId { .. } => "prompt_id",
            Self::Version { .. } => "version",
            Self::Alias { .. } => "alias",
            Self::Uri { .. } => "uri",
        }
    }

    pub fn prompt_id(&self) -> &str {
        match self {
            Self::PromptId { prompt_id }
            | Self::Version { prompt_id, .. }
            | Self::Alias { prompt_id, .. }
            | Self::Uri { prompt_id, .. } => prompt_id,
        }
    }

    pub fn require(
        &self,
        context: RefContext,
        workspace_id: Option<Uuid>,
    ) -> Result<(), PromptRefError> {
        if let (
            Self::Uri {
                workspace_id: named,
                ..
            },
            Some(current),
        ) = (self, workspace_id)
        {
            if *named != current {
                return Err(PromptRefError {
                    code: PROMPT_REF_CROSS_WORKSPACE,
                    reason: None,
                });
            }
        }
        if context == RefContext::Execution && matches!(self, Self::PromptId { .. }) {
            return Err(PromptRefError {
                code: PROMPT_REF_UNVERSIONED,
                reason: None,
            });
        }
        Ok(())
    }

    pub fn version_ref(&self, workspace_id: Option<Uuid>) -> Option<(&str, u32)> {
        match self {
            Self::Version { prompt_id, version } => Some((prompt_id, *version)),
            Self::Uri {
                workspace_id: named,
                prompt_id,
                version,
            } if Some(*named) == workspace_id => Some((prompt_id, *version)),
            _ => None,
        }
    }
}

fn parse_uri(scheme: &str, rest: &str) -> Result<PromptRef, PromptRefError> {
    if scheme != "agenomic" {
        return Err(PromptRefError::invalid("unsupported_scheme"));
    }
    if rest.contains('?') || rest.contains('#') {
        return Err(PromptRefError::invalid("query_or_fragment"));
    }
    if rest.is_empty() {
        return Err(PromptRefError::invalid("empty_segment"));
    }
    if rest.ends_with('/') {
        return Err(PromptRefError::invalid("trailing_slash"));
    }
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err(PromptRefError::invalid("empty_segment"));
    }
    if segments.len() != 5 || segments[1] != "prompts" || segments[3] != "versions" {
        return Err(PromptRefError::invalid("invalid_uri_path"));
    }
    if !is_uuid_lower(segments[0]) {
        return Err(PromptRefError::invalid("invalid_workspace"));
    }
    let workspace_id =
        Uuid::parse_str(segments[0]).map_err(|_| PromptRefError::invalid("invalid_workspace"))?;
    let prompt_id = prompt_id_of(segments[2])?;
    let version = parse_version(segments[4]).ok_or(PromptRefError::invalid("invalid_version"))?;
    Ok(PromptRef::Uri {
        workspace_id,
        prompt_id,
        version,
    })
}

impl FromStr for PromptRef {
    type Err = PromptRefError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for PromptRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PromptId { prompt_id } => write!(f, "{prompt_id}"),
            Self::Version { prompt_id, version } => write!(f, "{prompt_id}:{version}"),
            Self::Alias { prompt_id, alias } => write!(f, "{prompt_id}@{alias}"),
            Self::Uri {
                workspace_id,
                prompt_id,
                version,
            } => f.write_str(&canonical_uri(*workspace_id, prompt_id, *version)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKSPACE: &str = "0b6c2f1e-7a44-4c8e-9f1d-2a3b4c5d6e7f";
    const OTHER_WORKSPACE: &str = "5a5a5a5a-1111-4222-8333-444455556666";

    fn workspace(text: &str) -> Uuid {
        Uuid::parse_str(text).unwrap()
    }

    #[test]
    fn every_valid_form_round_trips_through_display() {
        let long_id = format!("prm_{}", "a".repeat(60));
        let inputs = [
            "prm_planner".to_string(),
            "prm_planner:7".to_string(),
            "prm_planner:2147483647".to_string(),
            "prm_planner@staging".to_string(),
            "prm_a-b_c9:1".to_string(),
            "prm_x@a_b-c".to_string(),
            format!("{long_id}:1"),
            format!("agenomic://{WORKSPACE}/prompts/prm_planner/versions/7"),
        ];
        for input in inputs {
            let parsed = PromptRef::parse(&input).unwrap();
            assert_eq!(parsed.to_string(), input);
            assert_eq!(input.parse::<PromptRef>().unwrap(), parsed);
        }
    }

    #[test]
    fn version_ref_refuses_unchecked_foreign_uri() {
        let uri = PromptRef::parse(&format!(
            "agenomic://{WORKSPACE}/prompts/prm_planner/versions/7"
        ))
        .unwrap();
        assert_eq!(uri.version_ref(Some(workspace(OTHER_WORKSPACE))), None);
        assert_eq!(uri.version_ref(None), None);
        assert_eq!(
            uri.version_ref(Some(workspace(WORKSPACE))),
            Some(("prm_planner", 7))
        );
        assert!(uri.require(RefContext::Execution, None).is_ok());
        assert_eq!(
            uri.require(RefContext::Management, Some(workspace(OTHER_WORKSPACE)))
                .unwrap_err()
                .code,
            PROMPT_REF_CROSS_WORKSPACE
        );
    }

    #[test]
    fn bare_id_is_management_only() {
        let bare = PromptRef::parse("prm_planner").unwrap();
        assert!(bare.require(RefContext::Management, None).is_ok());
        assert_eq!(
            bare.require(RefContext::Execution, None).unwrap_err().code,
            PROMPT_REF_UNVERSIONED
        );
    }

    #[test]
    fn grammar_helpers() {
        assert_eq!(parse_version("2147483648"), None);
        assert_eq!(parse_version("07"), None);
        assert!(is_uuid_lower(WORKSPACE));
        assert!(!is_uuid_lower(&WORKSPACE.to_uppercase()));
        assert!(is_channel_name("production"));
        assert!(!is_channel_name("Production"));
        assert!(is_slot_path("planner.instructions"));
        assert!(!is_slot_path("planner"));
        let error: PromptError = PromptRef::parse("prm_x:07").unwrap_err().into();
        assert_eq!(error.code, PROMPT_REF_INVALID);
        assert_eq!(error.reason.as_deref(), Some("invalid_version"));
    }
}
