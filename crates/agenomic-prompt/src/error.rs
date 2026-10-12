use serde_json::{Map, Value};

pub const PROMPT_REF_INVALID: &str = "prompt_ref_invalid";
pub const PROMPT_REF_UNVERSIONED: &str = "prompt_ref_unversioned";
pub const PROMPT_REF_CROSS_WORKSPACE: &str = "prompt_ref_cross_workspace";
pub const PROMPT_TEMPLATE_INVALID: &str = "prompt_template_invalid";
pub const PROMPT_SECRET_DETECTED: &str = "prompt_secret_detected";
pub const PROMPT_CONTENT_TOO_LARGE: &str = "prompt_content_too_large";
pub const PROMPT_KIND_MISMATCH: &str = "prompt_kind_mismatch";
pub const PROMPT_RENDER_ERROR: &str = "prompt_render_error";
pub const PROMPT_DIGEST_MISMATCH: &str = "prompt_digest_mismatch";
pub const MANIFEST_DIGEST_MISMATCH: &str = "manifest_digest_mismatch";
pub const BUNDLE_SIGNATURE_INVALID: &str = "bundle_signature_invalid";
pub const BUNDLE_UNTRUSTED_KEY: &str = "bundle_untrusted_key";
pub const BUNDLE_INCOMPLETE: &str = "bundle_incomplete";
pub const BUNDLE_EXPIRED: &str = "bundle_expired";
pub const BUNDLE_SCOPE_MISMATCH: &str = "bundle_scope_mismatch";
pub const BUNDLE_UNGOVERNED: &str = "bundle_ungoverned";
pub const PROMPT_FILE_INVALID: &str = "prompt_file_invalid";

pub const INTEGRITY_CODES: [&str; 2] = [PROMPT_DIGEST_MISMATCH, MANIFEST_DIGEST_MISMATCH];

pub const AUTHENTICITY_CODES: [&str; 4] = [
    BUNDLE_SIGNATURE_INVALID,
    BUNDLE_UNTRUSTED_KEY,
    BUNDLE_EXPIRED,
    BUNDLE_UNGOVERNED,
];

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct PromptError {
    pub code: &'static str,
    pub reason: Option<String>,
    pub offset: Option<usize>,
    pub message: String,
    pub details: Value,
}

impl PromptError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            reason: None,
            offset: None,
            message: message.into(),
            details: Value::Object(Map::new()),
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        self.set_detail("reason", Value::String(reason.clone()));
        self.reason = Some(reason);
        self
    }

    pub fn with_offset(mut self, offset: Option<usize>) -> Self {
        self.offset = offset;
        self
    }

    pub fn with_detail(mut self, key: &str, value: Value) -> Self {
        self.set_detail(key, value);
        self
    }

    fn set_detail(&mut self, key: &str, value: Value) {
        if let Value::Object(map) = &mut self.details {
            map.insert(key.to_string(), value);
        }
    }

    pub fn is_integrity(&self) -> bool {
        INTEGRITY_CODES.contains(&self.code)
    }

    pub fn is_authenticity(&self) -> bool {
        AUTHENTICITY_CODES.contains(&self.code)
    }
}
