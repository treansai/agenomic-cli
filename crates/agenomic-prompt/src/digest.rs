use crate::canonical::{prompt_digest, AjsError};
use crate::error::{PromptError, PROMPT_DIGEST_MISMATCH};
use crate::refs::version_key;
use serde_json::{json, Value};

pub const CONTENT_SCHEMA: &str = "agenomic.prompt_content/v1";
pub const VERSION_SCHEMA: &str = "agenomic.prompt_version/v1";
pub const MANIFEST_SCHEMA: &str = "agenomic.prompt_manifest/v1";
pub const RENDERED_PROMPT_SCHEMA: &str = "agenomic.rendered_prompt/v1";
pub const ARTIFACT_SET_SCHEMA: &str = "agenomic.prompt_artifact_set/v1";
pub const BUNDLE_SCHEMA: &str = "agenomic.prompt_bundle/v1";
pub const PROMPT_FILE_SCHEMA: &str = "agenomic.prompt_file/v1";

pub fn document_digest(document: &Value) -> Result<String, AjsError> {
    prompt_digest(document)
}

pub fn artifact_set(document: &Value) -> Value {
    json!({
        "schema": ARTIFACT_SET_SCHEMA,
        "prompt_manifest_digest": document.get("prompt_manifest_digest").cloned().unwrap_or(Value::Null),
        "manifest": document.get("manifest").cloned().unwrap_or(Value::Null),
        "children": document.get("children").cloned().unwrap_or(Value::Null),
        "prompts": document.get("prompts").cloned().unwrap_or(Value::Null),
    })
}

pub fn artifact_set_digest(document: &Value) -> Result<String, AjsError> {
    prompt_digest(&artifact_set(document))
}

pub fn verify_content(
    prompt_id: &str,
    version: impl std::fmt::Display,
    content: &Value,
    expected: &str,
) -> Result<String, PromptError> {
    let reference = version_key(prompt_id, version);
    let mismatch = |actual: Value| {
        PromptError::new(
            PROMPT_DIGEST_MISMATCH,
            format!("the content digest of {reference} does not match"),
        )
        .with_detail("ref", json!(reference))
        .with_detail("expected", json!(expected))
        .with_detail("actual", actual)
    };
    match prompt_digest(content) {
        Ok(actual) if actual == expected => Ok(actual),
        Ok(actual) => Err(mismatch(json!(actual))),
        Err(error) => Err(mismatch(Value::Null).with_reason(error.reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_content_reports_the_reference_and_both_digests() {
        let content = json!({ "schema": CONTENT_SCHEMA });
        let digest = prompt_digest(&content).unwrap();
        assert_eq!(
            verify_content("prm_x", 1, &content, &digest).unwrap(),
            digest
        );
        let error = verify_content("prm_x", 1, &content, "sha256:00").unwrap_err();
        assert_eq!(error.code, PROMPT_DIGEST_MISMATCH);
        assert_eq!(error.details["ref"], "prm_x:1");
        assert_eq!(error.details["actual"], json!(digest));
        let error = verify_content("prm_x", 1, &json!({ "a": 0.5 }), &digest).unwrap_err();
        assert_eq!(error.reason.as_deref(), Some("float_not_allowed"));
    }
}
